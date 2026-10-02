// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	share "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

type ClientConfig struct {
	OnionURL     string
	SOCKSNetwork string // Explicitly tcp or unix; never a direct-network fallback.
	SOCKSAddress string
	TLS          *tls.Config
	Fingerprint  string
	AccessToken  func(context.Context) (string, error)
}

type Mapping struct {
	listener *net.TCPListener
	cancel   context.CancelFunc
	mu       sync.Mutex
	active   map[net.Conn]struct{}
	closed   bool
	status   error
}

func (m *Mapping) Addr() net.Addr { return m.listener.Addr() }

// Status is the most recent carrier setup/transport failure, not a health probe.
func (m *Mapping) Status() error       { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Mapping) setStatus(err error) { m.mu.Lock(); m.status = err; m.mu.Unlock() }
func (m *Mapping) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.cancel()
	m.listener.Close()
	for c := range m.active {
		c.Close()
	}
	return nil
}

// Map atomically reserves the loopback port. Every accepted native connection
// gets one independent carrier; a failed connection is never retried or replayed.
func Map(ctx context.Context, cfg ClientConfig, serviceID string, port int) (*Mapping, error) {
	dialer, endpoint, err := cfg.prepare(serviceID)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid local port")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	m := &Mapping{listener: listener, cancel: cancel, active: make(map[net.Conn]struct{})}
	context.AfterFunc(ctx, func() { m.Close() })
	go func() {
		for {
			local, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			m.mu.Lock()
			if m.closed {
				m.mu.Unlock()
				local.Close()
				return
			}
			m.active[local] = struct{}{}
			m.mu.Unlock()
			go func() {
				defer local.Close()
				defer func() { m.mu.Lock(); delete(m.active, local); m.mu.Unlock() }()
				if err := m.carry(ctx, cfg, dialer, endpoint, serviceID, local); err != nil && ctx.Err() == nil {
					m.setStatus(err)
				}
			}()
		}
	}()
	return m, nil
}

func (c ClientConfig) prepare(id string) (*websocket.Dialer, string, error) {
	u, err := url.Parse(c.OnionURL)
	if err != nil || u.Scheme != "https" || !onionPattern.MatchString(u.Hostname()) || u.User != nil || (u.Port() != "" && u.Port() != "443") || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || !servicePattern.MatchString(id) {
		return nil, "", errors.New("an exact HTTPS v3 onion origin and service ID are required")
	}
	if err := (Endpoint{c.SOCKSNetwork, c.SOCKSAddress}).validate(); err != nil {
		return nil, "", fmt.Errorf("invalid Tor SOCKS endpoint: %w", err)
	}
	pin, err := base64.StdEncoding.DecodeString(c.Fingerprint)
	if err != nil || len(pin) != 32 {
		return nil, "", errors.New("a complete Chisel SHA256 fingerprint is required")
	}
	if c.AccessToken == nil || c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.RootCAs == nil || len(c.TLS.Certificates) == 0 || (c.TLS.ServerName != "" && c.TLS.ServerName != u.Hostname()) {
		return nil, "", errors.New("OAuth callback, trusted TLS roots, matching hostname and mTLS certificate are required")
	}
	tlsConfig := c.TLS.Clone()
	tlsConfig.ServerName = u.Hostname()
	tlsConfig.MinVersion = tls.VersionTLS13
	socks, err := proxy.SOCKS5(c.SOCKSNetwork, c.SOCKSAddress, nil, &net.Dialer{Timeout: handshakeTimeout})
	if err != nil {
		return nil, "", err
	}
	contextual, ok := socks.(proxy.ContextDialer)
	if !ok {
		return nil, "", errors.New("Tor SOCKS dialer must support cancellation")
	}
	expected := net.JoinHostPort(u.Hostname(), "443")
	d := &websocket.Dialer{HandshakeTimeout: handshakeTimeout, Subprotocols: []string{share.ProtocolVersion}, TLSClientConfig: tlsConfig, NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != expected {
			return nil, errors.New("unexpected tunnel destination")
		}
		return contextual.DialContext(ctx, "tcp", expected)
	}}
	u.Scheme = "wss"
	u.Path = "/tunnel/" + id
	return d, u.String(), nil
}

func (m *Mapping) carry(parent context.Context, cfg ClientConfig, dialer *websocket.Dialer, endpoint, id string, local *net.TCPConn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	tokenCtx, tokenCancel := context.WithTimeout(ctx, handshakeTimeout)
	token, err := cfg.AccessToken(tokenCtx)
	tokenCancel()
	if err != nil || !validToken(token) {
		return errors.New("OAuth access token unavailable")
	}
	ws, response, err := dialer.DialContext(ctx, endpoint, http.Header{"Authorization": []string{"Bearer " + token}})
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	if err != nil {
		return errors.New("Tor/TLS tunnel upgrade failed")
	}
	conn := cnet.NewWebSocketConn(ws)
	ws.SetReadLimit(512 * 1024)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close(); local.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sc, channels, requests, err := ssh.NewClientConn(conn, "", &ssh.ClientConfig{User: "torkitten", Auth: []ssh.AuthMethod{ssh.Password(token)}, ClientVersion: "SSH-" + share.ProtocolVersion + "-client", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ccrypto.FingerprintKey(key) != cfg.Fingerprint {
			return errors.New("SSH fingerprint mismatch")
		}
		return nil
	}})
	if err != nil {
		return errors.New("pinned SSH handshake failed")
	}
	defer sc.Close()
	remote := &settings.Remote{LocalHost: "127.0.0.1", LocalPort: strconv.Itoa(local.LocalAddr().(*net.TCPAddr).Port), LocalProto: "tcp", RemoteHost: id, RemotePort: "1", RemoteProto: "tcp"}
	ok, _, err := sc.SendRequest("config", true, settings.EncodeConfig(settings.Config{Version: share.BuildVersion, Remotes: settings.Remotes{remote}}))
	if err != nil || !ok {
		return errors.New("service configuration denied")
	}
	stream, reqs, err := sc.OpenChannel("chisel", []byte(id+":1"))
	if err != nil {
		return errors.New("service channel unavailable")
	}
	conn.SetDeadline(time.Time{})
	m.setStatus(nil)
	go ssh.DiscardRequests(reqs)
	go func() {
		err := bind(ctx, sc, requests, channels)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			m.setStatus(errors.New("tunnel carrier interrupted"))
		}
		// Stop accepting native input, but drain SSH output before closing TCP.
		// A carrier can close while its last response bytes are still buffered.
		local.CloseRead()
	}()
	cio.Pipe(local, stream)
	cancel()
	return nil
}
