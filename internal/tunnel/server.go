// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	share "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
)

// AuthorizeBearer delegates each new carrier's authorization to Authelia.
type AuthorizeBearer func(context.Context, string) error

type service struct {
	endpoint Endpoint
	active   map[net.Conn]context.CancelFunc
}

type Server struct {
	signer    ssh.Signer
	authorize AuthorizeBearer
	mu        sync.Mutex
	services  map[string]*service
	epoch     uint64
	closed    bool
}

func NewServer(signer ssh.Signer, authorize AuthorizeBearer) (*Server, error) {
	if signer == nil || authorize == nil {
		return nil, errors.New("SSH signer and authorization are required")
	}
	return &Server{signer: signer, authorize: authorize, services: make(map[string]*service)}, nil
}

func (s *Server) Fingerprint() string { return ccrypto.FingerprintKey(s.signer.PublicKey()) }

func closeService(v *service) {
	if v != nil {
		for c, cancel := range v.active {
			cancel()
			c.Close()
		}
	}
}

func (s *Server) SetService(id string, endpoint Endpoint) error {
	if !servicePattern.MatchString(id) {
		return errors.New("invalid service ID")
	}
	if err := endpoint.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	old := s.services[id]
	if old != nil && old.endpoint == endpoint {
		return nil
	}
	closeService(old)
	s.services[id] = &service{endpoint: endpoint, active: make(map[net.Conn]context.CancelFunc)}
	return nil
}

func (s *Server) RemoveService(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	closeService(s.services[id])
	delete(s.services, id)
}

// Revoke closes all carriers, including handshakes, and invalidates upgrades
// still awaiting authorization. The caller also revokes tokens at Authelia.
func (s *Server) Revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch++
	for _, v := range s.services {
		closeService(v)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.epoch++
	for _, v := range s.services {
		closeService(v)
	}
	return nil
}

// ServeHTTP must be mounted on the private Unix HTTP backend behind Caddy.
// Authorization is independently checked here, including if Caddy is bypassed.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/tunnel/")
	if r.Method != "GET" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Path != "/tunnel/"+id || !servicePattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	v, epoch, closed := s.services[id], s.epoch, s.closed
	s.mu.Unlock()
	if closed || v == nil {
		http.NotFound(w, r)
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		http.Error(w, "unauthorized", 401)
		return
	}
	token := strings.TrimPrefix(headers[0], "Bearer ")
	if !validToken(token) {
		http.Error(w, "unauthorized", 401)
		return
	}
	authCtx, authCancel := context.WithTimeout(r.Context(), 15*time.Second)
	err := s.authorize(authCtx, token)
	authCancel()
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Header.Get("Sec-WebSocket-Protocol") != share.ProtocolVersion {
		http.Error(w, "invalid protocol", 400)
		return
	}
	upgrade := websocket.Upgrader{Subprotocols: []string{share.ProtocolVersion}, HandshakeTimeout: handshakeTimeout}
	ws, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := cnet.NewWebSocketConn(ws)
	ws.SetReadLimit(512 * 1024)
	defer conn.Close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s.mu.Lock()
	if s.closed || s.epoch != epoch || s.services[id] != v {
		s.mu.Unlock()
		return
	}
	v.active[conn] = cancel
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(v.active, conn); s.mu.Unlock() }()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sshConfig := &ssh.ServerConfig{MaxAuthTries: 1, PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "torkitten" || subtle.ConstantTimeCompare(password, []byte(token)) != 1 {
			return nil, errors.New("unauthorized")
		}
		return nil, nil
	}}
	sshConfig.AddHostKey(s.signer)
	sc, channels, requests, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		return
	}
	defer sc.Close()
	var request *ssh.Request
	select {
	case request = <-requests:
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
		return
	}
	if request == nil {
		return
	}
	if request.Type != "config" || len(request.Payload) > 8192 || !validConfig(request.Payload, id) {
		request.Reply(false, []byte("service configuration denied"))
		return
	}
	if err := request.Reply(true, nil); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	noChannels := make(chan ssh.NewChannel)
	close(noChannels)
	go func() { bind(ctx, sc, requests, noChannels); cancel() }()
	used := false
	for ch := range channels {
		if used || ch.ChannelType() != "chisel" || string(ch.ExtraData()) != id+":1" {
			ch.Reject(ssh.Prohibited, "service channel denied")
			continue
		}
		used = true
		go func() {
			target, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, v.endpoint.Network, v.endpoint.Address)
			if err != nil {
				ch.Reject(ssh.ConnectionFailed, "service unavailable")
				return
			}
			defer target.Close()
			stop := context.AfterFunc(ctx, func() { target.Close() })
			defer stop()
			stream, reqs, err := ch.Accept()
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			cio.Pipe(stream, target)
		}()
	}
}

// The wire remote is a Chisel-valid serviceID:1 label, not a dial address.
func validConfig(payload []byte, id string) bool {
	config, err := settings.DecodeConfig(payload)
	if err != nil || len(config.Remotes) != 1 || config.Remotes[0] == nil {
		return false
	}
	r := config.Remotes[0]
	return !r.Reverse && !r.Socks && r.RemoteHost == id && r.RemotePort == "1" && r.RemoteProto == "tcp" && r.LocalProto == "tcp"
}
