// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	chclient "github.com/jpillora/chisel/client"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
)

const testOnion = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
const testToken = "test-only-bearer"

type fixture struct {
	server                 *Server
	cfg                    ClientConfig
	proxyCalls             *atomic.Int64
	tlsServer              *httptest.Server
	caPEM, certPEM, keyPEM []byte
}

func shortTemp(t *testing.T) string {
	t.Helper()
	p, err := os.MkdirTemp("", "tt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}

func newFixture(t *testing.T, authorize AuthorizeBearer) *fixture {
	t.Helper()
	if authorize == nil {
		authorize = func(_ context.Context, token string) error {
			if token != testToken {
				return errors.New("denied")
			}
			return nil
		}
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	server, err := NewServer(signer, authorize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	issue := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		_, leafKey, _ := ed25519.GenerateKey(rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{testOnion}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, leafKey.Public(), caKey)
		pkcs, _ := x509.MarshalPKCS8PrivateKey(leafKey)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}
	serverPair, _, _ := issue(2, x509.ExtKeyUsageServerAuth)
	clientPair, clientPEM, clientKeyPEM := issue(3, x509.ExtKeyUsageClientAuth)
	httpServer := httptest.NewUnstartedServer(server)
	httpServer.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	proxyAddr, calls := startSOCKS(t, "tcp", "127.0.0.1:0", httpServer.Listener.Addr().String(), false)
	return &fixture{server: server, tlsServer: httpServer, proxyCalls: calls, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), certPEM: clientPEM, keyPEM: clientKeyPEM, cfg: ClientConfig{OnionURL: "https://" + testOnion, SOCKSNetwork: "tcp", SOCKSAddress: proxyAddr, TLS: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientPair}}, Fingerprint: server.Fingerprint(), AccessToken: func(context.Context) (string, error) { return testToken, nil }}}
}

// A deterministic SOCKS fixture proves that all onion dialing passes through
// this boundary and sends its hostname to the proxy, without local DNS lookup.
func startSOCKS(t *testing.T, network, address, target string, deny bool) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	calls := &atomic.Int64{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			go func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				head := make([]byte, 2)
				if _, err := io.ReadFull(conn, head); err != nil {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				conn.Write([]byte{5, 0})
				req := make([]byte, 5)
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				if req[0] != 5 || req[1] != 1 || req[3] != 3 {
					return
				}
				name := make([]byte, int(req[4])+2)
				if _, err := io.ReadFull(conn, name); err != nil {
					return
				}
				if string(name[:len(name)-2]) != testOnion || binary.BigEndian.Uint16(name[len(name)-2:]) != 443 || deny {
					conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				dst, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer dst.Close()
				stopDst := context.AfterFunc(ctx, func() { dst.Close() })
				defer stopDst()
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				cio.Pipe(conn, dst)
			}()
		}
	}()
	return listener.Addr().String(), calls
}

func backend(t *testing.T, network string, handler func(net.Conn)) Endpoint {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "unix" {
		address = filepath.Join(shortTemp(t), "s")
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				handler(c)
			}()
		}
	}()
	return Endpoint{network, listener.Addr().String()}
}

func mapped(t *testing.T, f *fixture, id string, endpoint Endpoint) *Mapping {
	t.Helper()
	if err := f.server.SetService(id, endpoint); err != nil {
		t.Fatal(err)
	}
	m, err := Map(context.Background(), f.cfg, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
func connect(t *testing.T, m *Mapping) *net.TCPConn {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, m.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func exchange(t *testing.T, m *Mapping, payload []byte) []byte {
	t.Helper()
	c := connect(t, m)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite()
	out, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v (mapping: %v)", err, m.Status())
	}
	return out
}
func expectEcho(t *testing.T, c io.ReadWriter, body string) {
	t.Helper()
	c.Write([]byte(body))
	got := make([]byte, len(body))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != body {
		t.Fatalf("echo %q: %q, %v", body, got, err)
	}
}

func TestOpaqueBinaryTCPUnixAndHalfClose(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			f := newFixture(t, nil)
			// The backend responds only after observing the upload's EOF. The response
			// is larger than the SSH window, so early close loses data deterministically.
			endpoint := backend(t, network, func(c net.Conn) { body, _ := io.ReadAll(c); time.Sleep(40 * time.Millisecond); c.Write(body) })
			m := mapped(t, f, "binary", endpoint)
			payload := make([]byte, 3*1024*1024)
			rand.Read(payload)
			if got := exchange(t, m, payload); !bytes.Equal(got, payload) {
				t.Fatalf("binary mismatch: got %d want %d", len(got), len(payload))
			}
			if f.proxyCalls.Load() != 1 {
				t.Fatal("unexpected carrier count")
			}
		})
	}
}

func TestIndependentCarriersAndAtomicAutoPort(t *testing.T) {
	f := newFixture(t, nil)
	m := mapped(t, f, "echo", backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) }))
	if extra, err := net.Listen("tcp", m.Addr().String()); err == nil {
		extra.Close()
		t.Fatal("Auto port was not reserved")
	}
	a, b := connect(t, m), connect(t, m)
	expectEcho(t, a, "one")
	expectEcho(t, b, "two")
	if f.proxyCalls.Load() != 2 {
		t.Fatalf("got %d carriers", f.proxyCalls.Load())
	}
	// Holding one established stream open does not block a separate carrier.
	expectEcho(t, b, "independent")
	m.Close()
	for _, c := range []net.Conn{a, b} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := c.Read(make([]byte, 1)); n != 0 {
			t.Fatal("closed mapping still readable")
		}
	}
	l, err := net.Listen("tcp", m.Addr().String())
	if err != nil {
		t.Fatal("port not released:", err)
	}
	l.Close()
}

func TestSSEAndHTTPUploadUnchanged(t *testing.T) {
	f := newFixture(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for n := 0; n < 5; n++ {
			fmt.Fprintf(w, "id: %d\ndata: {\"n\":%d}\n\n", n, n)
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer app.Close()
	m := mapped(t, f, "web", Endpoint{"tcp", app.Listener.Addr().String()})
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	body := bytes.Repeat([]byte{0, 255, 17, 32}, 65536)
	response, err := client.Post("http://"+m.Addr().String()+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("upload altered", err)
	}
	response, err = client.Get("http://" + m.Addr().String() + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first := make([]byte, 6)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "id: 0\n" {
		t.Fatal("SSE prefix altered")
	}
	tail, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(append(first, tail...)), "data:") != 5 {
		t.Fatal("missing SSE event")
	}
}

func TestRemoveReplaceRevokeAndClose(t *testing.T) {
	f := newFixture(t, nil)
	ep := backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) })
	a, b := mapped(t, f, "first", ep), mapped(t, f, "second", ep)
	ca, cb := connect(t, a), connect(t, b)
	expectEcho(t, ca, "a")
	expectEcho(t, cb, "b")
	if err := f.server.SetService("first", ep); err != nil {
		t.Fatal(err)
	}
	expectEcho(t, ca, "unchanged")
	f.server.RemoveService("first")
	mustClosed(t, ca)
	expectEcho(t, cb, "survives")
	f.server.Revoke()
	mustClosed(t, cb)
	// Revoke invalidates carriers, not the approved service catalogue. Authelia
	// token revocation is separately controlled by the caller.
	cc := connect(t, b)
	expectEcho(t, cc, "new")
	replacement := backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) })
	f.server.SetService("second", replacement)
	mustClosed(t, cc)
	cd := connect(t, b)
	expectEcho(t, cd, "replacement")
	f.server.Close()
	mustClosed(t, cd)
	if err := f.server.SetService("new", ep); err == nil {
		t.Fatal("closed server accepted a service")
	}
}
func mustClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatal("connection survived revocation")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection was not closed")
	}
}

func TestTorUnixSOCKSAndNoFallback(t *testing.T) {
	f := newFixture(t, nil)
	ep := backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) })
	addr, calls := startSOCKS(t, "unix", filepath.Join(shortTemp(t), "s"), f.tlsServer.Listener.Addr().String(), false)
	f.cfg.SOCKSNetwork = "unix"
	f.cfg.SOCKSAddress = addr
	m := mapped(t, f, "echo", ep)
	if got := exchange(t, m, []byte("unix SOCKS")); string(got) != "unix SOCKS" {
		t.Fatal("Unix proxy failed")
	}
	if calls.Load() != 1 {
		t.Fatal("Unix proxy not used")
	}
	f.cfg.SOCKSAddress = filepath.Join(shortTemp(t), "missing")
	broken, err := Map(context.Background(), f.cfg, "echo", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	expectFailure(t, broken)
	if broken.Status() == nil {
		t.Fatal("missing failure status")
	}
	addr, calls = startSOCKS(t, "tcp", "127.0.0.1:0", f.tlsServer.Listener.Addr().String(), true)
	f.cfg.SOCKSNetwork = "tcp"
	f.cfg.SOCKSAddress = addr
	denied, err := Map(context.Background(), f.cfg, "echo", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	expectFailure(t, denied)
	if calls.Load() != 1 {
		t.Fatal("denied SOCKS retried")
	}
}

func TestTransportTrustFailures(t *testing.T) {
	for _, name := range []string{"bearer", "pin", "roots", "client-cert"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.server.SetService("echo", backend(t, "tcp", func(c net.Conn) { t.Error("unauthorized backend dial") }))
			switch name {
			case "bearer":
				f.cfg.AccessToken = func(context.Context) (string, error) { return "wrong", nil }
			case "pin":
				f.cfg.Fingerprint = strings.Repeat("A", 43) + "="
			case "roots":
				f.cfg.TLS.RootCAs = x509.NewCertPool()
			case "client-cert":
				f.cfg.TLS.Certificates = []tls.Certificate{{}}
			}
			m, err := Map(context.Background(), f.cfg, "echo", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			expectFailure(t, m)
			if m.Status() == nil {
				t.Fatal("no failure status")
			}
		})
	}
}

func TestRejectInvalidConfiguration(t *testing.T) {
	for _, ep := range []Endpoint{{"tcp", "example.com:80"}, {"tcp", "0.0.0.0:80"}, {"tcp", "192.168.1.1:80"}, {"tcp", "127.0.0.1:0"}, {"tcp", "127.0.0.1:080"}, {"udp", "127.0.0.1:53"}, {"unix", "relative"}, {"unix", "/a/../b"}} {
		if ep.validate() == nil {
			t.Errorf("accepted %+v", ep)
		}
	}
	f := newFixture(t, nil)
	for _, id := range []string{"", "../echo", "Echo", "echo/udp", "a%2fb", "-a", "a-"} {
		if _, _, err := f.cfg.prepare(id); err == nil {
			t.Errorf("accepted ID %q", id)
		}
	}
	for _, address := range []string{"http://" + testOnion, "https://example.com", "https://" + testOnion + ":444", "https://user@" + testOnion, "https://" + testOnion + "/other", "https://" + testOnion + "?x=1"} {
		cfg := f.cfg
		cfg.OnionURL = address
		if _, _, err := cfg.prepare("echo"); err == nil {
			t.Errorf("accepted origin %q", address)
		}
	}
	cfg := f.cfg
	cfg.TLS = cfg.TLS.Clone()
	cfg.TLS.InsecureSkipVerify = true
	if _, _, err := cfg.prepare("echo"); err == nil {
		t.Fatal("TLS bypass accepted")
	}
	cfg = f.cfg
	cfg.SOCKSNetwork = ""
	if _, _, err := cfg.prepare("echo"); err == nil {
		t.Fatal("implicit proxy network accepted")
	}
}

func rawSSH(t *testing.T, f *fixture, id string) ssh.Conn {
	t.Helper()
	d, u, err := f.cfg.prepare(id)
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := d.DialContext(context.Background(), u, http.Header{"Authorization": []string{"Bearer " + testToken}})
	if err != nil {
		t.Fatal(err)
	}
	conn := cnet.NewWebSocketConn(ws)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	sc, channels, requests, err := ssh.NewClientConn(conn, "", &ssh.ClientConfig{User: "torkitten", Auth: []ssh.AuthMethod{ssh.Password(testToken)}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if string(key.Marshal()) != string(f.server.signer.PublicKey().Marshal()) {
			return errors.New("pin")
		}
		return nil
	}})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); sc.Close() })
	go bind(ctx, sc, requests, channels)
	return sc
}
func wireConfig(id string) *settings.Remote {
	return &settings.Remote{LocalHost: "127.0.0.1", LocalPort: "1", LocalProto: "tcp", RemoteHost: id, RemotePort: "1", RemoteProto: "tcp"}
}

func TestMaliciousConfigAndChannelRejected(t *testing.T) {
	f := newFixture(t, nil)
	ep := backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) })
	f.server.SetService("echo", ep)
	for _, kind := range []string{"udp", "reverse", "socks", "destination", "nil", "extra"} {
		t.Run(kind, func(t *testing.T) {
			sc := rawSSH(t, f, "echo")
			defer sc.Close()
			r := wireConfig("echo")
			rs := settings.Remotes{r}
			switch kind {
			case "udp":
				r.RemoteProto = "udp"
			case "reverse":
				r.Reverse = true
			case "socks":
				r.Socks = true
			case "destination":
				r.RemoteHost = "127.0.0.1"
				r.RemotePort = "22"
			case "nil":
				rs = settings.Remotes{nil}
			case "extra":
				rs = append(rs, wireConfig("echo"))
			}
			ok, _, err := sc.SendRequest("config", true, settings.EncodeConfig(settings.Config{Remotes: rs}))
			if err == nil && ok {
				t.Fatal("malicious configuration accepted")
			}
		})
	}
	sc := rawSSH(t, f, "echo")
	defer sc.Close()
	ok, _, err := sc.SendRequest("config", true, settings.EncodeConfig(settings.Config{Remotes: settings.Remotes{wireConfig("echo")}}))
	if err != nil || !ok {
		t.Fatal("valid config", err)
	}
	for _, target := range []string{"echo:1/udp", "echo:1/tcp", "127.0.0.1:22", "socks", "other:1"} {
		if c, _, err := sc.OpenChannel("chisel", []byte(target)); err == nil {
			c.Close()
			t.Fatalf("accepted target %q", target)
		}
	}
	if c, _, err := sc.OpenChannel("direct-tcpip", []byte("echo:1")); err == nil {
		c.Close()
		t.Fatal("accepted wrong channel type")
	}
	ch, requests, err := sc.OpenChannel("chisel", []byte("echo:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(requests)
	expectEcho(t, ch, "approved")
	if c, _, err := sc.OpenChannel("chisel", []byte("echo:1")); err == nil {
		c.Close()
		t.Fatal("accepted second channel on carrier")
	}
}

func TestRevokeDuringAuthorization(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newFixture(t, func(context.Context, string) error { close(entered); <-release; return nil })
	m := mapped(t, f, "echo", backend(t, "tcp", func(c net.Conn) { t.Error("backend reached after revocation") }))
	c := connect(t, m)
	c.Write([]byte("pending"))
	<-entered
	f.server.Revoke()
	close(release)
	mustClosed(t, c)
}

func TestStockChiselClientInteroperability(t *testing.T) {
	f := newFixture(t, nil)
	f.server.SetService("echo", backend(t, "tcp", func(c net.Conn) { io.Copy(c, c) }))
	dir := shortTemp(t)
	for name, data := range map[string][]byte{"ca": f.caPEM, "cert": f.certPEM, "key": f.keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	native, stdio := net.Pipe()
	defer native.Close()
	defer stdio.Close()
	native.SetDeadline(time.Now().Add(10 * time.Second))
	previous := cio.Stdio
	cio.Stdio = &struct {
		io.ReadCloser
		io.Writer
	}{stdio, stdio}
	defer func() { cio.Stdio = previous }()
	client, err := chclient.NewClient(&chclient.Config{Server: f.cfg.OnionURL + "/tunnel/echo", Auth: "torkitten:" + testToken, Fingerprint: f.cfg.Fingerprint, Headers: http.Header{"Authorization": []string{"Bearer " + testToken}}, Proxy: "socks://" + f.cfg.SOCKSAddress, Remotes: []string{"stdio:echo:1"}, KeepAlive: 25 * time.Second, MaxRetryCount: 0, TLS: chclient.TLSConfig{CA: filepath.Join(dir, "ca"), Cert: filepath.Join(dir, "cert"), Key: filepath.Join(dir, "key")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); client.Close(); client.Wait() }()
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	if !client.Ready(readyCtx) {
		t.Fatal("stock Chisel did not connect")
	}
	expectEcho(t, native, "stock protocol preserved")
	if f.proxyCalls.Load() != 1 {
		t.Fatal("stock client used unexpected carrier count")
	}
}

func expectFailure(t *testing.T, m *Mapping) {
	t.Helper()
	c := connect(t, m)
	c.Write([]byte("must fail"))
	got, err := io.ReadAll(c)
	if len(got) != 0 {
		t.Fatal("failed boundary delivered payload")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("failed boundary did not close")
	}
}

func TestHalfCloseWaitsBeyondTenSeconds(t *testing.T) {
	f := newFixture(t, nil)
	ep := backend(t, "tcp", func(c net.Conn) { body, _ := io.ReadAll(c); time.Sleep(11 * time.Second); c.Write(body) })
	m := mapped(t, f, "delayed", ep)
	c := connect(t, m)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte("after EOF"))
	c.CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "after EOF" {
		t.Fatalf("delayed half-close response: %q %v", got, err)
	}
}

func TestCarriedWebSocketAndSSH(t *testing.T) {
	f := newFixture(t, nil)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			typ, body, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if ws.WriteMessage(typ, body) != nil {
				return
			}
		}
	}))
	defer app.Close()
	m := mapped(t, f, "websocket", Endpoint{"tcp", app.Listener.Addr().String()})
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+m.Addr().String()+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	want := []byte{0, 1, 255, 42}
	ws.WriteMessage(websocket.BinaryMessage, want)
	kind, got, err := ws.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(got, want) {
		t.Fatal("carried WebSocket altered", err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(private)
	innerConfig := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) != "native-test" {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	innerConfig.AddHostKey(hostKey)
	ep := backend(t, "tcp", func(c net.Conn) {
		sc, channels, requests, err := ssh.NewServerConn(c, innerConfig)
		if err != nil {
			return
		}
		defer sc.Close()
		go ssh.DiscardRequests(requests)
		for pending := range channels {
			if pending.ChannelType() != "session" {
				pending.Reject(ssh.Prohibited, "session only")
				continue
			}
			ch, requests, err := pending.Accept()
			if err != nil {
				return
			}
			for request := range requests {
				if request.Type != "exec" {
					request.Reply(false, nil)
					continue
				}
				request.Reply(true, nil)
				ch.Write([]byte("native SSH payload"))
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.Close()
				break
			}
		}
	})
	nativeMapping := mapped(t, f, "native-ssh", ep)
	sc, err := ssh.Dial("tcp", nativeMapping.Addr().String(), &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("native-test")}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), hostKey.PublicKey().Marshal()) {
			return nil
		}
		return errors.New("wrong native key")
	}, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	session, err := sc.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	got, err = session.Output("fixture-command")
	if err != nil || string(got) != "native SSH payload" {
		t.Fatalf("native SSH output %q %v", got, err)
	}
}

func TestHTTPBoundaryRejectsNonCanonicalRequests(t *testing.T) {
	f := newFixture(t, nil)
	f.server.SetService("echo", Endpoint{"tcp", "127.0.0.1:1"})
	for _, path := range []string{"/tunnel/echo/", "/tunnel/%65cho", "/tunnel/echo?x=1", "/tunnel/../echo", "/other/echo"} {
		req := httptest.NewRequest("GET", "https://"+testOnion+path, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		f.server.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Fatalf("path %s status %d", path, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "https://"+testOnion+"/tunnel/echo", nil)
	req.Header.Add("Authorization", "Bearer "+testToken)
	req.Header.Add("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("duplicate authorization accepted")
	}
}
