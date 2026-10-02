// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

// Package tunnel adapts pristine Chisel wire components to host-approved services.
// It never interprets the carried application protocol or accepts remote dial targets.
package tunnel

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jpillora/chisel/share/cio"
	chtunnel "github.com/jpillora/chisel/share/tunnel"
	"golang.org/x/crypto/ssh"
)

const handshakeTimeout = 45 * time.Second

var servicePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var onionPattern = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

// Endpoint is host configuration, never supplied by a remote client.
type Endpoint struct{ Network, Address string }

func (e Endpoint) validate() error {
	switch e.Network {
	case "tcp":
		host, port, err := net.SplitHostPort(e.Address)
		n, pe := strconv.Atoi(port)
		ip := net.ParseIP(host)
		if err == nil && pe == nil && n > 0 && n <= 65535 && ip != nil && ip.IsLoopback() && strconv.Itoa(n) == port {
			return nil
		}
	case "unix":
		if filepath.IsAbs(e.Address) && filepath.Clean(e.Address) == e.Address && !strings.ContainsRune(e.Address, 0) {
			return nil
		}
	}
	return errors.New("endpoint must be numeric loopback TCP or an absolute Unix socket")
}

func validToken(token string) bool {
	if len(token) == 0 || len(token) > 8192 {
		return false
	}
	for _, c := range token {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

// Upstream Chisel owns SSH ping/pong, backpressure and half-close semantics.
// There is no stream lifetime deadline and no reconnection or replay loop.
func bind(ctx context.Context, c ssh.Conn, requests <-chan *ssh.Request, channels <-chan ssh.NewChannel) error {
	t := chtunnel.New(chtunnel.Config{Logger: cio.NewLogger("tunnel"), KeepAlive: 25 * time.Second})
	return t.BindSSH(ctx, c, requests, channels)
}
