// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The operator trial preserves all product state and the root, but stages the
// old intermediate/leaf cache offline. A config change alone reuses old leaves.
func TestPinnedCaddyIssuerTransitionAndRollback(t *testing.T) {
	binary := os.Getenv("TORKITTEN_CADDY_BIN")
	if binary == "" {
		t.Skip("set TORKITTEN_CADDY_BIN for pinned integration test")
	}
	dir := t.TempDir()
	r := testRenderer(dir)
	r.TargetHost = "127.0.0.1"
	for _, path := range []string{r.LauncherRoot, r.StorageRoot, filepath.Join(dir, "saved")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s := renderState()
	s.Mappings = nil
	candidate, err := r.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	prior := strings.Replace(string(candidate), "\t\t\tintermediate_lifetime 17520h\n", "", 1)
	prior = strings.Replace(prior, "\tcert_issuer internal {\n", "\tcert_issuer internal {\n\t\tsign_with_root\n", 1)
	client, err := NewClient(r.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	stop := func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			cmd = nil
		}
	}
	defer stop()
	start := func(config []byte) {
		t.Helper()
		path := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(path, config, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(binary, "run", "--config", path, "--adapter", "caddyfile")
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		for client.Healthy(ctx) != nil {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	start([]byte(prior))
	root, err := client.RootCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		t.Fatal("invalid public root")
	}
	chain := func() []*x509.Certificate {
		t.Helper()
		for {
			raw, err := (&net.Dialer{}).DialContext(ctx, "unix", r.OnionTLSSocket)
			if err == nil {
				conn := tls.Client(raw, &tls.Config{ServerName: s.Host(""), RootCAs: roots})
				err = conn.HandshakeContext(ctx)
				if err == nil {
					verified := conn.ConnectionState().VerifiedChains[0]
					_ = conn.Close()
					return verified
				}
				_ = conn.Close()
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	original := chain()
	if len(original) != 2 {
		t.Fatal("prior fixture was not direct-root signed")
	}
	stop()
	start(candidate)
	if cached := chain(); len(cached) != 2 || !bytes.Equal(cached[0].Raw, original[0].Raw) {
		t.Fatal("unexpected cache behavior; re-evaluate the offline transition procedure")
	}
	stored, err := os.ReadFile(filepath.Join(r.StorageRoot, "pki/authorities/local/intermediate.crt"))
	block, _ := pem.Decode(stored)
	if err != nil || block == nil {
		t.Fatal("stored public intermediate unavailable")
	}
	oldIntermediate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || oldIntermediate.NotAfter.Sub(oldIntermediate.NotBefore) != 7*24*time.Hour {
		t.Fatal("unexpected stored-intermediate behavior after configuration change")
	}
	stop()
	stage := func(relative, name string) {
		t.Helper()
		if err := os.Rename(filepath.Join(r.StorageRoot, relative), filepath.Join(dir, "saved", name)); err != nil {
			t.Fatal(err)
		}
	}
	stage("certificates/local", "direct-leaves")
	stage("pki/authorities/local/intermediate.crt", "old-intermediate.crt")
	stage("pki/authorities/local/intermediate.key", "old-intermediate.key")
	start(candidate)
	updated := chain()
	if len(updated) != 3 || updated[0].CheckSignatureFrom(updated[1]) != nil || updated[1].CheckSignatureFrom(updated[2]) != nil || !bytes.Equal(updated[2].Raw, original[1].Raw) {
		t.Fatal("intermediate trial did not retain the original root")
	}
	if updated[0].NotAfter.Sub(updated[0].NotBefore) != 397*24*time.Hour || updated[1].NotAfter.Sub(updated[1].NotBefore) != 730*24*time.Hour {
		t.Fatal("intermediate trial silently clamped certificate lifetimes")
	}
	stop()
	// Roll back only issuance; retain the current root and intermediate state.
	stage("certificates/local", "intermediate-leaves")
	start([]byte(prior))
	reverted := chain()
	rootAfter, err := client.RootCA(ctx)
	if err != nil || !bytes.Equal(root, rootAfter) || len(reverted) != 2 || !bytes.Equal(reverted[1].Raw, original[1].Raw) {
		t.Fatal("direct-root rollback changed the persistent trust anchor")
	}
}
