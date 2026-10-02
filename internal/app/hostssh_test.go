// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"torkitten/internal/tunnel"
)

// Run with an absolute TORKITTEN_SSH_BIN containing the pinned OpenSSH build.
// This test deliberately runs as the ordinary host user, never container root.
func TestHostSSHRealCommandSFTPAndRevocation(t *testing.T) {
	bin := os.Getenv("TORKITTEN_SSH_BIN")
	if bin == "" {
		t.Skip("set TORKITTEN_SSH_BIN for the real unprivileged OpenSSH proof")
	}
	if !filepath.IsAbs(bin) || os.Geteuid() == 0 {
		t.Fatal("the real SSH proof requires absolute binaries and a nonroot user")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root, e := os.MkdirTemp("", "tkssh-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	a := &App{ctx: ctx, root: root, run: filepath.Join(root, "run"), bin: bin, host: HostState{Version: 2, Initialized: true, Generation: "identity-" + randomID()}, services: Services{Version: 2, SSH: true}}
	for _, dir := range []string{a.run, a.gen()} {
		if e := privateDir(dir); e != nil {
			t.Fatal(e)
		}
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	a.relay, e = tunnel.NewServer(signer, func(context.Context, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer a.relay.Close()
	defer a.stopHostSSH()
	if e = a.syncHostSSH(true); e != nil {
		output, _ := exec.Command(filepath.Join(bin, "sshd"), "-t", "-f", a.gen("sshd.conf")).CombinedOutput()
		t.Fatalf("start: %v %s", e, output)
	}
	creds, e := a.sshCredentials()
	if e != nil {
		t.Fatal(e)
	}
	if creds.User == "root" {
		t.Fatal("root account exposed")
	}
	info, e := os.Stat(a.socket("host-ssh"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("SSH socket must be private")
	}
	private := filepath.Join(root, "client.key")
	known := filepath.Join(root, "known_hosts")
	if e = atomicWrite(private, []byte(creds.Key)); e != nil {
		t.Fatal(e)
	}
	if e = atomicWrite(known, []byte("torkitten-proof "+creds.HostKey)); e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			client, e := ln.Accept()
			if e != nil {
				return
			}
			server, e := net.Dial("unix", a.socket("host-ssh"))
			if e != nil {
				client.Close()
				continue
			}
			go func() {
				defer client.Close()
				defer server.Close()
				done := make(chan struct{})
				go func() { io.Copy(server, client); close(done) }()
				io.Copy(client, server)
				client.Close()
				server.Close()
				<-done
			}()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	common := []string{"-F", "/dev/null", "-oBatchMode=yes", "-oIdentitiesOnly=yes", "-oStrictHostKeyChecking=yes", "-oHostKeyAlias=torkitten-proof", "-oUserKnownHostsFile=" + known, "-i", private}
	sshArgs := append(append([]string{}, common...), "-p", port, creds.User+"@127.0.0.1")
	run := func(args []string) ([]byte, error) {
		c, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		return exec.CommandContext(c, "/usr/bin/ssh", args...).CombinedOutput()
	}
	output, e := run(append(append([]string{}, sshArgs...), "/usr/bin/id -u"))
	if e != nil || strings.TrimSpace(string(output)) != strconv.Itoa(os.Geteuid()) {
		t.Fatalf("ordinary SSH command failed: %v %s", e, output)
	}
	t.Log("ordinary OpenSSH command runs as the current host user")
	ptyArgs := append([]string{"-tt"}, sshArgs...)
	output, e = run(append(ptyArgs, "/usr/bin/tty"))
	if e != nil || !strings.Contains(string(output), "/dev/pts/") {
		t.Fatalf("ordinary SSH PTY failed: %v %s", e, output)
	}
	t.Log("ordinary OpenSSH interactive PTY is allocated")
	payload := []byte("SFTP exact bytes\x00\xff\n")
	source, remote, download := filepath.Join(root, "source"), filepath.Join(root, "remote"), filepath.Join(root, "download")
	if e = os.WriteFile(source, payload, 0600); e != nil {
		t.Fatal(e)
	}
	sftpArgs := append(append([]string{}, common...), "-P", port, "-b", "-", creds.User+"@127.0.0.1")
	c, stop := context.WithTimeout(ctx, 10*time.Second)
	command := exec.CommandContext(c, "/usr/bin/sftp", sftpArgs...)
	command.Stdin = strings.NewReader(fmt.Sprintf("put %q %q\nget %q %q\n", source, remote, remote, download))
	output, e = command.CombinedOutput()
	stop()
	if e != nil {
		t.Fatalf("SFTP failed: %v %s", e, output)
	}
	got, e := os.ReadFile(download)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("SFTP changed file bytes")
	}
	t.Log("ordinary SFTP upload/download preserves exact bytes")
	wrong := append(append([]string{}, common...), "-p", port, "root@127.0.0.1", "true")
	if _, e = run(wrong); e == nil {
		t.Fatal("another OS account authenticated")
	}
	password := append([]string{"-oPubkeyAuthentication=no", "-oPreferredAuthentications=password"}, sshArgs...)
	if _, e = run(append(password, "true")); e == nil {
		t.Fatal("password authentication accepted")
	}
	otherKey := filepath.Join(root, "unmatched.key")
	if _, e = runPrivate(ctx, "/usr/bin/ssh-keygen", nil, "-q", "-t", "ed25519", "-N", "", "-f", otherKey); e != nil {
		t.Fatal(e)
	}
	unmatched := append([]string{}, sshArgs...)
	for i := range unmatched {
		if unmatched[i] == private {
			unmatched[i] = otherKey
		}
	}
	if _, e = run(append(unmatched, "true")); e == nil {
		t.Fatal("unmatched public key authenticated")
	}
	t.Log("root/other-user, password-only and unmatched-key authentication denied")
	live := exec.Command("/usr/bin/ssh", append(append([]string{}, sshArgs...), "cat")...)
	input, e := live.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	outputPipe, e := live.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = live.Start(); e != nil {
		t.Fatal(e)
	}
	defer live.Process.Kill()
	defer input.Close()
	if _, e = io.WriteString(input, "ready\n"); e != nil {
		t.Fatal(e)
	}
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(outputPipe).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "ready\n" {
			t.Fatal("live SSH channel did not echo")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("live SSH channel not ready")
	}
	if e = a.syncHostSSH(false); e != nil {
		t.Fatal(e)
	}
	ended := make(chan error, 1)
	go func() { ended <- live.Wait() }()
	select {
	case e := <-ended:
		if e == nil {
			t.Fatal("disabled SSH channel completed as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("disable did not terminate live SSH")
	}
	if _, e = a.sshCredentials(); e == nil {
		t.Fatal("credentials available while disabled")
	}
	if conn, e := net.Dial("unix", a.socket("host-ssh")); e == nil {
		conn.Close()
		t.Fatal("SSH listener survived disable")
	}
	t.Log("disable closes the active SSH session and private listener")
	a.host.Generation = "identity-" + randomID()
	if e = privateDir(a.gen()); e != nil {
		t.Fatal(e)
	}
	if e = a.syncHostSSH(true); e != nil {
		t.Fatal(e)
	}
	renewed, e := a.sshCredentials()
	if e != nil {
		t.Fatal(e)
	}
	if renewed.Key == creds.Key || renewed.HostKey == creds.HostKey {
		t.Fatal("new identity reused SSH keys")
	}
	t.Log("identity rotation generates new SSH host and login keys")
}
