// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"torkitten/internal/tunnel"
)

type SSHCredentials struct {
	User    string `json:"user"`
	Key     string `json:"key"`
	HostKey string `json:"host_key"`
}
type hostSSH struct {
	listener *net.UnixListener
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	files    map[*os.File]bool
	workers  sync.WaitGroup
	once     sync.Once
	user     string
}

func hostSSHUser() (string, error) {
	u, err := user.Current()
	if err != nil || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || u.Uid != strconv.Itoa(os.Geteuid()) || !regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]*\$?$`).MatchString(u.Username) {
		return "", errors.New("host SSH requires a named, unprivileged current OS user")
	}
	return u.Username, nil
}
func (a *App) hostSSHConfig(username string) string {
	return fmt.Sprintf(`HostKey %s
AuthorizedKeysFile none
AuthorizedKeysCommand /usr/bin/cat %s
AuthorizedKeysCommandUser %s
SshdSessionPath %s
SshdAuthPath %s
AllowUsers %s
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
DisableForwarding yes
PermitUserEnvironment no
PermitUserRC no
UseDNS no
StrictModes yes
PrintMotd no
PrintLastLog no
LogLevel ERROR
Subsystem sftp internal-sftp
`, quote(a.gen("ssh.host")), quote(strings.ReplaceAll(a.gen("ssh.login.pub"), "%", "%%")), quote(username), quote(filepath.Join(a.bin, "sshd-session")), quote(filepath.Join(a.bin, "sshd-auth")), quote(username))
}

// The caller holds a.mu. Only the current identity owns these keys.
func (a *App) startHostSSH() error {
	if a.hostSSH != nil {
		return nil
	}
	username, err := hostSSHUser()
	if err != nil {
		return err
	}
	for _, name := range []string{"sshd", "sshd-session", "sshd-auth"} {
		st, e := os.Stat(filepath.Join(a.bin, name))
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
			return errors.New("bundled OpenSSH runtime is missing")
		}
	}
	for _, name := range []string{"ssh.host", "ssh.login"} {
		path := a.gen(name)
		if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			_, err = runPrivate(a.ctx, "/usr/bin/ssh-keygen", nil, "-q", "-t", "ed25519", "-N", "", "-C", "torkitten-"+name, "-f", path)
		}
		if err != nil {
			return err
		}
	}
	config := a.gen("sshd.conf")
	if err = atomicWrite(config, []byte(a.hostSSHConfig(username))); err != nil {
		return err
	}
	binary := filepath.Join(a.bin, "sshd")
	if _, err = runPrivate(a.ctx, binary, nil, "-t", "-f", config); err != nil {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: a.socket("host-ssh"), Net: "unix"})
	if err != nil {
		return err
	}
	if err = os.Chmod(a.socket("host-ssh"), 0600); err != nil {
		ln.Close()
		return err
	}
	ctx, cancel := context.WithCancel(a.ctx)
	h := &hostSSH{listener: ln, cancel: cancel, done: make(chan struct{}), files: map[*os.File]bool{}, user: username}
	a.hostSSH = h
	go func() {
		defer close(h.done)
		for {
			conn, e := ln.AcceptUnix()
			if e != nil {
				return
			}
			file, e := conn.File()
			conn.Close()
			if e != nil {
				continue
			}
			h.mu.Lock()
			h.files[file] = true
			h.mu.Unlock()
			h.workers.Add(1)
			go func() {
				defer h.workers.Done()
				defer func() { h.mu.Lock(); delete(h.files, file); file.Close(); h.mu.Unlock() }()
				cmd := exec.CommandContext(ctx, binary, "-i", "-e", "-f", config)
				cmd.Stdin = file
				cmd.Stdout = file
				cmd.Env = componentEnv()
				cmd.WaitDelay = 2 * time.Second
				_ = cmd.Run()
			}()
		}
	}()
	return nil
}
func (h *hostSSH) close() {
	h.once.Do(func() {
		h.cancel()
		h.listener.Close()
		<-h.done
		h.mu.Lock()
		for file := range h.files {
			_ = syscall.Shutdown(int(file.Fd()), syscall.SHUT_RDWR)
		}
		h.mu.Unlock()
		h.workers.Wait()
	})
}
func (a *App) stopHostSSH() {
	if a.hostSSH != nil {
		a.hostSSH.close()
		a.hostSSH = nil
	}
}

// syncHostSSH is called under a.mu after any required session revocation.
func (a *App) syncHostSSH(enabled bool) error {
	if !enabled || !a.host.Initialized || a.relay == nil {
		if a.relay != nil {
			a.relay.RemoveService("host-ssh")
		}
		a.stopHostSSH()
		return nil
	}
	if err := a.startHostSSH(); err != nil {
		return err
	}
	if err := a.relay.SetService("host-ssh", tunnel.Endpoint{Network: "unix", Address: a.socket("host-ssh")}); err != nil {
		a.stopHostSSH()
		return err
	}
	return nil
}
func (a *App) hostSSHView() *ViewService {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.services.SSH || !a.host.Initialized {
		return nil
	}
	return &ViewService{ID: "host-ssh", Title: "Host SSH", SSH: true, Actions: []string{}, Reachable: a.hostSSH != nil}
}

// The authenticated native-control caller holds a.mu and checks its OAuth epoch.
func (a *App) sshCredentials() (SSHCredentials, error) {
	if !a.services.SSH || !a.host.Initialized || a.hostSSH == nil {
		return SSHCredentials{}, errors.New("host SSH is disabled")
	}
	key, err := os.ReadFile(a.gen("ssh.login"))
	if err != nil {
		return SSHCredentials{}, err
	}
	defer clear(key)
	host, err := os.ReadFile(a.gen("ssh.host.pub"))
	if err != nil {
		return SSHCredentials{}, err
	}
	return SSHCredentials{User: a.hostSSH.user, Key: string(key), HostKey: string(host)}, nil
}
