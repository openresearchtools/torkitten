// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"torkitten/internal/tunnel"
)

type App struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	root, bin, run string
	host           HostState
	pendingSetup   *pendingSetup
	hostSSH        *hostSSH
	services       Services
	serviceBytes   string
	hostError      string
	processes      map[string]*process
	relay          *tunnel.Server
	profiles       map[string]*Profile
	admin, remote  *http.Server
	closed         sync.Once
	lock           *os.File
}

func Open(parent context.Context, root, bin string) (a *App, err error) {
	root = filepath.Clean(root)
	bin = filepath.Clean(bin)
	if !filepath.IsAbs(root) || !filepath.IsAbs(bin) || len(filepath.Join(root, "admin.sock")) > 100 {
		return nil, errors.New("absolute state/bin paths and a short Unix socket path are required")
	}
	if err = privateDir(root); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	a = &App{ctx: ctx, cancel: cancel, root: root, bin: bin, host: HostState{Version: 2}, services: Services{Version: 2, Services: []Service{}}, processes: map[string]*process{}, profiles: map[string]*Profile{}}
	cleanup := a
	defer func() {
		if err != nil {
			cleanup.Close()
		}
	}()
	a.lock, err = os.OpenFile(a.path("daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(a.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("another daemon owns this state")
	}
	temp := ""
	if runtime.GOOS == "android" {
		temp = root
	}
	a.run, err = os.MkdirTemp(temp, "torkitten-")
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{"profiles", "client-tor", "client-auth"} {
		if err = privateDir(filepath.Join(root, dir)); err != nil {
			return nil, err
		}
	}
	if e := readJSON(a.path("host.json"), &a.host); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if err = a.host.Validate(); err != nil {
		return nil, err
	}
	if e := readJSON(a.path("services.json"), &a.services); errors.Is(e, os.ErrNotExist) {
		err = writeJSON(a.path("services.json"), a.services)
	} else {
		err = e
	}
	if err != nil {
		return nil, err
	}
	if err = a.services.Validate(root); err != nil {
		return nil, err
	}
	if err = a.loadProfiles(); err != nil {
		return nil, err
	}
	if err = a.startClientTor(); err != nil {
		return nil, err
	}
	if a.host.Initialized {
		if err = a.startHost(); err != nil {
			return nil, err
		}
	}
	socket := a.path("admin.sock")
	if st, e := os.Lstat(socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("admin socket path is not a socket")
		}
		if err = os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	ln, e := net.Listen("unix", socket)
	if e != nil {
		return nil, e
	}
	if err = os.Chmod(socket, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	a.admin = &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go a.admin.Serve(ln)
	go a.watchServices()
	go func() { <-ctx.Done(); a.Close() }()
	return a, nil
}
func (a *App) path(parts ...string) string {
	return filepath.Join(append([]string{a.root}, parts...)...)
}
func (a *App) gen(parts ...string) string {
	return a.path(append([]string{a.host.Generation}, parts...)...)
}
func (a *App) socket(name string) string { return filepath.Join(a.run, name+".sock") }
func (a *App) Close() error {
	a.closed.Do(func() {
		a.cancel()
		if a.admin != nil {
			a.admin.Close()
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.clearPendingSetup()
		a.stopHostSSH()
		for _, p := range a.profiles {
			p.Close()
		}
		if a.relay != nil {
			a.relay.Close()
		}
		if a.remote != nil {
			a.remote.Close()
		}
		for _, p := range a.processes {
			p.stop()
		}
		if a.admin != nil {
			a.admin.Close()
			os.Remove(a.path("admin.sock"))
		}
		if a.run != "" {
			os.RemoveAll(a.run)
		}
		if a.lock != nil {
			a.lock.Close()
		}
	})
	return nil
}
func (a *App) startClientTor() error {
	cfg := torCommon(a.path("client-tor")) + "SocksPort unix:" + a.socket("socks") + "\nClientOnionAuthDir " + quote(a.path("client-auth")) + "\n"
	if err := atomicWrite(a.path("client-torrc"), []byte(cfg)); err != nil {
		return err
	}
	name := "tor"
	if runtime.GOOS == "android" {
		name = "libtor.so"
	}
	p, err := startProcess(a.ctx, filepath.Join(a.bin, name), a.path("client-tor.log"), "--defaults-torrc", "/dev/null", "-f", a.path("client-torrc"))
	if err != nil {
		return err
	}
	a.processes["client-tor"] = p
	return waitReady(a.ctx, p, func() error { _, err := os.Stat(a.socket("socks")); return err })
}
func (a *App) watchServices() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-tick.C:
		}
		a.mu.Lock()
		b, err := readPrivate(a.path("services.json"))
		if err == nil && (len(b) == 0 || string(b) != a.serviceBytes) {
			var s Services
			err = readJSON(a.path("services.json"), &s)
			if err == nil {
				err = s.Validate(a.root)
			}
			if err == nil {
				err = a.applyServices(s)
				if err == nil {
					a.serviceBytes = string(b)
					if strings.HasPrefix(a.hostError, "services.json rejected:") {
						a.hostError = ""
					}
				}
			}
		}
		if err != nil {
			a.hostError = "services.json rejected: " + err.Error()
			if a.relay != nil {
				a.relay.Revoke()
			}
		}
		for _, name := range []string{"tor", "caddy", "authelia"} {
			if p := a.processes[name]; p != nil && !p.alive() {
				a.hostError = name + " stopped; remote access is closed"
				if a.relay != nil {
					a.relay.Revoke()
				}
			}
		}
		a.mu.Unlock()
	}
}
