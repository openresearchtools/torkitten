// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
	"torkitten/internal/authelia"
	"torkitten/internal/caddy"
	"torkitten/internal/model"
	"torkitten/internal/state"
	"torkitten/internal/supervisor"
	torkitTor "torkitten/internal/tor"
	"unsafe"
)

const maxCLIOutput = 64 << 10

type Lifecycle interface {
	StartAuthelia(context.Context) error
	StopAuthelia(context.Context) error
}
type Runtime struct {
	Tor         torkitTor.Paths
	Authelia    authelia.Paths
	Caddy       caddy.Renderer
	CaddyClient *caddy.Client
	CaddyConfig string
}

func PrepareRuntime(ctx context.Context, current model.State) (*Runtime, error) {
	tp, ap, renderer := torkitTor.DefaultPaths(), authelia.DefaultPaths(), caddy.DefaultRenderer()
	configPath := "/etc/torkitten/caddy/Caddyfile"
	for _, dir := range []string{filepath.Dir(configPath), renderer.StorageRoot} {
		if err := state.EnsureDir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	steps := []func() error{tp.Ensure, ap.EnsureFiles,
		func() error { return tp.RecoverIdentity(current.ServiceID) },
		func() error { return tp.Reconcile(current.Devices, current.Pending) },
		func() error { return tp.WriteConfig(current.Publication) },
		func() error { return tp.Validate(ctx) }}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	initial, err := denyOnlyCaddy(renderer)
	if err != nil {
		return nil, err
	}
	if err = state.AtomicWrite(configPath, initial, 0o600); err != nil {
		return nil, err
	}
	for _, socket := range []string{renderer.AdminSocket, renderer.OnionHTTPSocket, renderer.OnionTLSSocket, ap.Socket, tp.ControlSocket} {
		_ = os.Remove(socket)
	}
	client, err := caddy.NewClient(renderer.AdminSocket)
	if err != nil {
		return nil, err
	}
	return &Runtime{Tor: tp, Authelia: ap, Caddy: renderer, CaddyClient: client, CaddyConfig: configPath}, nil
}
func denyOnlyCaddy(renderer caddy.Renderer) ([]byte, error) {
	return renderer.Render(model.NewState())
}

type SupervisedLifecycle struct {
	Process *supervisor.Supervisor
	Client  *authelia.Client
}

func (l SupervisedLifecycle) StartAuthelia(ctx context.Context) error {
	if err := l.Process.StartComponent(supervisor.Authelia); err != nil {
		return err
	}
	return WaitHealth(ctx, l.Client.Healthy)
}
func (l SupervisedLifecycle) StopAuthelia(ctx context.Context) error {
	if err := l.Process.StopComponent(supervisor.Authelia); err != nil {
		return err
	}
	for {
		for _, status := range l.Process.Statuses() {
			if status.Name == supervisor.Authelia && status.State == "stopped" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func PrepareAuthelia(ctx context.Context, paths authelia.Paths, serviceID string) (*authelia.Client, error) {
	config, err := paths.Render(serviceID)
	if err == nil {
		err = state.AtomicWrite(paths.Config, config, 0o600)
	}
	client, clientErr := authelia.NewClient(paths.Socket, serviceID)
	if err == nil {
		err = clientErr
	}
	if err == nil {
		err = (authelia.Runner{Paths: paths}).Validate(ctx)
	}
	return client, err
}
func WaitHealth(ctx context.Context, check func(context.Context) error) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := check(attempt)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type FactorVerifier interface {
	Verify(context.Context, string, []byte, string) error
}
type Initializer interface {
	Initialize(context.Context, model.LocalSession) error
}
type SessionIssuer interface {
	Issue(string) (cookie, csrf string, record model.LocalSession, err error)
}
type Manager struct {
	mu          sync.Mutex
	paths       authelia.Paths
	lifecycle   Lifecycle
	factors     FactorVerifier
	initializer Initializer
	sessions    SessionIssuer
	flow        *setupFlow
	now         func() time.Time
	hash        func(context.Context, authelia.Paths, []byte) (string, error)
	generate    func(context.Context, string) error
}
type setupFlow struct {
	id, username string
	password     []byte
	expires      time.Time
}

func New(paths authelia.Paths, lifecycle Lifecycle, factors FactorVerifier, initializer Initializer, sessions SessionIssuer) *Manager {
	runner := authelia.Runner{Paths: paths}
	return &Manager{paths: paths, lifecycle: lifecycle, factors: factors, initializer: initializer, sessions: sessions, now: time.Now, hash: HashPassword, generate: runner.GenerateTOTP}
}
func (m *Manager) Begin(ctx context.Context, initialized bool, username string, password, confirmation []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if initialized {
		return "", os.ErrNotExist
	}
	if err := model.ValidateUsername(username); err != nil || len(password) < 12 || len(password) > 128 || subtle.ConstantTimeCompare(password, confirmation) != 1 {
		return "", errors.New("invalid setup details")
	}
	m.clearFlow()
	digest, err := m.hash(ctx, m.paths, password)
	if err != nil {
		return "", err
	}
	if err = m.lifecycle.StopAuthelia(ctx); err != nil {
		return "", errors.New("could not reconcile Authelia")
	}
	for _, path := range []string{m.paths.Database, m.paths.Database + "-wal", m.paths.Database + "-shm", m.paths.QR} {
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", errors.New("could not clear incomplete setup")
		}
	}
	if err = authelia.WriteOwner(m.paths.Users, username, digest); err != nil {
		return "", err
	}
	if err = m.lifecycle.StartAuthelia(ctx); err != nil {
		return "", errors.New("Authelia did not become ready")
	}
	if err = m.generate(ctx, username); err != nil {
		return "", err
	}
	id, err := token()
	if err != nil {
		return "", err
	}
	m.flow = &setupFlow{id: id, username: username, password: append([]byte(nil), password...), expires: m.now().Add(10 * time.Minute)}
	return id, nil
}
func (m *Manager) QR(flowID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.validFlow(flowID) {
		return nil, os.ErrNotExist
	}
	file, err := os.Open(m.paths.QR)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 1<<20 {
		return nil, errors.New("unsafe setup QR")
	}
	data := make([]byte, info.Size())
	if _, err = io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}
func (m *Manager) Complete(ctx context.Context, flowID, totp string) (cookie, csrf string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.validFlow(flowID) {
		return "", "", errors.New("setup expired")
	}
	if err = m.factors.Verify(ctx, m.flow.username, m.flow.password, totp); err != nil {
		return "", "", errors.New("authentication failed")
	}
	cookie, csrf, record, err := m.sessions.Issue(m.flow.username)
	if err != nil {
		return "", "", err
	}
	if err = m.initializer.Initialize(ctx, record); err != nil {
		return "", "", err
	}
	m.clearFlow()
	_ = os.Remove(m.paths.QR)
	return cookie, csrf, nil
}
func (m *Manager) validFlow(id string) bool {
	if m.flow == nil || !m.flow.expires.After(m.now()) || subtle.ConstantTimeCompare([]byte(id), []byte(m.flow.id)) != 1 {
		if m.flow != nil && !m.flow.expires.After(m.now()) {
			m.clearFlow()
		}
		return false
	}
	return true
}
func (m *Manager) clearFlow() {
	if m.flow != nil {
		zero(m.flow.password)
		m.flow = nil
	}
}
func HashPassword(ctx context.Context, paths authelia.Paths, password []byte) (string, error) {
	if len(password) < 12 || len(password) > 128 || bytes.IndexByte(password, 0) >= 0 {
		return "", errors.New("password must contain 12-128 bytes")
	}
	args := []string{"crypto", "hash", "generate", "argon2", "--config", paths.Config}
	output, err := runPTY(ctx, paths.Binary, args, paths.Environment(os.Environ()), password)
	defer zero(output)
	if err != nil {
		return "", errors.New("Authelia password hashing failed")
	}
	plain := bytes.ReplaceAll(bytes.ReplaceAll(output, []byte{'\r'}, nil), []byte{'\n'}, nil)
	match := regexp.MustCompile(`Digest: (\$argon2id\$[A-Za-z0-9$=,/+.]+)`).FindSubmatch(plain)
	if len(match) != 2 || len(match[1]) > 512 {
		return "", errors.New("Authelia returned no password digest")
	}
	return string(match[1]), nil
}
func runPTY(ctx context.Context, binary string, args, env []string, password []byte) ([]byte, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer master.Close()
	var unlock int32
	var number uint32
	if ioctl(master.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)) != nil || ioctl(master.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&number)) != nil {
		return nil, errors.New("unable to open private terminal")
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env, cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, "/", slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = cmd.Start(); err != nil {
		slave.Close()
		return nil, err
	}
	slave.Close()
	var output bytes.Buffer
	entered, confirmed, overflow := false, false, false
	buf := make([]byte, 1024)
	for {
		n, readErr := master.Read(buf)
		if n > 0 {
			if output.Len()+n > maxCLIOutput {
				overflow = true
			} else {
				_, _ = output.Write(buf[:n])
			}
			plain := bytes.ReplaceAll(bytes.ReplaceAll(output.Bytes(), []byte{'\r'}, nil), []byte{'\n'}, nil)
			if !entered && bytes.Contains(plain, []byte("Enter Password:")) {
				err = writeSecret(master, password)
				entered = true
			} else if entered && !confirmed && bytes.Contains(plain, []byte("Confirm Password:")) {
				err = writeSecret(master, password)
				confirmed = true
			}
		}
		if readErr != nil || err != nil || overflow {
			break
		}
	}
	if overflow || err != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	result := append([]byte(nil), output.Bytes()...)
	zero(output.Bytes())
	if !entered || !confirmed || overflow || waitErr != nil {
		return result, errors.New("terminal command failed")
	}
	return result, nil
}
func writeSecret(file *os.File, secret []byte) error {
	line := append(append([]byte(nil), secret...), '\n')
	defer zero(line)
	_, err := file.Write(line)
	return err
}
func ioctl(fd uintptr, request uintptr, value unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}
func token() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func zero(data []byte) { clear(data) }
