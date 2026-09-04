// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package tor

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"torkitten/internal/model"
	"torkitten/internal/state"
)

const maxControlLine = 8 << 10

type Paths struct {
	Binary, Config, DataDir, HiddenServiceDir, ControlSocket, CookieFile, OnionHTTPSocket, OnionTLSSocket string
}

func DefaultPaths() Paths {
	return Paths{
		Binary: "/usr/bin/tor", Config: "/etc/torkitten/tor/torrc", DataDir: "/var/lib/torkitten/tor/data",
		HiddenServiceDir: "/var/lib/torkitten/tor/hidden-service", ControlSocket: "/run/torkitten/tor-control.sock",
		CookieFile: "/run/torkitten/tor-control.cookie", OnionHTTPSocket: "/run/torkitten/caddy-http.sock",
		OnionTLSSocket: "/run/torkitten/caddy-https.sock",
	}
}

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
var idRE = regexp.MustCompile(`^[a-f0-9]{32}$`)
var keyRE = regexp.MustCompile(`^[a-z2-7]{52}$`)

func (p Paths) safe() bool {
	for _, value := range []string{p.Binary, p.Config, p.DataDir, p.HiddenServiceDir, p.ControlSocket, p.CookieFile, p.OnionHTTPSocket, p.OnionTLSSocket} {
		if !filepath.IsAbs(value) || !safePath.MatchString(value) {
			return false
		}
	}
	return true
}
func (p Paths) Ensure() error {
	if !p.safe() {
		return errors.New("unsafe Tor paths")
	}
	for _, dir := range []string{filepath.Dir(p.Config), p.DataDir, p.HiddenServiceDir, p.AuthDir(), filepath.Dir(p.ControlSocket)} {
		if err := state.EnsureDir(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
func (p Paths) AuthDir() string { return filepath.Join(p.HiddenServiceDir, "authorized_clients") }
func (p Paths) Render(publication bool) ([]byte, error) {
	if !p.safe() {
		return nil, errors.New("unsafe Tor paths")
	}
	publish, disabled := 0, 1
	if publication {
		publish, disabled = 1, 0
	}
	return []byte(fmt.Sprintf(`DataDirectory %s
SocksPort 0
RunAsDaemon 0
SafeLogging 1
Log notice stdout
DisableDebuggerAttachment 1
ControlSocket %s
CookieAuthentication 1
CookieAuthFile %s
CookieAuthFileGroupReadable 0
DisableNetwork %d
PublishHidServDescriptors %d
HiddenServiceDir %s
HiddenServiceDirGroupReadable 0
HiddenServiceVersion 3
HiddenServiceAllowUnknownPorts 0
HiddenServiceEnableIntroDoSDefense 1
HiddenServicePort 80 unix:%s
HiddenServicePort 443 unix:%s
CellStatistics 0
ConnDirectionStatistics 0
DirReqStatistics 0
EntryStatistics 0
ExitPortStatistics 0
ExtraInfoStatistics 0
HiddenServiceStatistics 0
OverloadStatistics 0
PaddingStatistics 0
HeartbeatPeriod 0
`, p.DataDir, p.ControlSocket, p.CookieFile, disabled, publish, p.HiddenServiceDir, p.OnionHTTPSocket, p.OnionTLSSocket)), nil
}
func (p Paths) WriteConfig(publication bool) error {
	data, err := p.Render(publication)
	if err != nil {
		return err
	}
	return state.AtomicWrite(p.Config, data, 0o600)
}
func (p Paths) Validate(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, p.Binary, "--verify-config", "-f", p.Config)
	cmd.Env, cmd.Dir = cleanEnvironment(os.Environ()), "/"
	var output limitWriter
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil || output > 64<<10 {
		return errors.New("Tor rejected configuration")
	}
	return nil
}
func cleanEnvironment(base []string) []string {
	result := make([]string, 0, len(base))
	for _, value := range base {
		if !strings.HasPrefix(value, "TOR_") {
			result = append(result, value)
		}
	}
	return result
}
func (p Paths) ServiceID() (string, error) {
	path := filepath.Join(p.HiddenServiceDir, "hostname")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128 {
		return "", errors.New("Tor onion hostname unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	host := strings.TrimSpace(string(data))
	if !regexp.MustCompile(`^[a-z2-7]{56}\.onion$`).MatchString(host) {
		return "", errors.New("Tor returned invalid v3 onion hostname")
	}
	return strings.TrimSuffix(host, ".onion"), nil
}
func (p Paths) WaitServiceID(ctx context.Context) (string, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if id, err := p.ServiceID(); err == nil {
			return id, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}
func GenerateClientKey() (public, private string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	encode := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString
	return strings.ToLower(encode(key.PublicKey().Bytes())), strings.ToLower(encode(key.Bytes())), nil
}
func Credential(serviceID, private string) (string, error) {
	if !regexp.MustCompile(`^[a-z2-7]{56}$`).MatchString(serviceID) || !keyRE.MatchString(private) {
		return "", errors.New("invalid Tor client credential")
	}
	return serviceID + ":descriptor:x25519:" + private, nil
}
func (p Paths) WriteAuthorization(id, public string) error {
	if !idRE.MatchString(id) || !keyRE.MatchString(public) {
		return errors.New("invalid Tor authorization record")
	}
	return state.AtomicWrite(filepath.Join(p.AuthDir(), id+".auth"), []byte("descriptor:x25519:"+public+"\n"), 0o600)
}
func (p Paths) RemoveAuthorization(id string) error {
	if !idRE.MatchString(id) {
		return errors.New("invalid device id")
	}
	err := os.Remove(filepath.Join(p.AuthDir(), id+".auth"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (p Paths) Reconcile(devices []model.Device, pending *model.PendingDevice) error {
	expected := map[string]string{}
	for _, device := range devices {
		expected[device.ID] = device.PublicKey
	}
	if pending != nil {
		expected[pending.ID] = pending.PublicKey
	}
	ids := make([]string, 0, len(expected))
	for id := range expected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := p.WriteAuthorization(id, expected[id]); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(p.AuthDir())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		id := strings.TrimSuffix(name, ".auth")
		if strings.HasSuffix(name, ".auth") && !entry.IsDir() && expected[id] == "" {
			if err = os.Remove(filepath.Join(p.AuthDir(), name)); err != nil {
				return err
			}
		}
	}
	return nil
}

type IdentityStage struct {
	Root, HiddenServiceDir, ServiceID string
}

func (p Paths) StageIdentity(ctx context.Context, devices []model.Device) (stage *IdentityStage, err error) {
	root, err := os.MkdirTemp(filepath.Dir(p.HiddenServiceDir), ".identity-stage-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
		}
	}()
	candidate := p
	candidate.Config, candidate.DataDir = filepath.Join(root, "torrc"), filepath.Join(root, "data")
	candidate.HiddenServiceDir, candidate.ControlSocket, candidate.CookieFile = filepath.Join(root, "hidden-service"), filepath.Join(root, "control.sock"), filepath.Join(root, "cookie")
	if err = candidate.Ensure(); err != nil {
		return nil, err
	}
	if err = candidate.Reconcile(devices, nil); err != nil {
		return nil, err
	}
	config, err := candidate.Render(false)
	if err != nil {
		return nil, err
	}
	config = append(config, []byte("DisableNetwork 1\n")...)
	if err = state.AtomicWrite(candidate.Config, config, 0o600); err != nil {
		return nil, err
	}
	if err = candidate.Validate(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p.Binary, "-f", candidate.Config)
	cmd.Env, cmd.Dir = cleanEnvironment(os.Environ()), "/"
	var output limitWriter
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	serviceID, waitErr := candidate.WaitServiceID(ctx)
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
	if waitErr != nil || output > 64<<10 {
		return nil, errors.New("Tor could not stage an onion identity")
	}
	return &IdentityStage{Root: root, HiddenServiceDir: candidate.HiddenServiceDir, ServiceID: serviceID}, nil
}
func (p Paths) ActivateIdentity(stage *IdentityStage) (string, error) {
	if stage == nil || !strings.HasPrefix(stage.Root, filepath.Dir(p.HiddenServiceDir)+string(os.PathSeparator)+".identity-stage-") {
		return "", errors.New("invalid identity stage")
	}
	backup := p.HiddenServiceDir + ".previous"
	if err := os.RemoveAll(backup); err != nil {
		return "", err
	}
	if err := os.Rename(p.HiddenServiceDir, backup); err != nil {
		return "", err
	}
	if err := os.Rename(stage.HiddenServiceDir, p.HiddenServiceDir); err != nil {
		_ = os.Rename(backup, p.HiddenServiceDir)
		return "", err
	}
	_ = os.RemoveAll(stage.Root)
	return backup, nil
}
func (p Paths) RestoreIdentity(backup string) error {
	if backup != p.HiddenServiceDir+".previous" {
		return errors.New("invalid identity backup")
	}
	failed := p.HiddenServiceDir + ".failed"
	_ = os.RemoveAll(failed)
	if err := os.Rename(p.HiddenServiceDir, failed); err != nil {
		return err
	}
	if err := os.Rename(backup, p.HiddenServiceDir); err != nil {
		_ = os.Rename(failed, p.HiddenServiceDir)
		return err
	}
	return os.RemoveAll(failed)
}
func (p Paths) FinishIdentity(backup string) error {
	if backup != p.HiddenServiceDir+".previous" {
		return errors.New("invalid identity backup")
	}
	return os.RemoveAll(backup)
}
func (p Paths) RecoverIdentity(serviceID string) error {
	stages, _ := filepath.Glob(filepath.Join(filepath.Dir(p.HiddenServiceDir), ".identity-stage-*"))
	for _, stage := range stages {
		_ = os.RemoveAll(stage)
	}
	backup := p.HiddenServiceDir + ".previous"
	active, activeErr := p.ServiceID()
	if serviceID == "" || activeErr == nil && active == serviceID {
		return os.RemoveAll(backup)
	}
	previous := p
	previous.HiddenServiceDir = backup
	if prior, err := previous.ServiceID(); err != nil || prior != serviceID {
		return errors.New("durable Tor identity cannot be recovered")
	}
	failed := p.HiddenServiceDir + ".failed"
	_ = os.RemoveAll(failed)
	if err := os.Rename(p.HiddenServiceDir, failed); err != nil {
		return err
	}
	if err := os.Rename(backup, p.HiddenServiceDir); err != nil {
		_ = os.Rename(failed, p.HiddenServiceDir)
		return err
	}
	return os.RemoveAll(failed)
}

type Client struct{ Socket, Cookie string }

func (c Client) Reload(ctx context.Context) error  { return c.exchange(ctx, "SIGNAL RELOAD") }
func (c Client) Healthy(ctx context.Context) error { return c.exchange(ctx, "GETINFO version") }
func (c Client) exchange(ctx context.Context, command string) error {
	if !safePath.MatchString(c.Socket) || !safePath.MatchString(c.Cookie) {
		return errors.New("unsafe Tor control paths")
	}
	info, err := os.Lstat(c.Cookie)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 32 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("unsafe Tor control cookie")
	}
	cookie, err := os.ReadFile(c.Cookie)
	if err != nil || len(cookie) != 32 {
		return errors.New("invalid Tor control cookie")
	}
	defer zero(cookie)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	reader := bufio.NewReaderSize(conn, maxControlLine)
	if err = controlCommand(conn, reader, "AUTHENTICATE "+hex.EncodeToString(cookie)); err == nil {
		err = controlCommand(conn, reader, command)
	}
	_, _ = io.WriteString(conn, "QUIT\r\n")
	return err
}
func controlCommand(conn net.Conn, reader *bufio.Reader, command string) error {
	if _, err := io.WriteString(conn, command+"\r\n"); err != nil {
		return err
	}
	for lines := 0; lines < 64; lines++ {
		line, err := reader.ReadString('\n')
		if err != nil || len(line) > maxControlLine {
			return errors.New("invalid Tor control response")
		}
		if len(line) >= 4 && line[:3] == "250" && line[3] == ' ' {
			return nil
		}
		if len(line) >= 4 && line[3] == ' ' {
			return errors.New("Tor control command failed")
		}
	}
	return errors.New("Tor control response too long")
}

type limitWriter int

func (w *limitWriter) Write(data []byte) (int, error) {
	*w += limitWriter(len(data))
	return len(data), nil
}
func zero(data []byte) { clear(data) }
