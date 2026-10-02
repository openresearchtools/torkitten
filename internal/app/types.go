// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const MaxFile = 2 << 20

var identifier = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
var onionName = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

var generationName = regexp.MustCompile(`^identity-[a-f0-9]{48}$`)
var deviceName = regexp.MustCompile(`^[a-f0-9]{48}$`)
var ownerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func (h HostState) Validate() error {
	if h.Version != 2 || len(h.Devices) > 64 || h.Generation != "" && !generationName.MatchString(h.Generation) {
		return errors.New("invalid host state")
	}
	if h.Initialized && (!generationName.MatchString(h.Generation) || !onionName.MatchString(h.Onion) || !ownerName.MatchString(h.Owner) || !strings.HasPrefix(h.OAuthClient, "torkitten-") || !deviceName.MatchString(strings.TrimPrefix(h.OAuthClient, "torkitten-"))) {
		return errors.New("invalid initialized host")
	}
	seen := map[string]bool{}
	for _, d := range h.Devices {
		if !deviceName.MatchString(d.ID) || seen[d.ID] || len(d.Certificate) > 8192 {
			return errors.New("invalid device record")
		}
		seen[d.ID] = true
	}
	return nil
}

type Endpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
}
type Service struct {
	ID        string              `json:"id"`
	Title     string              `json:"title"`
	Available bool                `json:"available"`
	SSH       bool                `json:"ssh"`
	Endpoint  Endpoint            `json:"endpoint"`
	Actions   map[string][]string `json:"actions"`
}
type Services struct {
	Version  int       `json:"version"`
	Services []Service `json:"services"`
}
type Device struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TorPublic   string `json:"tor_public"`
	Certificate string `json:"certificate"`
}
type HostState struct {
	Version     int      `json:"version"`
	Generation  string   `json:"generation"`
	Initialized bool     `json:"initialized"`
	Onion       string   `json:"onion"`
	OAuthClient string   `json:"oauth_client"`
	Owner       string   `json:"owner"`
	Devices     []Device `json:"devices"`
}
type Bundle struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Onion       string `json:"onion"`
	TorPrivate  string `json:"tor_private"`
	RootCA      string `json:"root_ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
}
type ViewService struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	SSH       bool     `json:"ssh"`
	Actions   []string `json:"actions"`
	Reachable bool     `json:"reachable"`
}

func (e Endpoint) Validate() error {
	switch e.Network {
	case "tcp":
		host, port, err := net.SplitHostPort(e.Address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("TCP endpoint must use a numeric loopback address")
		}
		var n int
		if _, err = fmt.Sscanf(port, "%d", &n); err != nil || fmt.Sprint(n) != port || n < 1 || n > 65535 {
			return errors.New("invalid TCP port")
		}
	case "unix":
		if !filepath.IsAbs(e.Address) || filepath.Clean(e.Address) != e.Address || strings.ContainsAny(e.Address, "\x00\r\n") || len(e.Address) > 100 {
			return errors.New("invalid absolute Unix socket")
		}
	default:
		return errors.New("endpoint must be tcp or unix")
	}
	return nil
}
func (s Services) Validate(privateRoot string) error {
	if s.Version != 2 || len(s.Services) > 64 {
		return errors.New("invalid services schema or count")
	}
	seen := map[string]bool{}
	for _, v := range s.Services {
		if !identifier.MatchString(v.ID) || seen[v.ID] || len(v.Title) < 1 || len(v.Title) > 80 {
			return errors.New("invalid or duplicate service")
		}
		seen[v.ID] = true
		if err := v.Endpoint.Validate(); err != nil {
			return err
		}
		if v.Endpoint.Network == "unix" && (v.Endpoint.Address == privateRoot || strings.HasPrefix(v.Endpoint.Address, privateRoot+string(os.PathSeparator))) {
			return errors.New("application control sockets cannot be shared")
		}
		for action, argv := range v.Actions {
			if action != "load" && action != "reload" && action != "stop" {
				return errors.New("unknown lifecycle action")
			}
			if len(argv) < 1 || len(argv) > 256 || !filepath.IsAbs(argv[0]) {
				return errors.New("actions require an absolute executable and argument array")
			}
			for _, arg := range argv {
				if len(arg) > 16384 || strings.IndexByte(arg, 0) >= 0 {
					return errors.New("invalid action argument")
				}
			}
		}
	}
	return nil
}
func randomID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func decode(data []byte, dst any) error {
	if len(data) > MaxFile {
		return errors.New("document too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing document data")
	}
	return nil
}
func readJSON(path string, dst any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > MaxFile {
		return errors.New("unsafe state file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decode(data, dst)
}
func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(b, '\n'))
}
func atomicWrite(path string, data []byte) (err error) {
	if !filepath.IsAbs(path) || len(data) > MaxFile {
		return errors.New("invalid state write")
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("refusing nonregular state path")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".torkitten-")
	if err != nil {
		return err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func privateDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state directory must be absolute")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe state directory")
	}
	return os.Chmod(path, 0700)
}
