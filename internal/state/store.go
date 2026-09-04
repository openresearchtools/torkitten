// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"torkitten/internal/model"
)

const MaxBytes = 2 << 20

type Store struct {
	mu    sync.Mutex
	path  string
	value model.State
	write func(string, []byte, fs.FileMode) error
}

func Open(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("state path must be absolute")
	}
	if err := EnsureDir(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path, write: AtomicWrite}
	value, err := load(path)
	if errors.Is(err, os.ErrNotExist) {
		value = model.NewState()
		if err = s.persist(value); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	normalize(&value)
	s.value = value
	return s, nil
}

func (s *Store) View() model.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Clone(s.value)
}

// Transition serializes all durable writers. The callback may apply a component
// candidate before returning it. If validation or persistence fails, rollback is
// invoked while the writer lock remains held.
func (s *Store) Transition(fn func(model.State) (model.State, func() error, error)) error {
	if fn == nil {
		return errors.New("nil state transition")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current := Clone(s.value)
	next, rollback, err := fn(current)
	if err == nil {
		normalize(&next)
		err = next.Validate()
	}
	if err == nil {
		err = s.persist(next)
	}
	if err != nil {
		if rollback != nil {
			err = errors.Join(err, rollback())
		}
		return err
	}
	s.value = Clone(next)
	return nil
}

func (s *Store) persist(value model.State) error {
	if err := value.Validate(); err != nil {
		return fmt.Errorf("refusing invalid state: %w", err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxBytes {
		return errors.New("encoded state exceeds size limit")
	}
	if err = s.write(s.path, data, 0o600); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	return nil
}

func load(path string) (model.State, error) {
	var value model.State
	info, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > MaxBytes {
		return value, errors.New("state file type, permissions, or size are unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxBytes+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode state: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return value, errors.New("state contains trailing data")
	}
	if err = value.Validate(); err != nil {
		return value, fmt.Errorf("validate state: %w", err)
	}
	return value, nil
}

func normalize(value *model.State) {
	if value.Mappings == nil {
		value.Mappings = []model.Mapping{}
	}
	if value.Devices == nil {
		value.Devices = []model.Device{}
	}
	if value.Sessions == nil {
		value.Sessions = []model.LocalSession{}
	}
	if value.Tokens == nil {
		value.Tokens = []model.AgentToken{}
	}
}

func Clone(value model.State) model.State {
	data, _ := json.Marshal(value)
	var result model.State
	_ = json.Unmarshal(data, &result)
	normalize(&result)
	return result
}

func ComponentChange(ctx context.Context, store *Store, render func(model.State) ([]byte, error), apply func(context.Context, []byte) ([]byte, error), mutate func(*model.State) error) error {
	return store.Transition(func(current model.State) (model.State, func() error, error) {
		if !current.Initialized && len(current.Sessions) != 0 {
			return current, nil, errors.New("invalid setup transition")
		}
		candidate := Clone(current)
		if err := mutate(&candidate); err != nil {
			return current, nil, err
		}
		if !candidate.Initialized {
			return current, nil, errors.New("setup is incomplete")
		}
		if err := candidate.Validate(); err != nil {
			return current, nil, err
		}
		config, err := render(candidate)
		if err != nil {
			return current, nil, err
		}
		rollback := func() error {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			prior, err := render(current)
			if err == nil {
				_, err = apply(rollbackCtx, prior)
			}
			return err
		}
		if _, err = apply(ctx, config); err != nil {
			return current, nil, errors.Join(err, rollback())
		}
		return candidate, rollback, nil
	})
}

func ReconcileLoop(ctx context.Context, reconcile func(context.Context) error, failClosed func()) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := reconcile(attempt)
			cancel()
			if err != nil && failClosed != nil {
				failClosed()
			}
		}
	}
}
func EnsureDir(path string, mode fs.FileMode) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("directory path must be absolute")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a safe directory")
	}
	return os.Chmod(path, mode)
}

func AtomicWrite(path string, data []byte, mode fs.FileMode) (err error) {
	if !filepath.IsAbs(path) || len(data) > MaxBytes {
		return errors.New("invalid atomic write")
	}
	dir := filepath.Dir(path)
	uid, gid := -1, -1
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace non-regular file")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(stat.Uid), int(stat.Gid)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	file, err := os.CreateTemp(dir, ".torkitten-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(tmp)
	}()
	if err = file.Chmod(mode); err == nil && uid >= 0 {
		err = file.Chown(uid, gid)
	}
	if err == nil {
		_, err = io.Copy(file, bytes.NewReader(data))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
