package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"torkitten/internal/model"
)

const maxStateBytes = 1 << 20

type Store struct {
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (store *Store) Load() (model.State, error) {
	file, err := os.Open(store.path)
	if err != nil {
		return model.State{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return model.State{}, err
	}
	if !info.Mode().IsRegular() {
		return model.State{}, errors.New("state path is not a regular file")
	}
	if info.Size() > maxStateBytes {
		return model.State{}, errors.New("state file exceeds size limit")
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	var value model.State
	if err := decoder.Decode(&value); err != nil {
		return model.State{}, fmt.Errorf("decode state: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return model.State{}, err
	}
	return value, nil
}

func (store *Store) Save(value model.State) error {
	value.Sort()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxStateBytes {
		return errors.New("state file exceeds size limit")
	}

	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	committed = true

	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("state contains multiple JSON values")
		}
		return fmt.Errorf("decode state trailer: %w", err)
	}
	return nil
}
