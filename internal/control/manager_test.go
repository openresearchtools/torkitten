package control

import (
	"context"
	"errors"
	"testing"

	"torkitten/internal/model"
)

const testServiceID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

type fakeStore struct {
	err   error
	saved []model.State
}

func (store *fakeStore) Save(state model.State) error {
	store.saved = append(store.saved, state.Clone())
	return store.err
}

type fakeLoader struct {
	errors []error
	loads  [][]byte
}

func (loader *fakeLoader) Load(_ context.Context, document []byte) error {
	loader.loads = append(loader.loads, append([]byte(nil), document...))
	if len(loader.errors) == 0 {
		return nil
	}
	err := loader.errors[0]
	loader.errors = loader.errors[1:]
	return err
}

func renderer(state model.State) ([]byte, error) {
	for _, mapping := range state.Mappings {
		if err := model.ValidatePrefix(mapping.Prefix); err != nil {
			return nil, err
		}
	}
	return []byte(state.ServiceID + ":" + string(rune(len(state.Mappings)))), nil
}

func TestRejectedLoadDoesNotPersistOrMutate(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	loader := &fakeLoader{errors: []error{errors.New("invalid")}}
	manager, err := NewManager(model.NewState(testServiceID), store, loader, renderer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Put(context.Background(), model.Mapping{Prefix: "api", Port: 7777, Scheme: model.SchemeHTTP, Enable: true})
	if err == nil {
		t.Fatal("rejected Caddy load was accepted")
	}
	if len(store.saved) != 0 || len(manager.State().Mappings) != 0 {
		t.Fatal("rejected candidate changed persistent or in-memory state")
	}
}

func TestPersistenceFailureRollsCaddyBack(t *testing.T) {
	t.Parallel()

	store := &fakeStore{err: errors.New("disk full")}
	loader := &fakeLoader{}
	manager, err := NewManager(model.NewState(testServiceID), store, loader, renderer)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Put(context.Background(), model.Mapping{Prefix: "api", Port: 7777, Scheme: model.SchemeHTTP, Enable: true})
	if err == nil {
		t.Fatal("persistence failure was accepted")
	}
	if len(loader.loads) != 2 {
		t.Fatalf("Caddy loads = %d, want candidate plus rollback", len(loader.loads))
	}
	if len(manager.State().Mappings) != 0 {
		t.Fatal("failed candidate changed in-memory state")
	}
}

func TestSuccessfulPutCommitsAfterCaddy(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	loader := &fakeLoader{}
	manager, err := NewManager(model.NewState(testServiceID), store, loader, renderer)
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.Put(context.Background(), model.Mapping{Prefix: "api", Port: 7777, Scheme: model.SchemeHTTP, Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(loader.loads) != 1 || len(store.saved) != 1 || len(state.Mappings) != 1 {
		t.Fatal("successful candidate was not loaded and persisted exactly once")
	}
}
