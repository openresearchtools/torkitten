package control

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"torkitten/internal/caddy"
	"torkitten/internal/model"
)

type StateStore interface {
	Save(model.State) error
}

type Renderer func(model.State) ([]byte, error)

type Manager struct {
	mutex    sync.RWMutex
	state    model.State
	store    StateStore
	loader   caddy.Loader
	renderer Renderer
}

func NewManager(initial model.State, store StateStore, loader caddy.Loader, renderer Renderer) (*Manager, error) {
	if store == nil || loader == nil || renderer == nil {
		return nil, errors.New("manager dependencies are required")
	}
	return &Manager{state: initial.Clone(), store: store, loader: loader, renderer: renderer}, nil
}

func (manager *Manager) State() model.State {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()
	return manager.state.Clone()
}

func (manager *Manager) Reconcile(ctx context.Context) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	document, err := manager.renderer(manager.state)
	if err != nil {
		return fmt.Errorf("render current configuration: %w", err)
	}
	if err := manager.loader.Load(ctx, document); err != nil {
		return fmt.Errorf("load current configuration: %w", err)
	}
	return nil
}

func (manager *Manager) Put(ctx context.Context, mapping model.Mapping) (model.State, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	candidate := manager.state.Clone()
	replaced := false
	for index := range candidate.Mappings {
		if candidate.Mappings[index].Prefix == mapping.Prefix {
			candidate.Mappings[index] = mapping
			replaced = true
			break
		}
	}
	if !replaced {
		candidate.Mappings = append(candidate.Mappings, mapping)
	}
	candidate.Sort()
	return manager.commit(ctx, candidate)
}

func (manager *Manager) Delete(ctx context.Context, prefix string) (model.State, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	candidate := manager.state.Clone()
	found := false
	filtered := candidate.Mappings[:0]
	for _, mapping := range candidate.Mappings {
		if mapping.Prefix == prefix {
			found = true
			continue
		}
		filtered = append(filtered, mapping)
	}
	if !found {
		return manager.state.Clone(), fmt.Errorf("mapping %q does not exist", prefix)
	}
	candidate.Mappings = filtered
	return manager.commit(ctx, candidate)
}

func (manager *Manager) commit(ctx context.Context, candidate model.State) (model.State, error) {
	document, err := manager.renderer(candidate)
	if err != nil {
		return manager.state.Clone(), fmt.Errorf("validate candidate: %w", err)
	}
	if err := manager.loader.Load(ctx, document); err != nil {
		return manager.state.Clone(), fmt.Errorf("Caddy rejected candidate: %w", err)
	}
	if err := manager.store.Save(candidate); err != nil {
		rollbackDocument, renderErr := manager.renderer(manager.state)
		if renderErr == nil {
			if rollbackErr := manager.loader.Load(ctx, rollbackDocument); rollbackErr != nil {
				return manager.state.Clone(), fmt.Errorf("persist candidate: %w; Caddy rollback also failed: %v", err, rollbackErr)
			}
		}
		return manager.state.Clone(), fmt.Errorf("persist candidate: %w", err)
	}
	manager.state = candidate.Clone()
	return manager.state.Clone(), nil
}

func SortedMappings(state model.State) []model.Mapping {
	mappings := append([]model.Mapping(nil), state.Mappings...)
	sort.Slice(mappings, func(left, right int) bool {
		return mappings[left].Prefix < mappings[right].Prefix
	})
	return mappings
}
