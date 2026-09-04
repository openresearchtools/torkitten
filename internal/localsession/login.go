// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package localsession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
	"torkitten/internal/authelia"
)

type Login struct {
	mu     sync.Mutex
	client *authelia.Client
	flows  map[string]*loginFlow
	now    func() time.Time
}
type loginFlow struct {
	factors *authelia.FactorSession
	expires time.Time
}

func NewLogin(client *authelia.Client) *Login {
	return &Login{client: client, flows: map[string]*loginFlow{}, now: time.Now}
}
func (l *Login) Begin(ctx context.Context, owner string, password []byte) (string, error) {
	factors, err := l.client.BeginFactors(ctx, owner, password)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		factors.Destroy()
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	zero(raw)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key, flow := range l.flows {
		if !flow.expires.After(now) {
			flow.factors.Destroy()
			delete(l.flows, key)
		}
	}
	if len(l.flows) >= 32 {
		factors.Destroy()
		return "", errors.New("too many login attempts")
	}
	l.flows[id] = &loginFlow{factors: factors, expires: now.Add(5 * time.Minute)}
	return id, nil
}
func (l *Login) Complete(ctx context.Context, id, token string) (string, error) {
	l.mu.Lock()
	flow := l.flows[id]
	delete(l.flows, id)
	l.mu.Unlock()
	if flow == nil || !flow.expires.After(l.now()) {
		if flow != nil {
			flow.factors.Destroy()
		}
		return "", errors.New("authentication failed")
	}
	defer flow.factors.Destroy()
	return flow.factors.Complete(ctx, token)
}
