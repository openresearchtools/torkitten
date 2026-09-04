// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"torkitten/internal/api"
	"torkitten/internal/apitoken"
	"torkitten/internal/authelia"
	"torkitten/internal/bootstrap"
	"torkitten/internal/caddy"
	"torkitten/internal/control"
	"torkitten/internal/localsession"
	"torkitten/internal/model"
	"torkitten/internal/onboarding"
	"torkitten/internal/state"
	"torkitten/internal/supervisor"
	torkitTor "torkitten/internal/tor"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("torkitten stopped: %v", err)
	}
}
func run() error {
	syscall.Umask(0o077)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	store, err := state.Open("/var/lib/torkitten/state.json")
	if err != nil {
		return err
	}
	current := store.View()
	prepareCtx, stopPrepare := context.WithTimeout(ctx, 15*time.Second)
	runtime, err := bootstrap.PrepareRuntime(prepareCtx, current)
	stopPrepare()
	if err != nil {
		return err
	}
	tp, ap, renderer, caddyClient := runtime.Tor, runtime.Authelia, runtime.Caddy, runtime.CaddyClient
	var autheliaClient *authelia.Client
	if current.ServiceID != "" {
		checkCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		autheliaClient, err = bootstrap.PrepareAuthelia(checkCtx, ap, current.ServiceID)
		stop()
		if err != nil {
			return err
		}
	}
	autheliaHealth := func(check context.Context) error {
		if autheliaClient == nil {
			return errors.New("Authelia is not configured")
		}
		return autheliaClient.Healthy(check)
	}
	secretEnv := []string{"AUTHELIA_SESSION_SECRET_FILE=" + filepath.Join(ap.SecretsDir, "session"), "AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=" + filepath.Join(ap.SecretsDir, "storage"), "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=" + filepath.Join(ap.SecretsDir, "jwt")}
	process, err := supervisor.New([]supervisor.Spec{
		{Name: supervisor.Tor, Path: tp.Binary, Args: []string{"-f", tp.Config}, Health: (torkitTor.Client{Socket: tp.ControlSocket, Cookie: tp.CookieFile}).Healthy},
		{Name: supervisor.Caddy, Path: "/usr/bin/caddy", Args: []string{"run", "--config", runtime.CaddyConfig, "--adapter", "caddyfile"}, Health: caddyClient.Healthy},
		{Name: supervisor.Authelia, Path: ap.Binary, Args: []string{"--config", ap.Config}, Env: secretEnv, Health: autheliaHealth, Disabled: !current.Initialized},
	}, log.Default())
	if err != nil {
		return err
	}
	if err = process.Start(ctx); err != nil {
		return err
	}
	defer process.Shutdown()
	readyCtx, stopReady := context.WithTimeout(ctx, 45*time.Second)
	defer stopReady()
	if err = bootstrap.WaitHealth(readyCtx, caddyClient.Healthy); err != nil {
		return err
	}
	serviceID, err := tp.WaitServiceID(readyCtx)
	if err != nil {
		return err
	}
	if current.ServiceID != "" && current.ServiceID != serviceID {
		return errors.New("Tor onion identity does not match durable state")
	}
	if current.ServiceID == "" {
		if err = store.Transition(func(next model.State) (model.State, func() error, error) {
			next.ServiceID = serviceID
			return next, nil, nil
		}); err != nil {
			return err
		}
		autheliaClient, err = bootstrap.PrepareAuthelia(readyCtx, ap, serviceID)
		if err != nil {
			return err
		}
	}
	manager := control.New(store, renderer, caddyClient, tp)
	manager.SetIdentityRuntime(caddy.IdentityRotator{Tor: tp, Renderer: renderer, Caddy: caddyClient, Authelia: ap, Auth: autheliaClient, Processes: process})
	if err = manager.ReconcileTor(readyCtx); err != nil {
		return err
	}
	config, err := renderer.Render(store.View())
	if err != nil {
		return err
	}
	if _, err = caddyClient.Apply(readyCtx, config); err != nil {
		return err
	}
	if store.View().Initialized {
		if err = bootstrap.WaitHealth(readyCtx, autheliaClient.Healthy); err != nil {
			return err
		}
	}
	sessions := localsession.New(store)
	manager.SetCredentials(sessions, process)
	life := bootstrap.SupervisedLifecycle{Process: process, Client: autheliaClient}
	setup := bootstrap.New(ap, life, autheliaClient, manager, sessions)
	onboard, err := onboarding.New(manager, autheliaClient, renderer.BootstrapRoot)
	if err != nil {
		return err
	}
	handler, err := api.New(api.Dependencies{Control: manager, Sessions: sessions, Factors: autheliaClient, Setup: setup, Tokens: apitoken.New(store), Onboarding: onboard, Supervisor: process})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:12755")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go state.ReconcileLoop(ctx, onboard.Expire, func() { _ = process.StopComponent(supervisor.Tor) })
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
