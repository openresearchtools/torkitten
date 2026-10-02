// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"torkitten/internal/app"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "TorKitten:", err)
		os.Exit(1)
	}
}
func run() error {
	syscall.Umask(0077)
	args := os.Args[1:]
	daemon := len(args) > 0 && args[0] == "daemon"
	if daemon {
		args = args[1:]
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	f := flag.NewFlagSet("torkitten", flag.ContinueOnError)
	state := f.String("state", filepath.Join(config, "torkitten-v2"), "private application state directory")
	bin := f.String("bin-dir", filepath.Dir(executable), "directory containing pinned upstream binaries")
	if err = f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if daemon {
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		a, err := app.Open(ctx, *state, *bin)
		if err != nil {
			return err
		}
		defer a.Close()
		<-ctx.Done()
		return nil
	}
	socket := filepath.Join(*state, "admin.sock")
	ready := func() bool {
		c, e := net.DialTimeout("unix", socket, time.Second)
		if e != nil {
			return false
		}
		c.Close()
		return true
	}
	if !ready() {
		if err = os.MkdirAll(*state, 0700); err != nil {
			return err
		}
		log, err := os.OpenFile(filepath.Join(*state, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer log.Close()
		child := exec.Command(executable, "daemon", "--state", *state, "--bin-dir", *bin)
		child.Stdout = log
		child.Stderr = log
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err = child.Start(); err != nil {
			return err
		}
		child.Process.Release()
		until := time.Now().Add(45 * time.Second)
		for !ready() {
			if time.Now().After(until) {
				return errors.New("daemon did not become ready; inspect private daemon.log")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	window := exec.Command(filepath.Join(*bin, "torkitten-native"), socket)
	window.Stdout = os.Stdout
	window.Stderr = os.Stderr
	return window.Run()
}
