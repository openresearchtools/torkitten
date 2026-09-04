// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"net"
	"os"
	"torkitten/internal/control"
	"torkitten/internal/state"
)

func main() {
	if len(os.Args) != 4 || os.Args[1] != "owner" || os.Args[2] != "reset" || os.Args[3] != "RESET" {
		fatal("usage: torkittenctl owner reset RESET")
	}
	guard, err := net.Listen("tcp4", "127.0.0.1:12755")
	if err != nil {
		fatal("Torkitten must be stopped before owner recovery")
	}
	defer guard.Close()
	store, err := state.Open("/var/lib/torkitten/state.json")
	if err != nil {
		fatal("could not open Torkitten state")
	}
	if err = control.StageOwnerReset(store); err != nil {
		fatal("could not stage owner recovery")
	}
	fmt.Println("Owner recovery staged. Start Torkitten and complete setup at http://localhost:12755/setup")
}
func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
