// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The live Linux proof checks actual kernel listeners, not just torrc text.
func livePrivateListeners(t *testing.T, a *App) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for name, process := range a.processes {
		root := fmt.Sprintf("/proc/%d", process.cmd.Process.Pid)
		fds, err := os.ReadDir(filepath.Join(root, "fd"))
		if err != nil {
			t.Fatal("cannot inspect component listeners:", name, err)
		}
		sockets := map[string]bool{}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(root, "fd", fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				sockets[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
		for _, network := range []string{"tcp", "tcp6"} {
			data, err := os.ReadFile(filepath.Join(root, "net", network))
			if err != nil {
				t.Fatal("cannot inspect TCP listener table:", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 9 && fields[3] == "0A" && sockets[fields[9]] {
					t.Fatalf("component %s opened an unexpected TCP listener", name)
				}
			}
		}
	}
}
