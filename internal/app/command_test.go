// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"reflect"
	"testing"
)

func TestCommandLiteralArguments(t *testing.T) {
	got, err := commandArgs(`/opt/llama-server -m '/models/large model.gguf' --prompt "a b" --empty '' '$HOME' "$(touch /tmp/no)" a\ b`)
	want := []string{"/opt/llama-server", "-m", "/models/large model.gguf", "--prompt", "a b", "--empty", "", "$HOME", "$(touch /tmp/no)", "a b"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("literal arguments changed: %q, %v", got, err)
	}
	for _, bad := range []string{"", "llama-server", "/bin/x 'unclosed", "/bin/x \\", "/bin/x\n/bin/y", "/bin/x\x00arg"} {
		if _, err = commandArgs(bad); err == nil {
			t.Fatalf("invalid command accepted: %q", bad)
		}
	}
}
