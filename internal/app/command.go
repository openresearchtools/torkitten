// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"errors"
	"path/filepath"
	"strings"
)

// Split a direct launch command into words. Quotes and backslash group literal
// arguments; no shell, variables, globbing, pipes or substitutions are evaluated.
func commandArgs(line string) ([]string, error) {
	if len(line) > 32768 || strings.ContainsAny(line, "\x00\r\n") {
		return nil, errors.New("invalid launch command")
	}
	var args []string
	var word strings.Builder
	var quote rune
	started, escape := false, false
	for _, ch := range line {
		switch {
		case escape:
			word.WriteRune(ch)
			escape = false
		case ch == '\\' && quote != '\'':
			escape, started = true, true
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				word.WriteRune(ch)
			}
		case ch == '\'' || ch == '"':
			quote, started = ch, true
		case ch == ' ' || ch == '\t':
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(ch)
			started = true
		}
	}
	if quote != 0 || escape {
		return nil, errors.New("unclosed quote or escape in launch command")
	}
	if started {
		args = append(args, word.String())
	}
	if len(args) == 0 || len(args) > 256 || !filepath.IsAbs(args[0]) {
		return nil, errors.New("a launch command with an absolute executable is required")
	}
	return args, nil
}
