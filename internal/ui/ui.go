// Copyright 2026 The Torkitten Authors
// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

func Handler() http.Handler { sub, _ := fs.Sub(assets, "assets"); return http.FileServer(http.FS(sub)) }
