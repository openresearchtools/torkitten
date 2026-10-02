// Copyright 2026 The TorKitten Authors
// SPDX-License-Identifier: Apache-2.0
package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func scannerRequest(a *App, data, host, origin string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"data": data})
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/scan-qr", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func scannerQR(t *testing.T, text string) []byte {
	t.Helper()
	data, err := qrPNG(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func scannerImage(t *testing.T, im image.Image, format string) []byte {
	t.Helper()
	var out bytes.Buffer
	var err error
	if format == "jpeg" {
		err = jpeg.Encode(&out, im, &jpeg.Options{Quality: 95})
	} else {
		err = png.Encode(&out, im)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestScannerReturnsOnlyEncryptedBundleWithoutPassword(t *testing.T) {
	const secret = "private-onion-and-device-key"
	const password = "scanner-test-file-password"
	ciphertext, err := encrypt(map[string]string{"private": secret}, password)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	qr := scannerQR(t, "TK2:"+encoded)
	im, err := png.Decode(bytes.NewReader(qr))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{root: t.TempDir(), profiles: map[string]*Profile{}}
	for _, format := range []string{"png", "jpeg"} {
		t.Run(format, func(t *testing.T) {
			frame := scannerImage(t, im, format)
			w := scannerRequest(a, base64.StdEncoding.EncodeToString(frame), "app", "torkitten://app")
			if w.Code != http.StatusOK {
				t.Fatalf("scan returned status %d: %s", w.Code, w.Body.String())
			}
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result) != 2 || result["found"] != true || result["data"] != encoded {
				t.Fatal("scanner must return only found and unchanged encrypted bytes")
			}
			if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), password) {
				t.Fatal("scanner response contains plaintext credentials")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("scanner response must not be cached")
			}
		})
	}
	files, err := os.ReadDir(a.root)
	if err != nil || len(files) != 0 || len(a.profiles) != 0 {
		t.Fatal("scanning must not import profiles or persist frames or credentials")
	}
}

func TestScannerOrdinaryFramesAndOtherQRReturnNotFound(t *testing.T) {
	blank := image.NewGray(image.Rect(0, 0, 320, 240))
	for i := range blank.Pix {
		blank.Pix[i] = color.Gray{Y: 255}.Y
	}
	for name, frame := range map[string][]byte{
		"plain PNG":  scannerImage(t, blank, "png"),
		"plain JPEG": scannerImage(t, blank, "jpeg"),
		"other QR":   scannerQR(t, "https://example.invalid/unrelated"),
	} {
		t.Run(name, func(t *testing.T) {
			w := scannerRequest(&App{}, base64.StdEncoding.EncodeToString(frame), "app", "torkitten://app")
			if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"found":false}` {
				t.Fatalf("ordinary camera frame returned %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestScannerMalformedAndOversizedFramesAreExplicitErrors(t *testing.T) {
	oversized := scannerImage(t, image.NewGray(image.Rect(0, 0, 4097, 1)), "png")
	for name, encoded := range map[string]string{
		"invalid base64":       "%",
		"invalid image":        base64.StdEncoding.EncodeToString([]byte("not an image")),
		"oversized dimensions": base64.StdEncoding.EncodeToString(oversized),
		"oversized body":       strings.Repeat("A", MaxFile+1),
		"invalid QR base64":    base64.StdEncoding.EncodeToString(scannerQR(t, "TK2:%%%")),
		"plaintext QR":         base64.StdEncoding.EncodeToString(scannerQR(t, "TK2:"+base64.StdEncoding.EncodeToString([]byte(`{"private":"plaintext"}`)))),
	} {
		t.Run(name, func(t *testing.T) {
			w := scannerRequest(&App{}, encoded, "app", "torkitten://app")
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusBadRequest || len(result) != 1 || result["error"] == nil {
				t.Fatalf("malformed input must return a JSON error, got %d", w.Code)
			}
		})
	}
}

func TestScannerRequiresTrustedLocalUI(t *testing.T) {
	for _, tc := range []struct{ host, origin string }{
		{"app", ""},
		{"app", "https://example.invalid"},
		{"example.invalid", "torkitten://app"},
	} {
		w := scannerRequest(&App{}, "", tc.host, tc.origin)
		if w.Code != http.StatusForbidden {
			t.Fatalf("untrusted origin/host reached scanner: %d", w.Code)
		}
	}
}
