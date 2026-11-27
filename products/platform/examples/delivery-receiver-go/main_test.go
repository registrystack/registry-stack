package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testKey = []byte(strings.Repeat("k", 32))

func signedRequest(id, body string, now time.Time) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, testKey)
	mac.Write([]byte(id + "." + timestamp + "." + body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Webhook-Id", id)
	request.Header.Set("Webhook-Timestamp", timestamp)
	request.Header.Set("Webhook-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestRepeatedIDIsProcessedOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	processed := 0
	handler := newHandler([][]byte{testKey}, func() time.Time { return now }, func([]byte) { processed++ })
	for range 2 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, signedRequest("evt", `{"id":"evt"}`, now))
		if response.Code != http.StatusNoContent {
			t.Fatalf("got status %d, want 204", response.Code)
		}
		now = now.Add(time.Second)
	}
	if processed != 1 {
		t.Fatalf("processed %d times, want 1", processed)
	}
}

func TestAnIDThatDiffersFromTheBodyIsRefused(t *testing.T) {
	checkRefused(t, http.StatusBadRequest, `{"id":"other"}`, nil)
}

func TestAMissingOrRepeatedHeaderIsRefused(t *testing.T) {
	for _, header := range []string{"Webhook-Id", "Webhook-Timestamp", "Webhook-Signature", "Content-Type"} {
		t.Run(header+"/missing", func(t *testing.T) {
			checkRefused(t, http.StatusBadRequest, `{"id":"evt"}`, func(h http.Header) { h.Del(header) })
		})
		t.Run(header+"/repeated", func(t *testing.T) {
			checkRefused(t, http.StatusBadRequest, `{"id":"evt"}`, func(h http.Header) { h.Add(header, h.Get(header)) })
		})
	}
}

func TestABodyOverOneMebibyteIsRefused(t *testing.T) {
	checkRefused(t, http.StatusRequestEntityTooLarge, strings.Repeat(" ", 1048577), nil)
}

func TestAChangedBodyUnderTheSameIDIsRefused(t *testing.T) {
	now := time.Unix(1000, 0)
	processed := 0
	handler := newHandler([][]byte{testKey}, func() time.Time { return now }, func([]byte) { processed++ })
	for _, delivery := range []struct {
		body   string
		status int
	}{
		{`{"id":"evt","data":1}`, http.StatusNoContent},
		{`{"id":"evt","data":2}`, http.StatusBadRequest},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, signedRequest("evt", delivery.body, now))
		if response.Code != delivery.status {
			t.Errorf("got status %d, want %d", response.Code, delivery.status)
		}
	}
	if processed != 1 {
		t.Errorf("processed %d times, want 1", processed)
	}
}

func checkRefused(t *testing.T, status int, body string, changeHeader func(http.Header)) {
	t.Helper()
	now := time.Unix(1000, 0)
	request := signedRequest("evt", body, now)
	if changeHeader != nil {
		changeHeader(request.Header)
	}
	handler := newHandler([][]byte{testKey}, func() time.Time { return now }, func([]byte) {
		t.Error("refused delivery reached the process callback")
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Errorf("got status %d, want %d", response.Code, status)
	}
}

func TestASixtyFiveByteKeyFileEndingInANewlineIsRefusedNamingTheNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webhook.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := readKey("-key", path)
	if err == nil || !strings.Contains(err.Error(), "-key") ||
		!strings.Contains(err.Error(), "65") || !strings.Contains(err.Error(), "newline") {
		t.Fatalf("expected flag, length and trailing newline diagnostic, got %v", err)
	}
}
