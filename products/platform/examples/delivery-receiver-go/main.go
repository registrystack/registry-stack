package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func readKey(flagName, path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	if len(key) < 32 || len(key) > 64 {
		suffix := ""
		if bytes.HasSuffix(key, []byte("\n")) {
			suffix = " including a trailing newline"
		}
		return nil, fmt.Errorf("%s: invalid-key: got %d bytes%s, want 32 to 64", flagName, len(key), suffix)
	}
	if bytes.HasPrefix(key, []byte("whsec_")) {
		return nil, fmt.Errorf("%s: invalid-key: use exact key bytes instead of whsec_ text", flagName)
	}
	return key, nil
}

func newHandler(keys [][]byte, clock func() time.Time, process func([]byte)) http.Handler {
	const retention = 10 * time.Minute
	type delivery struct {
		expires time.Time
		digest  [sha256.Size]byte
	}
	// The handler admits one sender, so its map needs only the event id.
	seen := make(map[string]delivery)
	var mu sync.Mutex

	refuse := func(w http.ResponseWriter, status int, code error) {
		log.Printf("delivery refused: %s", code)
		w.WriteHeader(status)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			refuse(w, http.StatusBadRequest, Refusal("invalid-method"))
			return
		}
		id := r.Header.Values("Webhook-Id")
		timestamp := r.Header.Values("Webhook-Timestamp")
		signature := r.Header.Values("Webhook-Signature")
		contentType := r.Header.Values("Content-Type")
		if len(id) != 1 || len(timestamp) != 1 || len(signature) != 1 ||
			len(contentType) != 1 || contentType[0] != "application/json" {
			refuse(w, http.StatusBadRequest, Refusal("invalid-headers"))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			refuse(w, http.StatusRequestEntityTooLarge, BodyTooLarge)
			return
		}
		if err != nil {
			refuse(w, http.StatusBadRequest, Refusal("unreadable-body"))
			return
		}
		now := clock()
		if err := Verify(keys, id[0], timestamp[0], signature[0], body, now); err != nil {
			refuse(w, http.StatusBadRequest, err)
			return
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			refuse(w, http.StatusBadRequest, Refusal("invalid-json"))
			return
		}
		var eventID string
		if err := json.Unmarshal(fields["id"], &eventID); err != nil || eventID != id[0] {
			refuse(w, http.StatusBadRequest, Refusal("body-id-mismatch"))
			return
		}

		digest := sha256.Sum256(body)
		mu.Lock()
		for eventID, entry := range seen {
			if !now.Before(entry.expires) {
				delete(seen, eventID)
			}
		}
		entry, duplicate := seen[eventID]
		if duplicate && entry.digest != digest {
			mu.Unlock()
			refuse(w, http.StatusBadRequest, Refusal("duplicate-body-mismatch"))
			return
		}
		if !duplicate {
			seen[eventID] = delivery{expires: now.Add(retention), digest: digest}
			process(body)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8099", "HTTP listen address")
	keyPath := flag.String("key", "", "current signing key file")
	previousPath := flag.String("previous-key", "", "previous signing key file")
	flag.Parse()

	key, err := readKey("-key", *keyPath)
	if err != nil {
		log.Fatal(err)
	}
	keys := [][]byte{key}
	if *previousPath != "" {
		previous, err := readKey("-previous-key", *previousPath)
		if err != nil {
			log.Fatal(err)
		}
		if bytes.Equal(key, previous) {
			log.Fatal("-previous-key: invalid-key: key bytes must differ from -key")
		}
		keys = append(keys, previous)
	}

	mux := http.NewServeMux()
	mux.Handle("/events", newHandler(keys, time.Now, func([]byte) {
		log.Print("delivery accepted")
	}))
	server := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
