package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"time"
)

type Refusal string

func (r Refusal) Error() string { return string(r) }

const (
	InvalidKey          Refusal = "invalid-key"
	InvalidID           Refusal = "invalid-id"
	BodyTooLarge        Refusal = "body-too-large"
	InvalidTimestamp    Refusal = "invalid-timestamp"
	MalformedSignature  Refusal = "malformed-signature"
	UnsupportedVersion  Refusal = "unsupported-version"
	SignatureMismatch   Refusal = "signature-mismatch"
	StaleDelivery       Refusal = "stale-delivery"
	maxBodyBytes                = 1 << 20
	maxSignatureEntries         = 4
	deliveryTolerance           = 300 * time.Second
)

func Verify(keys [][]byte, id, timestamp, signature string, body []byte, now time.Time) error {
	if len(keys) < 1 || len(keys) > 2 {
		return InvalidKey
	}
	for _, key := range keys {
		if len(key) < 32 || len(key) > 64 || bytes.HasPrefix(key, []byte("whsec_")) {
			return InvalidKey
		}
	}
	if len(keys) == 2 && bytes.Equal(keys[0], keys[1]) {
		return InvalidKey
	}

	if len(id) == 0 || len(id) > 256 {
		return InvalidID
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '!' || id[i] > '~' || id[i] == '.' {
			return InvalidID
		}
	}
	if len(body) > maxBodyBytes {
		return BodyTooLarge
	}

	if len(timestamp) == 0 || len(timestamp) > 20 || (len(timestamp) > 1 && timestamp[0] == '0') {
		return InvalidTimestamp
	}
	for i := 0; i < len(timestamp); i++ {
		if timestamp[i] < '0' || timestamp[i] > '9' {
			return InvalidTimestamp
		}
	}
	seconds, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		return InvalidTimestamp
	}

	tags, err := signatureTags(signature)
	if err != nil {
		return err
	}
	for _, key := range keys {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + timestamp + "."))
		mac.Write(body)
		expected := mac.Sum(nil)
		for _, tag := range tags {
			if hmac.Equal(expected, tag) {
				if seconds > math.MaxInt64 {
					return StaleDelivery
				}
				// Bias signed Unix seconds so unsigned subtraction preserves their order.
				delivery := seconds + 1<<63
				receiver := uint64(now.Unix()) ^ (1 << 63)
				if delivery > receiver {
					if delivery-receiver > uint64(deliveryTolerance/time.Second) {
						return StaleDelivery
					}
				} else if receiver-delivery > uint64(deliveryTolerance/time.Second) ||
					(receiver-delivery == uint64(deliveryTolerance/time.Second) && now.Nanosecond() != 0) {
					return StaleDelivery
				}
				return nil
			}
		}
	}
	return SignatureMismatch
}

func signatureTags(signature string) ([][]byte, error) {
	entries := strings.SplitN(signature, " ", maxSignatureEntries+1)
	if len(entries) > maxSignatureEntries {
		return nil, MalformedSignature
	}
	var tags [][]byte
	for _, entry := range entries {
		version, value, found := strings.Cut(entry, ",")
		if !found || version == "" || value == "" {
			return nil, MalformedSignature
		}
		if version != "v1" {
			continue
		}
		if len(value) != base64.StdEncoding.EncodedLen(sha256.Size) {
			return nil, MalformedSignature
		}
		tag, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(tag) != sha256.Size {
			return nil, MalformedSignature
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		return nil, UnsupportedVersion
	}
	return tags, nil
}
