package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommittedVectors(t *testing.T) {
	data, err := os.ReadFile("../../../../crates/registry-platform-crypto/tests/fixtures/standard-webhooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, KeyHex, ID, Timestamp, Body, Signature, Expected, KeyPolicy string
		PreviousKeyHex                                                    *string
		Now                                                               int64
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 16 {
		t.Fatalf("got %d shared vectors, want at least 16", len(vectors))
	}
	hasPreviousKey := false
	for _, v := range vectors {
		if v.PreviousKeyHex != nil && *v.PreviousKeyHex != "" {
			hasPreviousKey = true
		}
		t.Run(v.Name, func(t *testing.T) {
			decode := func(s string) []byte {
				key, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return key
			}
			keys := [][]byte{decode(v.KeyHex)}
			if v.PreviousKeyHex != nil {
				keys = append(keys, decode(*v.PreviousKeyHex))
			}
			var want error
			if v.KeyPolicy == "below-minimum" {
				want = Refusal("invalid-key")
			} else if v.Expected != "accepted" {
				want = Refusal(v.Expected)
			}
			if got := Verify(keys, v.ID, v.Timestamp, v.Signature, []byte(v.Body), time.Unix(v.Now, 0)); got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
	if !hasPreviousKey {
		t.Error("shared vectors contain no previous-key vector")
	}
}

func TestAKeyOutsideThirtyTwoToSixtyFourBytesIsRefused(t *testing.T) {
	for _, keys := range [][][]byte{nil, {make([]byte, 31)}, {make([]byte, 65)}} {
		if got := Verify(keys, "event", "1", "", nil, time.Unix(1, 0)); got != Refusal("invalid-key") {
			t.Errorf("got %v, want invalid-key", got)
		}
	}
}

func TestDocsPageQuotesVerifyGo(t *testing.T) {
	page, err := os.ReadFile("../../../../docs/site/src/content/docs/reference/delivery-signing.mdx")
	if err != nil {
		t.Fatal(err)
	}
	const fence = "\n```go\n"
	if strings.Count(string(page), fence) != 1 {
		t.Fatal("expected exactly one Go fence")
	}
	_, rest, _ := strings.Cut(string(page), fence)
	quoted, _, ok := strings.Cut(rest, "\n```\n")
	if !ok {
		t.Fatal("Go fence is unclosed")
	}
	source, err := os.ReadFile("verify.go")
	if err != nil {
		t.Fatal(err)
	}
	if quoted+"\n" != strings.ReplaceAll(string(source), "\t", "    ") {
		t.Fatal("Go fence differs from verify.go")
	}
}
