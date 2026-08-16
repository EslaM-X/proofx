// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package evidence

import (
	"encoding/json"
	"testing"
)

// FuzzCanonJSON feeds arbitrary bytes into canonical JSON parsing. The
// canonicalizer must never panic on malformed input.
func FuzzCanonJSON(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"b":[1,2,3]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`12345`))
	f.Add([]byte(`{`))
	f.Add([]byte(`]`))
	f.Add([]byte(`{"a":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return // invalid JSON is fine, must just not panic
		}
		if v == nil {
			return
		}
		if _, err := CanonJSON(v); err != nil {
			t.Fatalf("CanonJSON returned error for valid JSON: %v", err)
		}
	})
}

// FuzzDigestOf feeds arbitrary valid JSON values and requires that the digest
// is always 64 hex chars.
func FuzzDigestOf(f *testing.F) {
	f.Add(`{"files":{"a.txt":"d1"}}`)
	f.Add(`{"commit":"abc","branch":"main"}`)
	f.Fuzz(func(t *testing.T, s string) {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return
		}
		d, err := DigestOf(v)
		if err != nil {
			t.Fatalf("DigestOf error: %v", err)
		}
		if len(d) != 64 {
			t.Fatalf("digest must be 64 hex chars, got %q", d)
		}
	})
}

// TestCanonJSONDeterministic verifies the canonicalizer is byte-stable across
// repeated calls with the same logical object.
func TestCanonJSONDeterministic(t *testing.T) {
	a, err := CanonJSON(map[string]any{"b": 2, "a": map[string]any{"y": "v", "x": "u"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonJSON(map[string]any{"a": map[string]any{"x": "u", "y": "v"}, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("canonical JSON not deterministic across key order:\n%s\n%s", a, b)
	}
}
