package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectSkippedAndSorted(t *testing.T) {
	now := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	col := &Collectors{
		Git:       func() (any, error) { return map[string]any{"commit": "abc"}, nil },
		Artifacts: func() (any, error) { return map[string]any{"files": map[string]string{"a.txt": "d1"}}, nil },
		Depends:   nil, // not configured -> skipped
		Tests:     nil,
		Env:       func() (any, error) { return map[string]any{"os": "linux"}, nil },
	}
	res := Collect(col, now)
	if len(res) != 3 {
		t.Fatalf("expected 3 evidence nodes, got %d", len(res))
	}
	for _, r := range res {
		if r.Err != nil {
			t.Fatalf("unexpected error: %v", r.Err)
		}
		if r.Evidence.Digest == "" {
			t.Fatalf("node %s missing digest", r.Evidence.ID)
		}
		if r.Evidence.Timestamp == "" {
			t.Fatalf("node %s missing timestamp", r.Evidence.ID)
		}
	}
	// sorted by id: artifact, environment, git
	if res[0].Evidence.ID != "artifact" || res[1].Evidence.ID != "environment" || res[2].Evidence.ID != "git" {
		t.Fatalf("evidence not sorted: %v", []string{res[0].Evidence.ID, res[1].Evidence.ID, res[2].Evidence.ID})
	}
}

func TestCollectCapturesCollectorError(t *testing.T) {
	col := &Collectors{
		Git: func() (any, error) { return nil, os.ErrNotExist },
	}
	res := Collect(col, time.Now())
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].Err == nil {
		t.Fatalf("collector error must be surfaced")
	}
}

func TestDigestStable(t *testing.T) {
	a := Digests(`{"a":1}`)
	b := Digests(`{"a":1}`)
	c := Digests(`{"a":2}`)
	if a != b {
		t.Fatalf("digest must be deterministic")
	}
	if a == c {
		t.Fatalf("digest must change with payload")
	}
}

func TestHashFileAndBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("HashFile = %s, want %s", got, want)
	}
	if HashBytes([]byte("hello")) != want {
		t.Fatalf("HashBytes mismatch")
	}
}

func TestArtifactsCollectorMissingFileRecordsEmpty(t *testing.T) {
	dir := t.TempDir()
	fn := ArtifactsCollector(dir, []string{"missing.txt"})
	payload, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	files := payload.(map[string]any)["files"].(map[string]string)
	if files["missing.txt"] != "" {
		t.Fatalf("missing artifact must record empty digest, got %q", files["missing.txt"])
	}
}
