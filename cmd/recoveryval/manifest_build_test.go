package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildCompiledManifestStrictPairsOnly(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("paired.lsp", `(defun c:paired () (prompt "ok"))`)
	write("paired.fas", "stub")
	write("orphan_only_source.lsp", `(defun c:orphan () (prompt "skip"))`)
	write("compiled_only.fas", "stub")

	mf, stats, err := buildCompiledManifest(dir, dir, "strict", false)
	if err != nil {
		t.Fatalf("buildCompiledManifest: %v", err)
	}
	if len(mf.Cases) != 1 {
		t.Fatalf("expected 1 paired case, got %d", len(mf.Cases))
	}
	if got := filepath.Base(mf.Cases[0].SourcePath); got != "paired.lsp" {
		t.Fatalf("unexpected source path: %s", mf.Cases[0].SourcePath)
	}
	if stats.IncludedPairs != 1 {
		t.Fatalf("expected 1 included pair, got %d", stats.IncludedPairs)
	}
	if stats.SkippedLSPOnly != 1 {
		t.Fatalf("expected 1 skipped LSP-only case, got %d", stats.SkippedLSPOnly)
	}
	if stats.SkippedCompiledOnly != 1 {
		t.Fatalf("expected 1 skipped compiled-only case, got %d", stats.SkippedCompiledOnly)
	}
}
