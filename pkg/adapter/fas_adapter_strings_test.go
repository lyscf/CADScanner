package adapter

import "testing"

func TestSplitResourceChunkPreservesPromptOptionLists(t *testing.T) {
	adapter := NewFASAdapter()

	got := adapter.splitResourceChunk("choose cut list option [stock/multiplier/layer/add/count/reset/done] <")
	if len(got) != 1 {
		t.Fatalf("expected prompt string to stay intact, got %#v", got)
	}
}

func TestSplitResourceChunkSplitsBracketResourceBoundary(t *testing.T) {
	adapter := NewFASAdapter()

	got := adapter.splitResourceChunk("prompt[S::STARTUP")
	if len(got) != 2 {
		t.Fatalf("expected boundary split, got %#v", got)
	}
	if got[0] != "prompt" || got[1] != "[S::STARTUP" {
		t.Fatalf("unexpected split result: %#v", got)
	}
}
