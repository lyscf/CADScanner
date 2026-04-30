package ir

import "testing"

func TestPropagationEvidenceKeepsRecoveredEffectFunctionMapping(t *testing.T) {
	readEffect := IREffect{
		EffectType: FILE_READ,
		Target:     "findfile",
		Source:     "reader_fn",
		Line:       -1,
	}
	writeEffect := IREffect{
		EffectType: FILE_WRITE,
		Target:     "vl-file-copy",
		Source:     "writer_fn",
		Line:       -1,
	}

	functions := map[string]*IRFunction{
		"reader_fn": {
			Name:       "reader_fn",
			Blocks:     map[string]*IRBasicBlock{"entry": {ID: "entry", Effects: []IREffect{readEffect}}},
			EntryBlock: "entry",
		},
		"writer_fn": {
			Name:       "writer_fn",
			Blocks:     map[string]*IRBasicBlock{"entry": {ID: "entry", Effects: []IREffect{writeEffect}}},
			EntryBlock: "entry",
		},
	}

	evidence := NewPropagationEvidenceExtractor(functions, []IREffect{readEffect, writeEffect}).Extract()
	if evidence == nil {
		t.Fatalf("expected propagation evidence")
	}

	assignments := make(map[string]string)
	for _, target := range evidence.Targets {
		assignments[target.Path] = target.Function
	}

	if assignments["findfile"] != "reader_fn" {
		t.Fatalf("expected findfile to map to reader_fn, got %q", assignments["findfile"])
	}
	if assignments["vl-file-copy"] != "writer_fn" {
		t.Fatalf("expected vl-file-copy to map to writer_fn, got %q", assignments["vl-file-copy"])
	}
}
