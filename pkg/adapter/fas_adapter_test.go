package adapter

import "testing"

func TestFASAdapterFallbackExposesParseState(t *testing.T) {
	adapter := NewFASAdapter()

	result, err := adapter.Adapt([]byte("FAS4-FILE ; Do not change it!"))
	if err != nil {
		t.Fatalf("expected fallback adaptation, got error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected adaptation result")
	}
	if !result.UsedFallback {
		t.Fatalf("expected UsedFallback=true")
	}
	if result.ParseError == nil {
		t.Fatalf("expected ParseError to preserve the original parse failure")
	}
	if result.Meta["parse_fallback"] != true {
		t.Fatalf("expected parse_fallback metadata, got %#v", result.Meta["parse_fallback"])
	}
	if result.Source == "" {
		t.Fatalf("expected fallback pseudo source to be populated")
	}
}

func TestFASAdapterAcceptsHeaderTextVariants(t *testing.T) {
	adapter := NewFASAdapter()

	result, err := adapter.Adapt([]byte("\r\n FAS4-FILE ; Always change it!\r\n"))
	if err != nil {
		t.Fatalf("expected variant header to reach fallback adaptation, got error: %v", err)
	}
	if result == nil {
		t.Fatalf("expected adaptation result")
	}
	if !result.UsedFallback {
		t.Fatalf("expected UsedFallback=true for truncated variant header")
	}
}
