package llm

import "testing"

func TestExtractJSONObject(t *testing.T) {
	input := "preface```json\n{\"semantic_label\":\"MALICIOUS\",\"confidence\":0.99}\n```suffix"
	got := extractJSONObject(input)
	want := "{\"semantic_label\":\"MALICIOUS\",\"confidence\":0.99}"
	if got != want {
		t.Fatalf("extractJSONObject() = %q, want %q", got, want)
	}
}

