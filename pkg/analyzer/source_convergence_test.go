package analyzer

import (
	"strings"
	"testing"
)

func TestConvergeSourceLimitsAdjacentDuplicateLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxAdjacentDuplicateSourceLines+3; i++ {
		b.WriteString("(setq flagx t)\n\n")
	}

	got := convergeSource(b.String())
	wantCount := maxAdjacentDuplicateSourceLines
	if count := strings.Count(got, "(setq flagx t)"); count != wantCount {
		t.Fatalf("line count = %d, want %d", count, wantCount)
	}
}

func TestConvergeSourcePreservesDistinctLines(t *testing.T) {
	source := "(setq a 1)\n\n(setq a 1)\n\n(load \"x\")\n\n(setq a 1)\n"
	got := convergeSource(source)
	if strings.Count(got, "(setq a 1)") != 3 {
		t.Fatalf("setq occurrences = %d, want 3", strings.Count(got, "(setq a 1)"))
	}
	if !strings.Contains(got, "(load \"x\")") {
		t.Fatal("distinct line was removed")
	}
}

func TestConvergeSourceLimitsTotalDuplicateLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxTotalDuplicateSourceLines+10; i++ {
		b.WriteString("(setq flagx t)\n")
		b.WriteString("(load \"x\")\n")
	}

	got := convergeSource(b.String())
	if count := strings.Count(got, "(setq flagx t)"); count != maxTotalDuplicateSourceLines {
		t.Fatalf("global duplicate count = %d, want %d", count, maxTotalDuplicateSourceLines)
	}
	if count := strings.Count(got, "(load \"x\")"); count != maxTotalDuplicateSourceLines {
		t.Fatalf("global duplicate count = %d, want %d", count, maxTotalDuplicateSourceLines)
	}
}
