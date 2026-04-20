package ir

import (
	"testing"

	"github.com/evilcad/cadscanner/pkg/normalizer"
)

func TestEvaluateStringExpressionCacheRespectsValueVersion(t *testing.T) {
	b := NewBuilder()
	expr := &normalizer.NormalizedNode{
		FunctionName: "strcat",
		Arguments:    []interface{}{"prefix-", "x"},
	}

	b.setTrackedValue("x", "one")
	if got := b.evaluateStringExpression(expr); got != "prefix-one" {
		t.Fatalf("first evaluation = %q, want %q", got, "prefix-one")
	}

	b.setTrackedValue("x", "two")
	if got := b.evaluateStringExpression(expr); got != "prefix-two" {
		t.Fatalf("second evaluation = %q, want %q", got, "prefix-two")
	}
}

func TestCleanTargetUsesResolvedValue(t *testing.T) {
	b := NewBuilder()
	b.setTrackedValue("payload", ` " C:\temp\evil.lsp " `)

	got1 := b.cleanTarget("payload")
	got2 := b.cleanTarget("payload")

	if got1 != `C:\temp\evil.lsp` {
		t.Fatalf("cleanTarget first call = %q, want %q", got1, `C:\temp\evil.lsp`)
	}
	if got2 != got1 {
		t.Fatalf("cleanTarget second call = %q, want %q", got2, got1)
	}
}

func TestBuildTracksOpenHandleForWriteLine(t *testing.T) {
	b := NewBuilder()
	nodes := []*normalizer.NormalizedNode{
		{
			Operation:    normalizer.SETQ,
			FunctionName: "setq",
			Arguments: []interface{}{
				"f",
				&normalizer.NormalizedNode{
					Operation:    normalizer.FILE_OPEN,
					FunctionName: "open",
					Arguments:    []interface{}{`c:\boot.dat`, "w"},
				},
			},
		},
		{
			Operation:    normalizer.FILE_WRITE,
			FunctionName: "write-line",
			Arguments:    []interface{}{"[dang]", "f"},
		},
	}

	result, err := b.Build(nodes)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(result.Effects) < 2 {
		t.Fatalf("effects len = %d, want at least 2", len(result.Effects))
	}

	foundBootDat := false
	for _, effect := range result.Effects {
		if effect.EffectType == FILE_WRITE && effect.Target == `c:\boot.dat` {
			foundBootDat = true
			break
		}
	}
	if !foundBootDat {
		t.Fatalf("expected file write effect targeting %q, got %#v", `c:\boot.dat`, result.Effects)
	}
}

func TestInferUnknownEffectsDoesNotTreatReferenceURLTableAsNetwork(t *testing.T) {
	b := NewBuilder()
	node := &normalizer.NormalizedNode{
		Operation:    normalizer.UNKNOWN,
		FunctionName: "fn@219DC",
		Arguments: []interface{}{
			"http://epsg.io/32610",
			"SIRGAS 2000 / UTM zone 22N",
		},
	}

	b.inferUnknownEffects(node)

	for _, effect := range b.globalEffects {
		if effect.EffectType == NETWORK_CONNECT {
			t.Fatalf("unexpected network effect inferred from reference URL table: %#v", effect)
		}
	}
}

func TestInferUnknownEffectsKeepsSuspiciousUnknownURL(t *testing.T) {
	b := NewBuilder()
	node := &normalizer.NormalizedNode{
		Operation:    normalizer.UNKNOWN,
		FunctionName: "fn_0042",
		Arguments: []interface{}{
			"http://sl.szmr.org/cj/?msg_block_004D",
		},
	}

	b.inferUnknownEffects(node)

	found := false
	for _, effect := range b.globalEffects {
		if effect.EffectType == NETWORK_CONNECT && effect.Target == "http://sl.szmr.org/cj/?msg_block_004D" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected suspicious unknown URL to still infer network effect, got %#v", b.globalEffects)
	}
}

func TestInferUnknownEffectsTreatsURLToFileAsWrite(t *testing.T) {
	b := NewBuilder()
	node := &normalizer.NormalizedNode{
		Operation:    normalizer.UNKNOWN,
		FunctionName: "~",
		Arguments: []interface{}{
			"http://evil.example/payload",
			".dcl",
		},
	}

	b.inferUnknownEffects(node)

	found := false
	for _, effect := range b.globalEffects {
		if effect.EffectType == FILE_WRITE && effect.Target == ".dcl" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected url-to-file wrapper to keep inferred file write, got %#v", b.globalEffects)
	}
}
