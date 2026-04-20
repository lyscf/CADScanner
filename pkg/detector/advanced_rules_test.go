package detector

import (
	"testing"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/normalizer"
)

func TestScriptControlDropperRuleMatchesRecoveredChain(t *testing.T) {
	rule := &ScriptControlDropperRule{}
	effects := []ir.IREffect{
		{EffectType: ir.COM_INVOKE, Target: "ScriptControl", Source: "recovered_fas_module"},
		{EffectType: ir.COM_CREATE, Target: "ADODB.Stream", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_WRITE, Target: "payload.WSF", Source: "recovered_fas_module"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected ScriptControl staging chain to match")
	}
}

func TestScriptControlDropperRuleDoesNotMatchBenignCOM(t *testing.T) {
	rule := &ScriptControlDropperRule{}
	effects := []ir.IREffect{
		{EffectType: ir.COM_CREATE, Target: "Scripting.FileSystemObject", Source: "vl-load-com"},
		{EffectType: ir.FILE_WRITE, Target: "report.csv", Source: "write-line"},
	}

	if rule.Match(effects) {
		t.Fatalf("expected benign COM/file activity to stay unmatched")
	}
}

func TestReactorPropagationRuleMatchesRecoveredChain(t *testing.T) {
	rule := &ReactorPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.COM_INVOKE, Target: "[VLR-DWG-Reactor", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_READ, Target: "findfile", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_WRITE, Target: "acaddoc.lsp", Source: "vl-file-copy"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected reactor propagation chain to match")
	}
}

func TestReactorPropagationRuleDoesNotMatchReactorAlone(t *testing.T) {
	rule := &ReactorPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.COM_INVOKE, Target: "[VLR-DWG-Reactor", Source: "setup-reactor"},
		{EffectType: ir.FILE_WRITE, Target: "log.txt", Source: "write-line"},
	}

	if rule.Match(effects) {
		t.Fatalf("expected standalone reactor usage to stay unmatched")
	}
}

func TestRecoveredFASPropagationRuleMatchesRecoveredPair(t *testing.T) {
	rule := &RecoveredFASPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.FILE_READ, Target: "findfile", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "recovered_fas_module"},
		{EffectType: ir.FILE_WRITE, Target: "acaddoc.lsp", Source: "vl-file-copy"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected recovered FAS propagation pair to match")
	}
}

func TestRecoveredFASPropagationRuleDoesNotMatchRegularCopy(t *testing.T) {
	rule := &RecoveredFASPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.FILE_READ, Target: "findfile", Source: "helper"},
		{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "helper"},
	}

	if rule.Match(effects) {
		t.Fatalf("expected non-recovered copy helper to stay unmatched")
	}
}

func TestObfuscatedNetworkStubRuleMatchesSparseBeacon(t *testing.T) {
	rule := &ObfuscatedNetworkStubRule{}
	effects := []ir.IREffect{
		{EffectType: ir.NETWORK_CONNECT, Target: "http://sl.szmr.org/cj/?msg_block_004D", Source: "recovered_fas_module"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected sparse obfuscated network stub to match")
	}
}

func TestObfuscatedNetworkStubRuleDoesNotMatchRegularSingleRequest(t *testing.T) {
	rule := &ObfuscatedNetworkStubRule{}
	effects := []ir.IREffect{
		{EffectType: ir.NETWORK_CONNECT, Target: "https://example.com/api", Source: "microsoft.xmlhttp"},
	}

	if rule.Match(effects) {
		t.Fatalf("expected ordinary single HTTP client usage to stay unmatched")
	}
}

func TestObfuscatedNetworkStubRuleMatchesRecoveredFunctionStyleSource(t *testing.T) {
	rule := &ObfuscatedNetworkStubRule{}
	effects := []ir.IREffect{
		{EffectType: ir.NETWORK_CONNECT, Target: "https://c2.example/ping?x=%41", Source: "fn_0042"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected low-fidelity recovered function source to match")
	}
}

func TestFindfileCopyPropagationRuleMatchesHelperPair(t *testing.T) {
	rule := &FindfileCopyPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.FILE_READ, Target: "findfile", Source: "helper-dwgprefix"},
		{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "helper-dwgprefix"},
		{EffectType: ir.FILE_WRITE, Target: "&{symbol afas 368 16", Source: "vl-file-copy"},
	}

	if !rule.Match(effects) {
		t.Fatalf("expected suspicious findfile+copy helper to match")
	}
}

func TestFindfileCopyPropagationRuleDoesNotMatchPlainLookup(t *testing.T) {
	rule := &FindfileCopyPropagationRule{}
	effects := []ir.IREffect{
		{EffectType: ir.FILE_READ, Target: "findfile", Source: "read-config"},
		{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "copy-config"},
	}

	if rule.Match(effects) {
		t.Fatalf("expected plain lookup/copy helper to stay unmatched")
	}
}

func TestRecoveredDestructiveStubMatchesRecoveredSourceText(t *testing.T) {
	cfg, _ := config.Load("")
	d := New(cfg)
	source := `;; sym: VL-FILE-DELETE
;; sym: OBJECTNAME
;; sym: vla-get-ModelSpace
;; sym: WCMATCH
;; str: [vla-Delete
;; str: *NUCLEAR*,*REACTOR*,*POWER*`

	got, err := d.Detect(&ir.IRResult{}, []*normalizer.NormalizedNode{}, &EvidenceContext{Source: source})
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	for _, rule := range got.MatchedRules {
		if rule.ID == "DESTRUCT_STUB_001" {
			return
		}
	}
	t.Fatalf("expected DESTRUCT_STUB_001 to match recovered source text, got %#v", got.MatchedRules)
}
