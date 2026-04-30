package scoring

import (
	"testing"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/ir"
)

func TestScriptControlRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "SCRIPTCTRL_001", Name: "ScriptControl Payload Stager", Severity: 0.97},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.COM_INVOKE, Target: "ScriptControl", Source: "recovered_fas_module"},
			{EffectType: ir.COM_CREATE, Target: "ADODB.Stream", Source: "recovered_fas_module"},
			{EffectType: ir.FILE_WRITE, Target: "payload.WSF", Source: "recovered_fas_module"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.76 {
		t.Fatalf("expected ScriptControl floor to apply, got %.4f", result.RiskScore)
	}
}

func TestReactorPropagationRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "REACT_PROP_001", Name: "Reactor-Driven Propagation", Severity: 0.96},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.COM_INVOKE, Target: "[VLR-DWG-Reactor", Source: "recovered_fas_module"},
			{EffectType: ir.FILE_READ, Target: "findfile", Source: "recovered_fas_module"},
			{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "recovered_fas_module"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.74 {
		t.Fatalf("expected reactor propagation floor to apply, got %.4f", result.RiskScore)
	}
}

func TestRecoveredFASPropagationRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "REC_FAS_PROP_001", Name: "Recovered FAS Propagation Stub", Severity: 0.91},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.FILE_READ, Target: "findfile", Source: "recovered_fas_module"},
			{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "recovered_fas_module"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.70 {
		t.Fatalf("expected recovered FAS propagation floor to apply, got %.4f", result.RiskScore)
	}
}

func TestObfuscatedNetworkStubRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "NET_STUB_001", Name: "Obfuscated Network Stub", Severity: 0.90},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.NETWORK_CONNECT, Target: "http://sl.szmr.org/cj/?msg_block_004D", Source: "recovered_fas_module"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.68 {
		t.Fatalf("expected obfuscated network stub floor to apply, got %.4f", result.RiskScore)
	}
}

func TestFindfileCopyRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "FINDCOPY_001", Name: "Findfile Copy Propagation", Severity: 0.89},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.FILE_READ, Target: "findfile", Source: "helper-dwgprefix"},
			{EffectType: ir.FILE_WRITE, Target: "vl-file-copy", Source: "helper-dwgprefix"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.68 {
		t.Fatalf("expected findfile copy floor to apply, got %.4f", result.RiskScore)
	}
}

func TestEmbeddedStartupCopyStringRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "STARTUP_COPY_STR_001", Name: "Embedded Startup Copy String", Severity: 0.90},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.66 {
		t.Fatalf("expected embedded startup copy string floor to apply, got %.4f", result.RiskScore)
	}
}

func TestBootDatChainRuleAppliesRiskFloor(t *testing.T) {
	cfg, _ := config.Load("")
	s := New(cfg)

	detectResult := &detector.DetectResult{
		MatchedRules: []detector.MatchedRule{
			{ID: "BOOTDAT_CHAIN_001", Name: "Boot.dat Startup Chain", Severity: 0.88},
		},
		AttackResult: &detector.AttackResult{},
	}
	irResult := &ir.IRResult{
		Effects: []ir.IREffect{
			{EffectType: ir.FILE_WRITE, Target: `c:\boot.dat`, Source: "open"},
		},
	}

	result := s.Score(detectResult, irResult, nil, nil, nil)
	if result.RiskScore < 0.60 {
		t.Fatalf("expected boot.dat startup-chain floor to apply, got %.4f", result.RiskScore)
	}
}
