package ir

import "testing"

func TestMergeRecoveredFASInjectsRecoveredBehaviorsIntoIR(t *testing.T) {
	result := &IRResult{
		Functions: make(map[string]*IRFunction),
	}

	MergeRecoveredFAS(result, map[string]interface{}{
		"recovered_functions": []map[string]interface{}{
			{
				"name":         "stage-fn",
				"num_args":     0,
				"vars_count":   0,
				"start_offset": 4,
				"end_offset":   16,
			},
		},
		"recovered_behaviors": []map[string]interface{}{
			{
				"kind":      "script_payload_staging",
				"category":  "com",
				"summary":   "combines ScriptControl with ADODB.Stream; likely decodes and writes script payloads through COM",
				"functions": []string{"stage-fn"},
				"evidence":  []string{"ScriptControl", "ADODB.Stream"},
			},
			{
				"kind":      "wsh_warning_suppression",
				"category":  "registry",
				"summary":   "touches WSH settings registry key",
				"functions": []string{},
				"evidence":  []string{`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings`},
			},
		},
	})

	fn := result.Functions["stage-fn"]
	if fn == nil {
		t.Fatalf("expected recovered function to exist")
	}
	items, ok := fn.Metadata["recovered_behaviors"].([]map[string]interface{})
	if !ok || len(items) == 0 {
		t.Fatalf("expected recovered behaviors metadata on function, got %#v", fn.Metadata["recovered_behaviors"])
	}
	if result.FunctionSummaries["stage-fn"] == nil || !result.FunctionSummaries["stage-fn"].InferredBehaviors["script_payload_staging"] {
		t.Fatalf("expected recovered behavior to feed function summary, got %#v", result.FunctionSummaries["stage-fn"])
	}
	if result.Functions["recovered_fas_module"] == nil {
		t.Fatalf("expected module-level recovered behavior sink function")
	}
	if result.FunctionSummaries["recovered_fas_module"] == nil || !result.FunctionSummaries["recovered_fas_module"].InferredBehaviors["wsh_warning_suppression"] {
		t.Fatalf("expected module-level recovered behavior to feed summaries")
	}
	foundRegistry := false
	foundCOMCreate := false
	foundCOMInvoke := false
	for _, effect := range result.Effects {
		if effect.EffectType == REGISTRY_MODIFY && effect.Target == `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings` {
			foundRegistry = true
		}
		if effect.EffectType == COM_CREATE && effect.Target == "ADODB.Stream" {
			foundCOMCreate = true
		}
		if effect.EffectType == COM_INVOKE && effect.Target == "ScriptControl" {
			foundCOMInvoke = true
		}
	}
	if !foundRegistry || !foundCOMCreate || !foundCOMInvoke {
		t.Fatalf("expected recovered behaviors to emit IR effects, got %#v", result.Effects)
	}
	if result.PropagationEvidence == nil {
		t.Fatalf("expected propagation evidence to be rebuilt")
	}
	if len(result.PropagationEvidence.Methods) == 0 {
		t.Fatalf("expected propagation evidence methods from recovered behaviors")
	}
}

func TestMergeRecoveredVLXEmbeddedFASInjectsPrefixedRecoveredBehaviors(t *testing.T) {
	result := &IRResult{
		Functions: make(map[string]*IRFunction),
	}

	MergeRecoveredVLXEmbeddedFAS(result, map[string]interface{}{
		"MODULE_A_recovered_functions": []map[string]interface{}{
			{
				"name":         "module-a-fn",
				"num_args":     0,
				"vars_count":   0,
				"start_offset": 16,
				"end_offset":   32,
			},
		},
		"MODULE_A_recovered_behaviors": []map[string]interface{}{
			{
				"kind":      "script_payload_staging",
				"category":  "com",
				"summary":   "stages script payload via COM",
				"functions": []string{"module-a-fn"},
				"evidence":  []string{"ScriptControl", "ADODB.Stream"},
			},
		},
		"MODULE_B_recovered_behaviors": []map[string]interface{}{
			{
				"kind":      "wsh_warning_suppression",
				"category":  "registry",
				"summary":   "touches WSH settings registry key",
				"functions": []string{},
				"evidence":  []string{`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings`},
			},
		},
	})

	if result.Functions["module-a-fn"] == nil {
		t.Fatalf("expected prefixed recovered function to be merged")
	}

	foundRegistry := false
	foundCOMCreate := false
	for _, effect := range result.Effects {
		if effect.EffectType == REGISTRY_MODIFY && effect.Target == `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings` {
			foundRegistry = true
		}
		if effect.EffectType == COM_CREATE && effect.Target == "ADODB.Stream" {
			foundCOMCreate = true
		}
	}
	if !foundRegistry || !foundCOMCreate {
		t.Fatalf("expected prefixed VLX embedded FAS metadata to emit recovered effects, got %#v", result.Effects)
	}
}

func TestMergeRecoveredFASInjectsSparseResourceSummaryIOCs(t *testing.T) {
	result := &IRResult{
		Functions: make(map[string]*IRFunction),
	}

	MergeRecoveredFAS(result, map[string]interface{}{
		"resource_summary": map[string]interface{}{
			"urls":          []string{"https://api.web3forms.com/submit", "http://ip-api.com/line?fields=query,city,country"},
			"com_objects":   []string{"MSXML2.XMLHTTP.6.0"},
			"registry_keys": []string{`HKEY_CURRENT_USER\Software\Classes\CLSID\{B2AC-4109-A2}`},
			"cmd_strings":   []string{"cmd.exe /c powershell -enc ..."},
		},
	})

	var foundURL, foundCOM, foundRegistry, foundCmd bool
	for _, effect := range result.Effects {
		switch {
		case effect.EffectType == NETWORK_CONNECT && effect.Target == "https://api.web3forms.com/submit":
			foundURL = true
		case effect.EffectType == COM_CREATE && effect.Target == "MSXML2.XMLHTTP.6.0":
			foundCOM = true
		case effect.EffectType == REGISTRY_MODIFY && effect.Target == `HKEY_CURRENT_USER\Software\Classes\CLSID\{B2AC-4109-A2}`:
			foundRegistry = true
		case effect.EffectType == PROCESS_CREATE && effect.Target == "cmd.exe /c powershell -enc ...":
			foundCmd = true
		}
	}
	if !foundURL || !foundCOM || !foundRegistry || !foundCmd {
		t.Fatalf("expected sparse resource summary to emit recovered IOC effects, got %#v", result.Effects)
	}
}
