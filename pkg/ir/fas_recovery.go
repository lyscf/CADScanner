package ir

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/debugutil"
)

// MergeRecoveredFAS merges conservative FAS-recovered structure into IR.
// It only imports recovered functions and call edges; it does not synthesize
// side effects from adapter heuristics.
func MergeRecoveredFAS(result *IRResult, fasMeta map[string]interface{}) {
	startAll := time.Now()
	var functionsTime time.Duration
	var callGraphTime time.Duration
	var bindingsTime time.Duration
	var behaviorsTime time.Duration
	var analysisTime time.Duration
	var summaryTime time.Duration
	if result == nil || len(fasMeta) == 0 {
		return
	}
	if result.Functions == nil {
		result.Functions = make(map[string]*IRFunction)
	}

	recoveredFunctions := coerceRecoveredFunctions(fasMeta["recovered_functions"])
	recoveredCallGraph := coerceRecoveredCallGraph(fasMeta["recovered_call_graph"])
	recoveredBindings := coerceRecoveredBindings(fasMeta["recovered_bindings"])
	recoveredBehaviors := coerceRecoveredBehaviors(fasMeta["recovered_behaviors"])
	functionsByOffset := make(map[int]string)
	lightweightMode := shouldUseRecoveredLightweightMode(recoveredFunctions, recoveredBindings)

	start := time.Now()
	for _, fn := range recoveredFunctions {
		irFunc := ensureRecoveredFunction(result.Functions, fn.Name, fn.NumArgs)
		functionsByOffset[fn.StartOffset] = fn.Name
		applyRecoveredFunctionMetadata(irFunc, fn)
		for i := 0; i < fn.VarsCount; i++ {
			irFunc.LocalVars[fmt.Sprintf("local_%d", i)] = true
		}
		applyRecoveredCFG(irFunc, fn)
		if len(fn.Calls) > 0 && len(recoveredCallGraph[fn.Name]) == 0 {
			recoveredCallGraph[fn.Name] = append([]string{}, fn.Calls...)
		}
		for _, callee := range fn.Calls {
			ensureRecoveredFunction(result.Functions, callee, 0)
			addRecoveredCall(irFunc, callee, false)
		}
		for _, callee := range fn.IndirectCalls {
			ensureRecoveredFunction(result.Functions, callee, 0)
			addRecoveredCall(irFunc, callee, true)
		}
	}
	functionsTime += time.Since(start)

	start = time.Now()
	for caller, callees := range recoveredCallGraph {
		callerFn := ensureRecoveredFunction(result.Functions, caller, 0)
		for _, callee := range callees {
			if callee == "" {
				continue
			}
			ensureRecoveredFunction(result.Functions, callee, 0)
			addRecoveredCall(callerFn, callee, false)
		}
	}
	callGraphTime += time.Since(start)
	start = time.Now()
	for _, binding := range recoveredBindings {
		addRecoveredBinding(result.Functions, functionsByOffset, binding)
	}
	bindingsTime += time.Since(start)
	start = time.Now()
	applyRecoveredBehaviors(result, recoveredBehaviors)
	behaviorsTime += time.Since(start)

	start = time.Now()
	result.CallGraph = BuildCallGraph(result.Functions)
	if lightweightMode {
		result.PropagationEvidence = &PropagationEvidence{}
		result.FunctionSummaries = buildRecoveredLightweightSummaries(result.Functions, result.CallGraph)
	} else {
		propExtractor := NewPropagationEvidenceExtractorWithCallGraph(result.Functions, result.Effects, result.CallGraph)
		result.PropagationEvidence = propExtractor.Extract()
		augmentPropagationEvidenceFromRecoveredBehaviors(result.PropagationEvidence, recoveredBehaviors)
		interAnalyzer := NewInterproceduralAnalyzer(result.Functions, result.CallGraph, result.PropagationEvidence)
		result.FunctionSummaries = interAnalyzer.Analyze()
	}
	analysisTime += time.Since(start)
	start = time.Now()
	if lightweightMode {
		augmentPropagationEvidenceFromRecoveredBehaviors(result.PropagationEvidence, recoveredBehaviors)
	}
	applyRecoveredBehaviorSummaries(result, recoveredBehaviors)
	applyRecoveredResourceSummary(result, fasMeta["resource_summary"])
	summaryTime += time.Since(start)
	if debugutil.TimingEnabled() && time.Since(startAll) > 500*time.Millisecond {
		fmt.Fprintf(os.Stderr, "  [IR-RECOVER] total=%v funcs=%v callgraph=%v bindings=%v behaviors=%v analysis=%v summary=%v lightweight=%t recovered=[f=%d b=%d bh=%d]\n",
			time.Since(startAll), functionsTime, callGraphTime, bindingsTime, behaviorsTime, analysisTime, summaryTime,
			lightweightMode,
			len(recoveredFunctions), len(recoveredBindings), len(recoveredBehaviors))
	}
}

func shouldUseRecoveredLightweightMode(functions []recoveredFASFunction, bindings []recoveredFASBinding) bool {
	return len(functions) >= 2000 || len(bindings) >= 5000
}

func buildRecoveredLightweightSummaries(functions map[string]*IRFunction, callGraph map[string][]string) map[string]*FunctionSummary {
	summaries := make(map[string]*FunctionSummary, len(functions))
	for funcName, fn := range functions {
		summary := &FunctionSummary{
			Name:              funcName,
			DirectEffects:     []EffectType{},
			InheritedEffects:  []EffectType{},
			Calls:             append([]string{}, callGraph[funcName]...),
			InferredBehaviors: make(map[string]bool),
		}
		if fn != nil {
			for _, block := range fn.Blocks {
				for _, effect := range block.Effects {
					summary.DirectEffects = append(summary.DirectEffects, effect.EffectType)
				}
			}
		}
		summaries[funcName] = summary
	}
	return summaries
}

// MergeRecoveredVLXEmbeddedFAS extracts per-record recovered FAS metadata from
// VLX adapter output and folds it into the IR the same way as a standalone FAS.
// The VLX adapter stores embedded record metadata using keys like
// "<record>_recovered_functions" and "<record>_recovered_behaviors".
func MergeRecoveredVLXEmbeddedFAS(result *IRResult, vlxMeta map[string]interface{}) {
	if result == nil || len(vlxMeta) == 0 {
		return
	}

	suffixes := []string{
		"_recovered_functions",
		"_recovered_bindings",
		"_recovered_behaviors",
	}

	grouped := make(map[string]map[string]interface{})
	for key, value := range vlxMeta {
		if strings.HasSuffix(key, "_resource_summary") {
			prefix := strings.TrimSuffix(key, "_resource_summary")
			if prefix != "" {
				meta := grouped[prefix]
				if meta == nil {
					meta = make(map[string]interface{})
					grouped[prefix] = meta
				}
				meta["resource_summary"] = value
			}
		}
		for _, suffix := range suffixes {
			if !strings.HasSuffix(key, suffix) {
				continue
			}
			prefix := strings.TrimSuffix(key, suffix)
			if prefix == "" {
				continue
			}
			meta := grouped[prefix]
			if meta == nil {
				meta = make(map[string]interface{})
				grouped[prefix] = meta
			}
			meta[strings.TrimPrefix(suffix, "_")] = value
			break
		}
	}
	if len(grouped) == 0 {
		return
	}

	prefixes := make([]string, 0, len(grouped))
	for prefix := range grouped {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		MergeRecoveredFAS(result, grouped[prefix])
	}
}

func applyRecoveredResourceSummary(result *IRResult, raw interface{}) {
	summary, ok := raw.(map[string]interface{})
	if !ok || result == nil {
		return
	}

	module := ensureRecoveredFunction(result.Functions, "recovered_fas_module", 0)

	add := func(effectType EffectType, target string, extra map[string]interface{}) {
		target = strings.TrimSpace(target)
		if target == "" {
			return
		}
		meta := map[string]interface{}{
			"recovered_from": "resource_summary",
		}
		for k, v := range extra {
			meta[k] = v
		}
		addRecoveredEffect(result, module, IREffect{
			EffectType: effectType,
			Target:     target,
			Source:     module.Name,
			Metadata:   meta,
			Line:       -1,
		})
	}

	urls := coerceStringSlice(summary["urls"])
	if len(urls) > 0 && len(urls) <= 8 {
		for _, url := range urls {
			add(NETWORK_CONNECT, url, map[string]interface{}{"summary_field": "urls"})
		}
	}

	for _, obj := range limitRecoveredItems(coerceStringSlice(summary["com_objects"]), 4) {
		add(COM_CREATE, obj, map[string]interface{}{"summary_field": "com_objects"})
	}
	for _, key := range limitRecoveredItems(coerceStringSlice(summary["registry_keys"]), 4) {
		add(REGISTRY_MODIFY, key, map[string]interface{}{"summary_field": "registry_keys"})
	}
	for _, cmd := range limitRecoveredItems(coerceStringSlice(summary["cmd_strings"]), 4) {
		add(PROCESS_CREATE, cmd, map[string]interface{}{"summary_field": "cmd_strings"})
	}

	paths := append([]string{}, coerceStringSlice(summary["file_paths"])...)
	paths = append(paths, coerceStringSlice(summary["paths"])...)
	paths = append(paths, coerceStringSlice(summary["filenames"])...)
	for _, path := range limitRecoveredItems(paths, 6) {
		lower := strings.ToLower(strings.TrimSpace(path))
		if lower == "" {
			continue
		}
		if isRecoveredStartupPath(lower) || isRecoveredExecutablePath(lower) {
			add(FILE_WRITE, path, map[string]interface{}{"summary_field": "file_paths"})
		}
	}
}

func limitRecoveredItems(items []string, max int) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, minInt(max, len(items)))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
		if len(out) >= max {
			break
		}
	}
	return out
}

func isRecoveredStartupPath(path string) bool {
	return strings.Contains(path, "acad.lsp") ||
		strings.Contains(path, "acaddoc.lsp") ||
		strings.Contains(path, "acad.fas") ||
		strings.Contains(path, "acad.vlx") ||
		strings.Contains(path, ".mnl") ||
		strings.Contains(path, "startup")
}

func isRecoveredExecutablePath(path string) bool {
	for _, ext := range []string{".exe", ".dll", ".scr", ".hta", ".js", ".vbs", ".wsf", ".bat", ".cmd", ".ps1"} {
		if strings.Contains(path, ext) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type recoveredFASFunction struct {
	Name          string
	NumArgs       int
	MaxArgs       int
	VarsCount     int
	Calls         []string
	IndirectCalls []string
	StartOffset   int
	EndOffset     int
	Kind          string
	Flags         int
	GC            bool
	IsLambda      bool
	BlockStarts   []int
	ControlEdges  []recoveredFASEdge
}

type recoveredFASBinding struct {
	Scope  string
	Name   string
	Value  string
	Kind   string
	Offset int
}

type recoveredFASEdge struct {
	From int
	To   int
	Kind string
}

type recoveredFASBehavior struct {
	Kind      string
	Category  string
	Summary   string
	Functions []string
	Evidence  []string
}

func ensureRecoveredFunction(functions map[string]*IRFunction, name string, numArgs int) *IRFunction {
	if name == "" {
		name = "anonymous_fas"
	}
	if fn, ok := functions[name]; ok {
		if len(fn.Params) == 0 && numArgs > 0 {
			fn.Params = makeRecoveredParams(numArgs)
		}
		if fn.LocalVars == nil {
			fn.LocalVars = make(map[string]bool)
		}
		if fn.Metadata == nil {
			fn.Metadata = make(map[string]interface{})
		}
		return fn
	}

	fn := &IRFunction{
		Name:       name,
		Params:     makeRecoveredParams(numArgs),
		Blocks:     make(map[string]*IRBasicBlock),
		EntryBlock: "recovered_entry",
		LocalVars:  make(map[string]bool),
		Metadata:   make(map[string]interface{}),
	}
	fn.AddBlock(&IRBasicBlock{
		ID:           "recovered_entry",
		Instructions: []IRInstruction{},
		Effects:      []IREffect{},
		Successors:   []string{},
		Predecessors: []string{},
	})
	functions[name] = fn
	return fn
}

func makeRecoveredParams(numArgs int) []string {
	if numArgs <= 0 {
		return []string{}
	}
	params := make([]string, 0, numArgs)
	for i := 0; i < numArgs; i++ {
		params = append(params, fmt.Sprintf("arg_%d", i))
	}
	return params
}

func applyRecoveredFunctionMetadata(fn *IRFunction, recovered recoveredFASFunction) {
	if fn == nil {
		return
	}
	if fn.Metadata == nil {
		fn.Metadata = make(map[string]interface{})
	}
	fn.Metadata["recovered_from"] = "fas"
	fn.Metadata["recovered_kind"] = recovered.Kind
	fn.Metadata["recovered_flags"] = recovered.Flags
	fn.Metadata["recovered_gc"] = recovered.GC
	fn.Metadata["recovered_is_lambda"] = recovered.IsLambda
	fn.Metadata["recovered_start_offset"] = recovered.StartOffset
	fn.Metadata["recovered_end_offset"] = recovered.EndOffset
	fn.Metadata["recovered_num_args"] = recovered.NumArgs
	fn.Metadata["recovered_max_args"] = recovered.MaxArgs
	fn.Metadata["recovered_vars_count"] = recovered.VarsCount
}

func applyRecoveredCFG(fn *IRFunction, recovered recoveredFASFunction) {
	if fn == nil {
		return
	}

	entryID := recoveredBlockID(recovered.StartOffset)
	entry := ensureRecoveredBlock(fn, entryID)
	if fn.EntryBlock != entryID {
		if oldEntry, ok := fn.Blocks[fn.EntryBlock]; ok && oldEntry != nil && oldEntry != entry {
			entry.Instructions = append(entry.Instructions, oldEntry.Instructions...)
			entry.Effects = append(entry.Effects, oldEntry.Effects...)
			for _, successor := range oldEntry.Successors {
				entry.Successors = appendUniqueString(entry.Successors, successor)
			}
			for _, predecessor := range oldEntry.Predecessors {
				entry.Predecessors = appendUniqueString(entry.Predecessors, predecessor)
			}
			delete(fn.Blocks, fn.EntryBlock)
		}
		fn.EntryBlock = entryID
	}

	for _, start := range recovered.BlockStarts {
		ensureRecoveredBlock(fn, recoveredBlockID(start))
	}

	for _, edge := range recovered.ControlEdges {
		fromID := recoveredBlockID(edge.From)
		toID := recoveredBlockID(edge.To)
		fromBlock := ensureRecoveredBlock(fn, fromID)
		toBlock := ensureRecoveredBlock(fn, toID)
		fromBlock.Successors = appendUniqueString(fromBlock.Successors, toID)
		toBlock.Predecessors = appendUniqueString(toBlock.Predecessors, fromID)
	}
}

func recoveredBlockID(offset int) string {
	return fmt.Sprintf("block_%04X", offset)
}

func ensureRecoveredBlock(fn *IRFunction, id string) *IRBasicBlock {
	if fn.Blocks == nil {
		fn.Blocks = make(map[string]*IRBasicBlock)
	}
	if block, ok := fn.Blocks[id]; ok {
		return block
	}
	block := &IRBasicBlock{
		ID:           id,
		Instructions: []IRInstruction{},
		Effects:      []IREffect{},
		Successors:   []string{},
		Predecessors: []string{},
	}
	fn.AddBlock(block)
	return block
}

func addRecoveredCall(fn *IRFunction, callee string, indirect bool) {
	if fn == nil || callee == "" {
		return
	}
	entry := fn.Blocks[fn.EntryBlock]
	if entry == nil {
		entry = &IRBasicBlock{
			ID:           fn.EntryBlock,
			Instructions: []IRInstruction{},
			Effects:      []IREffect{},
			Successors:   []string{},
			Predecessors: []string{},
		}
		fn.AddBlock(entry)
	}
	for i := range entry.Instructions {
		instr := &entry.Instructions[i]
		if instr.Opcode != CALL || len(instr.Operands) == 0 {
			continue
		}
		if existing, ok := instr.Operands[0].(string); ok && existing == callee {
			if indirect {
				if instr.Metadata == nil {
					instr.Metadata = map[string]interface{}{}
				}
				instr.Metadata["recovered_indirect"] = true
			}
			return
		}
	}
	metadata := map[string]interface{}{
		"recovered_from": "fas",
	}
	if indirect {
		metadata["recovered_indirect"] = true
	}
	entry.AddInstruction(IRInstruction{
		Opcode:   CALL,
		Operands: []interface{}{callee},
		Metadata: metadata,
	})
}

func addRecoveredBinding(functions map[string]*IRFunction, functionsByOffset map[int]string, binding recoveredFASBinding) {
	if binding.Name == "" {
		return
	}

	switch binding.Scope {
	case "global":
		toplevel := ensureRecoveredFunction(functions, "__toplevel__", 0)
		addRecoveredAssign(toplevel, binding.Name, binding.Value, binding)
	case "slot":
		funcName := functionsByOffset[binding.Offset]
		if funcName == "" {
			return
		}
		fn := ensureRecoveredFunction(functions, funcName, 0)
		fn.LocalVars[binding.Name] = true
		addRecoveredAssign(fn, binding.Name, binding.Value, binding)
	}
}

func addRecoveredAssign(fn *IRFunction, name, value string, binding recoveredFASBinding) {
	if fn == nil || name == "" {
		return
	}
	entry := fn.Blocks[fn.EntryBlock]
	if entry == nil {
		entry = &IRBasicBlock{
			ID:           fn.EntryBlock,
			Instructions: []IRInstruction{},
			Effects:      []IREffect{},
			Successors:   []string{},
			Predecessors: []string{},
		}
		fn.AddBlock(entry)
	}
	for _, instr := range entry.Instructions {
		if instr.Opcode != ASSIGN || instr.Result != name || len(instr.Operands) == 0 {
			continue
		}
		if existing, ok := instr.Operands[0].(string); ok && existing == value {
			return
		}
	}
	entry.AddInstruction(IRInstruction{
		Opcode:   ASSIGN,
		Result:   name,
		Operands: []interface{}{value},
		Metadata: map[string]interface{}{
			"recovered_from": "fas_binding",
			"binding_scope":  binding.Scope,
			"binding_kind":   binding.Kind,
			"binding_offset": binding.Offset,
		},
	})
}

func coerceRecoveredFunctions(raw interface{}) []recoveredFASFunction {
	switch v := raw.(type) {
	case []map[string]interface{}:
		out := make([]recoveredFASFunction, 0, len(v))
		for _, item := range v {
			out = append(out, recoveredFASFunction{
				Name:          coerceString(item["name"]),
				NumArgs:       coerceInt(item["num_args"]),
				MaxArgs:       coerceInt(item["max_args"]),
				VarsCount:     coerceInt(item["vars_count"]),
				Calls:         coerceStringSlice(item["calls"]),
				IndirectCalls: coerceStringSlice(item["indirect_calls"]),
				StartOffset:   coerceInt(item["start_offset"]),
				EndOffset:     coerceInt(item["end_offset"]),
				Kind:          coerceString(item["kind"]),
				Flags:         coerceInt(item["flags"]),
				GC:            coerceBool(item["gc"]),
				IsLambda:      coerceBool(item["is_lambda"]),
				BlockStarts:   coerceIntSlice(item["block_starts"]),
				ControlEdges:  coerceRecoveredEdges(item["control_edges"]),
			})
		}
		return out
	case []interface{}:
		out := make([]recoveredFASFunction, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, recoveredFASFunction{
				Name:          coerceString(m["name"]),
				NumArgs:       coerceInt(m["num_args"]),
				MaxArgs:       coerceInt(m["max_args"]),
				VarsCount:     coerceInt(m["vars_count"]),
				Calls:         coerceStringSlice(m["calls"]),
				IndirectCalls: coerceStringSlice(m["indirect_calls"]),
				StartOffset:   coerceInt(m["start_offset"]),
				EndOffset:     coerceInt(m["end_offset"]),
				Kind:          coerceString(m["kind"]),
				Flags:         coerceInt(m["flags"]),
				GC:            coerceBool(m["gc"]),
				IsLambda:      coerceBool(m["is_lambda"]),
				BlockStarts:   coerceIntSlice(m["block_starts"]),
				ControlEdges:  coerceRecoveredEdges(m["control_edges"]),
			})
		}
		return out
	default:
		return nil
	}
}

func coerceRecoveredBindings(raw interface{}) []recoveredFASBinding {
	switch v := raw.(type) {
	case []map[string]interface{}:
		out := make([]recoveredFASBinding, 0, len(v))
		for _, item := range v {
			out = append(out, recoveredFASBinding{
				Scope:  coerceString(item["scope"]),
				Name:   coerceString(item["name"]),
				Value:  coerceString(item["value"]),
				Kind:   coerceString(item["kind"]),
				Offset: coerceInt(item["offset"]),
			})
		}
		return out
	case []interface{}:
		out := make([]recoveredFASBinding, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, recoveredFASBinding{
				Scope:  coerceString(m["scope"]),
				Name:   coerceString(m["name"]),
				Value:  coerceString(m["value"]),
				Kind:   coerceString(m["kind"]),
				Offset: coerceInt(m["offset"]),
			})
		}
		return out
	default:
		return nil
	}
}

func coerceRecoveredBehaviors(raw interface{}) []recoveredFASBehavior {
	switch v := raw.(type) {
	case []map[string]interface{}:
		out := make([]recoveredFASBehavior, 0, len(v))
		for _, item := range v {
			out = append(out, recoveredFASBehavior{
				Kind:      coerceString(item["kind"]),
				Category:  coerceString(item["category"]),
				Summary:   coerceString(item["summary"]),
				Functions: coerceStringSlice(item["functions"]),
				Evidence:  coerceStringSlice(item["evidence"]),
			})
		}
		return out
	case []interface{}:
		out := make([]recoveredFASBehavior, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, recoveredFASBehavior{
				Kind:      coerceString(m["kind"]),
				Category:  coerceString(m["category"]),
				Summary:   coerceString(m["summary"]),
				Functions: coerceStringSlice(m["functions"]),
				Evidence:  coerceStringSlice(m["evidence"]),
			})
		}
		return out
	default:
		return nil
	}
}

func applyRecoveredBehaviors(result *IRResult, behaviors []recoveredFASBehavior) {
	if result == nil || len(behaviors) == 0 {
		return
	}
	for _, behavior := range behaviors {
		targets := behavior.Functions
		if len(targets) == 0 {
			targets = []string{"recovered_fas_module"}
		}
		for _, funcName := range targets {
			fn := ensureRecoveredFunction(result.Functions, funcName, 0)
			if fn.Metadata == nil {
				fn.Metadata = make(map[string]interface{})
			}
			entries, _ := fn.Metadata["recovered_behaviors"].([]map[string]interface{})
			entry := map[string]interface{}{
				"kind":     behavior.Kind,
				"category": behavior.Category,
				"summary":  behavior.Summary,
				"evidence": append([]string{}, behavior.Evidence...),
			}
			fn.Metadata["recovered_behaviors"] = append(entries, entry)
			injectRecoveredBehaviorEffects(result, fn, behavior)
		}
	}
}

func injectRecoveredBehaviorEffects(result *IRResult, fn *IRFunction, behavior recoveredFASBehavior) {
	if result == nil || fn == nil {
		return
	}
	evidenceText := strings.Join(behavior.Evidence, " | ")
	add := func(effectType EffectType, target string, extra map[string]interface{}) {
		if target == "" {
			return
		}
		metadata := map[string]interface{}{
			"recovered_from":     "fas_behavior",
			"recovered_behavior": behavior.Kind,
			"recovered_category": behavior.Category,
			"recovered_summary":  behavior.Summary,
			"recovered_evidence": append([]string{}, behavior.Evidence...),
		}
		for k, v := range extra {
			metadata[k] = v
		}
		effect := IREffect{
			EffectType: effectType,
			Target:     target,
			Source:     fn.Name,
			Metadata:   metadata,
			Line:       -1,
		}
		addRecoveredEffect(result, fn, effect)
	}

	switch behavior.Kind {
	case "wsh_warning_suppression":
		target := firstNonEmptyString(behavior.Evidence, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings`)
		add(REGISTRY_MODIFY, target, nil)
	case "script_payload_staging":
		add(COM_CREATE, "ADODB.Stream", map[string]interface{}{"com_role": "payload_sink"})
		add(COM_INVOKE, "ScriptControl", map[string]interface{}{"com_role": "script_engine"})
	case "wsf_payload_output":
		target := firstNonEmptyString(behavior.Evidence, ".WSF")
		add(FILE_WRITE, target, map[string]interface{}{"path_hint": "script_payload"})
	case "reactor_persistence":
		target := firstNonEmptyString(behavior.Evidence, "[VLR-DWG-Reactor")
		add(COM_INVOKE, target, map[string]interface{}{"entrypoint_hint": "reactor"})
	case "timestamped_artifact_naming":
		add(ENV_CHECK, "date", map[string]interface{}{"purpose": "artifact_naming", "evidence_text": evidenceText})
	case "file_search_copy_propagation":
		add(FILE_READ, "findfile", map[string]interface{}{"behavior_role": "search"})
		add(FILE_WRITE, "vl-file-copy", map[string]interface{}{"behavior_role": "copy"})
	}
}

func addRecoveredEffect(result *IRResult, fn *IRFunction, effect IREffect) {
	if result == nil || fn == nil || effect.EffectType == "" || effect.Target == "" {
		return
	}
	for _, existing := range result.Effects {
		if existing.EffectType == effect.EffectType && existing.Target == effect.Target && existing.Source == effect.Source {
			return
		}
	}
	entry := fn.Blocks[fn.EntryBlock]
	if entry == nil {
		entry = ensureRecoveredBlock(fn, "recovered_entry")
		fn.EntryBlock = entry.ID
	}
	for _, existing := range entry.Effects {
		if existing.EffectType == effect.EffectType && existing.Target == effect.Target && existing.Source == effect.Source {
			return
		}
	}
	entry.Effects = append(entry.Effects, effect)
	result.Effects = append(result.Effects, effect)
}

func augmentPropagationEvidenceFromRecoveredBehaviors(evidence *PropagationEvidence, behaviors []recoveredFASBehavior) {
	if evidence == nil || len(behaviors) == 0 {
		return
	}
	for _, behavior := range behaviors {
		evidence.Methods = appendUniqueString(evidence.Methods, behavior.Kind)
		switch behavior.Kind {
		case "reactor_persistence":
			for _, fn := range behavior.Functions {
				evidence.EntryPoints = appendUniqueString(evidence.EntryPoints, fn)
			}
			evidence.PropagationLikely = true
		case "file_search_copy_propagation":
			target := PropagationTarget{
				Path:            "vl-file-copy",
				PathType:        "data_file",
				Severity:        "medium",
				ResolutionLevel: "partial",
				Function:        firstNonEmptyString(behavior.Functions, "recovered_fas_module"),
				Line:            -1,
				TargetKind:      "code_load",
				Origin:          "recovered_behavior",
				FromEntry:       len(behavior.Functions) > 0,
			}
			evidence.Targets = appendPropagationTarget(evidence.Targets, target)
			evidence.CodeLoaderTargets = appendUniqueString(evidence.CodeLoaderTargets, target.Path)
			evidence.PropagationLikely = true
		case "wsf_payload_output":
			evidence.CodeLoaderTargets = appendUniqueString(evidence.CodeLoaderTargets, ".WSF")
		}
	}
	if len(evidence.CodeLoaderTargets) > 0 {
		evidence.PropagationLikely = true
	}
}

func appendPropagationTarget(dst []PropagationTarget, value PropagationTarget) []PropagationTarget {
	for _, existing := range dst {
		if existing.Path == value.Path && existing.Function == value.Function && existing.TargetKind == value.TargetKind {
			return dst
		}
	}
	return append(dst, value)
}

func applyRecoveredBehaviorSummaries(result *IRResult, behaviors []recoveredFASBehavior) {
	if result == nil || len(behaviors) == 0 {
		return
	}
	if result.FunctionSummaries == nil {
		result.FunctionSummaries = make(map[string]*FunctionSummary)
	}
	for _, behavior := range behaviors {
		targets := behavior.Functions
		if len(targets) == 0 {
			targets = []string{"recovered_fas_module"}
		}
		for _, funcName := range targets {
			summary := result.FunctionSummaries[funcName]
			if summary == nil {
				summary = &FunctionSummary{
					Name:              funcName,
					InferredBehaviors: make(map[string]bool),
				}
				result.FunctionSummaries[funcName] = summary
			}
			if summary.InferredBehaviors == nil {
				summary.InferredBehaviors = make(map[string]bool)
			}
			summary.InferredBehaviors[behavior.Kind] = true
		}
	}
}

func firstNonEmptyString(items []string, fallback string) string {
	for _, item := range items {
		if item != "" {
			return item
		}
	}
	return fallback
}

func coerceRecoveredCallGraph(raw interface{}) map[string][]string {
	out := make(map[string][]string)
	switch v := raw.(type) {
	case map[string][]string:
		for caller, callees := range v {
			out[caller] = append([]string{}, callees...)
		}
	case map[string]interface{}:
		for caller, callees := range v {
			out[caller] = coerceStringSlice(callees)
		}
	}
	return out
}

func coerceRecoveredEdges(raw interface{}) []recoveredFASEdge {
	switch v := raw.(type) {
	case []recoveredFASEdge:
		return append([]recoveredFASEdge{}, v...)
	case []interface{}:
		out := make([]recoveredFASEdge, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			edge := recoveredFASEdge{
				From: coerceInt(m["from"]),
				To:   coerceInt(m["to"]),
				Kind: coerceString(m["kind"]),
			}
			if edge.From == 0 {
				edge.From = coerceInt(m["From"])
			}
			if edge.To == 0 {
				edge.To = coerceInt(m["To"])
			}
			if edge.Kind == "" {
				edge.Kind = coerceString(m["Kind"])
			}
			out = append(out, edge)
		}
		return out
	default:
		rv := reflect.ValueOf(raw)
		if !rv.IsValid() || rv.Kind() != reflect.Slice {
			return nil
		}
		out := make([]recoveredFASEdge, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			item := rv.Index(i)
			if item.Kind() == reflect.Interface || item.Kind() == reflect.Pointer {
				item = item.Elem()
			}
			switch item.Kind() {
			case reflect.Struct:
				out = append(out, recoveredFASEdge{
					From: coerceInt(fieldValue(item, "From")),
					To:   coerceInt(fieldValue(item, "To")),
					Kind: coerceString(fieldValue(item, "Kind")),
				})
			case reflect.Map:
				out = append(out, recoveredFASEdge{
					From: firstNonZero(coerceInt(mapValue(item, "from")), coerceInt(mapValue(item, "From"))),
					To:   firstNonZero(coerceInt(mapValue(item, "to")), coerceInt(mapValue(item, "To"))),
					Kind: firstNonEmpty(coerceString(mapValue(item, "kind")), coerceString(mapValue(item, "Kind"))),
				})
			}
		}
		return out
	}
}

func coerceIntSlice(raw interface{}) []int {
	switch v := raw.(type) {
	case []int:
		return append([]int{}, v...)
	case []interface{}:
		out := make([]int, 0, len(v))
		for _, item := range v {
			out = append(out, coerceInt(item))
		}
		return out
	default:
		return nil
	}
}

func coerceStringSlice(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return append([]string{}, v...)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := coerceString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func coerceString(raw interface{}) string {
	if s, ok := raw.(string); ok {
		return s
	}
	return ""
}

func coerceInt(raw interface{}) int {
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		return 0
	}
}

func coerceBool(raw interface{}) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case float32:
		return v != 0
	default:
		return false
	}
}

func fieldValue(v reflect.Value, name string) interface{} {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	field := v.FieldByName(name)
	if !field.IsValid() {
		return nil
	}
	return field.Interface()
}

func mapValue(v reflect.Value, key string) interface{} {
	if !v.IsValid() || v.Kind() != reflect.Map {
		return nil
	}
	value := v.MapIndex(reflect.ValueOf(key))
	if !value.IsValid() {
		return nil
	}
	return value.Interface()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
