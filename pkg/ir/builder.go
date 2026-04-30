package ir

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/normalizer"
)

// IRBuilder builds the intermediate representation
type IRBuilder struct {
	functions         map[string]*IRFunction
	globalEffects     []IREffect
	effectSeen        map[string]struct{}
	ssaCounter        int
	blockCounter      int
	currentFunction   *IRFunction
	currentBlock      *IRBasicBlock
	varVersions       map[string]int
	symbolTable       map[string]string
	valueTable        map[string]string
	valueVersion      int
	evalStringCache   map[*normalizer.NormalizedNode]cachedStringEval
	cleanStringCache  map[string]string
	typeInference     *TypeInference
	maxLiteralEvalLen int
}

type cachedStringEval struct {
	version int
	value   string
}

const (
	defaultMaxLiteralEvalLen = 4096
	maxGlobalEffects         = 1000
)

// IRResult represents the IR build result
type IRResult struct {
	Functions           map[string]*IRFunction
	Effects             []IREffect
	LiftedEffects       []LiftedEffect
	PropagationEvidence *PropagationEvidence
	FunctionSummaries   map[string]*FunctionSummary
	CallGraph           map[string][]string
	SemanticTags        map[string][]SemanticTag
	EnvChecks           []string
}

// BuildCallGraph computes the user-defined call graph from IR functions.
// This is the single canonical implementation; all consumers should use
// the CallGraph stored in IRResult rather than recomputing their own.
func BuildCallGraph(functions map[string]*IRFunction) map[string][]string {
	callGraph := make(map[string][]string)
	aliasMaps := buildAliasMaps(functions)
	for funcName, fn := range functions {
		calls := []string{}
		callSet := make(map[string]struct{})
		aliasMap := aliasMaps[funcName]
		resolutionCache := make(map[string][]string)
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Opcode == CALL && len(instr.Operands) > 0 {
					if callee, ok := instr.Operands[0].(string); ok {
						resolvedTargets, ok := resolutionCache[callee]
						if !ok {
							resolvedTargets = resolveCallTargetsWithAliasMap(functions, callee, aliasMap)
							resolutionCache[callee] = resolvedTargets
						}
						for _, resolved := range resolvedTargets {
							if _, exists := callSet[resolved]; exists {
								continue
							}
							callSet[resolved] = struct{}{}
							calls = append(calls, resolved)
						}
					}
				}
			}
		}
		callGraph[funcName] = calls
	}
	return callGraph
}

// NewBuilder creates a new IR builder
func NewBuilder() *IRBuilder {
	return &IRBuilder{
		functions:         make(map[string]*IRFunction),
		globalEffects:     make([]IREffect, 0),
		effectSeen:        make(map[string]struct{}),
		ssaCounter:        0,
		blockCounter:      0,
		varVersions:       make(map[string]int),
		symbolTable:       make(map[string]string),
		valueTable:        make(map[string]string),
		valueVersion:      0,
		evalStringCache:   make(map[*normalizer.NormalizedNode]cachedStringEval),
		cleanStringCache:  make(map[string]string),
		typeInference:     NewTypeInference(),
		maxLiteralEvalLen: defaultMaxLiteralEvalLen,
	}
}

// Reset clears all mutable state so the builder can be safely reused.
func (b *IRBuilder) Reset() {
	b.functions = make(map[string]*IRFunction)
	b.globalEffects = make([]IREffect, 0)
	b.effectSeen = make(map[string]struct{})
	b.ssaCounter = 0
	b.blockCounter = 0
	b.currentFunction = nil
	b.currentBlock = nil
	b.varVersions = make(map[string]int)
	b.symbolTable = make(map[string]string)
	b.valueTable = make(map[string]string)
	b.valueVersion = 0
	b.evalStringCache = make(map[*normalizer.NormalizedNode]cachedStringEval)
	b.cleanStringCache = make(map[string]string)
	b.typeInference = NewTypeInference()
}

// Build builds the IR from normalized AST
func (b *IRBuilder) Build(normalized []*normalizer.NormalizedNode) (*IRResult, error) {
	// Reset state to prevent pollution across calls
	b.Reset()

	// Build IR from normalized nodes
	start := time.Now()
	functions, err := b.buildFromNormalized(normalized)
	if err != nil {
		return nil, err
	}
	buildTime := time.Since(start)

	// Apply constant folding pass
	start = time.Now()
	folder := NewConstantFolder()
	functions = folder.Fold(functions)
	foldTime := time.Since(start)

	// Apply pruning pass
	start = time.Now()
	pruner := NewPruner()
	functions = pruner.Prune(functions)
	pruneTime := time.Since(start)

	// Apply effect lifting pass
	start = time.Now()
	lifter := NewEffectLifter(folder, b.symbolTable)
	liftedEffects := lifter.Lift(b.globalEffects)
	liftTime := time.Since(start)

	// Build call graph once — single source of truth
	start = time.Now()
	callGraph := BuildCallGraph(functions)
	cgTime := time.Since(start)

	// Extract propagation evidence
	start = time.Now()
	propExtractor := NewPropagationEvidenceExtractorWithCallGraph(functions, b.globalEffects, callGraph)
	propEvidence := propExtractor.Extract()
	propTime := time.Since(start)

	// Apply interprocedural analysis (receives pre-computed call graph)
	start = time.Now()
	interAnalyzer := NewInterproceduralAnalyzer(functions, callGraph, propEvidence)
	functionSummaries := interAnalyzer.Analyze()
	interTime := time.Since(start)

	// Generate semantic tags from effects (single source of truth for context scoring)
	start = time.Now()
	tagger := NewSemanticTagger()
	semanticTags := tagger.TagEffects(b.globalEffects)
	tagTime := time.Since(start)

	// Extract environment check targets from effects
	envChecks := make([]string, 0)
	for _, effect := range b.globalEffects {
		if effect.EffectType == ENV_CHECK {
			envChecks = append(envChecks, effect.Target)
		}
	}

	// Print timing breakdown if slow (>500ms total or any step >200ms)
	totalTime := buildTime + foldTime + pruneTime + liftTime + propTime + cgTime + interTime + tagTime
	if debugutil.TimingEnabled() && (totalTime > 500*time.Millisecond || buildTime > 200*time.Millisecond || interTime > 200*time.Millisecond) {
		fmt.Fprintf(os.Stderr, "    [IR-BUILD] total=%v build=%v fold=%v prune=%v lift=%v prop=%v cg=%v inter=%v tag=%v (funcs=%d effects=%d)\n",
			totalTime, buildTime, foldTime, pruneTime, liftTime, propTime, cgTime, interTime, tagTime,
			len(functions), len(b.globalEffects))
	}

	result := &IRResult{
		Functions:           functions,
		Effects:             b.globalEffects,
		LiftedEffects:       liftedEffects,
		PropagationEvidence: propEvidence,
		FunctionSummaries:   functionSummaries,
		CallGraph:           callGraph,
		SemanticTags:        semanticTags,
		EnvChecks:           envChecks,
	}

	return result, nil
}

// buildFromNormalized builds IR from normalized AST nodes
func (b *IRBuilder) buildFromNormalized(normalized []*normalizer.NormalizedNode) (map[string]*IRFunction, error) {

	// Check if there are any top-level non-defun nodes
	hasToplevel := false
	for _, n := range normalized {
		if n.Operation != normalizer.DEFUN {
			hasToplevel = true
			break
		}
	}

	if hasToplevel {
		tlFunc := &IRFunction{
			Name:       "__toplevel__",
			Params:     []string{},
			Blocks:     make(map[string]*IRBasicBlock),
			EntryBlock: "",
			LocalVars:  make(map[string]bool),
			Metadata:   make(map[string]interface{}),
		}
		tlBlock := &IRBasicBlock{
			ID:           b.newBlockID(),
			Instructions: make([]IRInstruction, 0),
			Effects:      make([]IREffect, 0),
			Successors:   make([]string, 0),
			Predecessors: make([]string, 0),
		}
		tlFunc.AddBlock(tlBlock)
		b.functions["__toplevel__"] = tlFunc
		b.currentFunction = tlFunc
		b.currentBlock = tlBlock
	}

	for _, node := range normalized {
		if node.Operation == normalizer.DEFUN {
			// defun resets current context internally and restores it after
			b.currentFunction = nil
			b.currentBlock = nil
			b.processNode(node)
			// Restore toplevel context after defun
			if _, ok := b.functions["__toplevel__"]; ok {
				b.currentFunction = b.functions["__toplevel__"]
				for _, block := range b.currentFunction.Blocks {
					b.currentBlock = block
					break
				}
			}
		} else {
			b.processNode(node)
		}
	}

	// Remove __toplevel__ if it ended up empty
	if tl, ok := b.functions["__toplevel__"]; ok {
		allEmpty := true
		for _, block := range tl.Blocks {
			if len(block.Instructions) > 0 || len(block.Effects) > 0 {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			delete(b.functions, "__toplevel__")
		}
	}

	return b.functions, nil
}

// processNode processes a normalized node
func (b *IRBuilder) processNode(node *normalizer.NormalizedNode) string {
	if node == nil {
		return ""
	}
	switch node.Operation {
	case normalizer.DEFUN:
		return b.processDefun(node)
	case normalizer.SETQ:
		return b.processSetq(node)
	case normalizer.IF:
		return b.processIf(node)
	case normalizer.WHILE:
		return b.processWhile(node)
	default:
		return b.processCall(node)
	}
}

// processDefun processes a function definition
func (b *IRBuilder) processDefun(node *normalizer.NormalizedNode) string {
	prevFunction := b.currentFunction
	prevBlock := b.currentBlock

	funcName := "anonymous"
	if len(node.Arguments) > 0 {
		if name, ok := node.Arguments[0].(string); ok {
			funcName = name
		}
	}

	params := []string{}
	// Extract parameters from metadata or arguments
	if len(node.Arguments) > 1 {
		if paramList, ok := node.Arguments[1].([]interface{}); ok {
			for _, p := range paramList {
				if str, ok := p.(string); ok && str != "/" {
					params = append(params, str)
				}
			}
		}
	}

	// Create function
	irFunc := &IRFunction{
		Name:       funcName,
		Params:     params,
		Blocks:     make(map[string]*IRBasicBlock),
		EntryBlock: "",
		LocalVars:  make(map[string]bool),
		Metadata:   make(map[string]interface{}),
	}
	b.functions[funcName] = irFunc
	b.currentFunction = irFunc

	// Create entry block
	entry := &IRBasicBlock{
		ID:           b.newBlockID(),
		Instructions: make([]IRInstruction, 0),
		Effects:      make([]IREffect, 0),
		Successors:   make([]string, 0),
		Predecessors: make([]string, 0),
	}
	irFunc.AddBlock(entry)
	b.currentBlock = entry

	// Process function body (arguments after params)
	for i := 2; i < len(node.Arguments); i++ {
		if childNode, ok := node.Arguments[i].(*normalizer.NormalizedNode); ok {
			b.processNode(childNode)
		}
	}

	// Restore previous context
	b.currentFunction = prevFunction
	b.currentBlock = prevBlock

	return funcName
}

// processSetq processes variable assignment
func (b *IRBuilder) processSetq(node *normalizer.NormalizedNode) string {
	if len(node.Arguments) < 2 {
		return ""
	}

	varName := ""
	if name, ok := node.Arguments[0].(string); ok {
		varName = name
	}

	// Process value and evaluate string expressions
	value := ""
	evaluatedValue := ""
	if len(node.Arguments) > 1 {
		if childNode, ok := node.Arguments[1].(*normalizer.NormalizedNode); ok {
			value = b.processNode(childNode)
			// Try to evaluate as string expression
			evaluatedValue = b.evaluateStringExpression(childNode)
		} else if str, ok := node.Arguments[1].(string); ok {
			value = str
			evaluatedValue = str
		}
	}

	// Create SSA variable
	ssaVar := b.newSSAVariable(varName)

	// Determine the best value to track
	// Priority: 1) evaluated string expression, 2) valueTable lookup, 3) raw value
	trackedValue := value
	if evaluatedValue != "" && evaluatedValue != value {
		// Use evaluated string expression (e.g., "acad.lsp" from strcat)
		trackedValue = evaluatedValue
	} else if val, ok := b.valueTable[value]; ok {
		// Value is a variable name, look up its resolved value
		trackedValue = val
	}

	// Track by the original variable name for direct lookups
	if varName != "" {
		b.setTrackedValue(varName, trackedValue)
	}
	// Also track SSA variable name
	if ssaVar != "" {
		b.setTrackedValue(ssaVar, trackedValue)
	}

	instr := IRInstruction{
		Opcode:   ASSIGN,
		Result:   ssaVar,
		Operands: []interface{}{varName, value},
		Metadata: map[string]interface{}{
			"original_var": varName,
		},
		Line: node.Line,
	}

	if b.currentBlock != nil {
		b.currentBlock.AddInstruction(instr)
	}

	return ssaVar
}

// processIf processes conditional branch
func (b *IRBuilder) processIf(node *normalizer.NormalizedNode) string {
	if len(node.Arguments) < 2 {
		return ""
	}

	// Process condition
	condition := ""
	if childNode, ok := node.Arguments[0].(*normalizer.NormalizedNode); ok {
		condition = b.processNode(childNode)
	}

	// Create branch instruction
	instr := IRInstruction{
		Opcode:   BRANCH,
		Operands: []interface{}{condition},
		Metadata: map[string]interface{}{},
		Line:     node.Line,
	}

	if b.currentBlock != nil {
		b.currentBlock.AddInstruction(instr)
	}

	// Process then branch
	if len(node.Arguments) > 1 {
		if childNode, ok := node.Arguments[1].(*normalizer.NormalizedNode); ok {
			b.processNode(childNode)
		}
	}

	// Process else branch
	if len(node.Arguments) > 2 {
		if childNode, ok := node.Arguments[2].(*normalizer.NormalizedNode); ok {
			b.processNode(childNode)
		}
	}

	return condition
}

// processWhile processes loop
func (b *IRBuilder) processWhile(node *normalizer.NormalizedNode) string {
	if len(node.Arguments) < 2 {
		return ""
	}

	// Process condition
	condition := ""
	if childNode, ok := node.Arguments[0].(*normalizer.NormalizedNode); ok {
		condition = b.processNode(childNode)
	}

	// Create loop instruction
	instr := IRInstruction{
		Opcode:   LOOP,
		Operands: []interface{}{condition},
		Metadata: map[string]interface{}{},
		Line:     node.Line,
	}

	if b.currentBlock != nil {
		b.currentBlock.AddInstruction(instr)
	}

	// Process body
	if len(node.Arguments) > 1 {
		if childNode, ok := node.Arguments[1].(*normalizer.NormalizedNode); ok {
			b.processNode(childNode)
		}
	}

	return condition
}

// processCall processes function call
func (b *IRBuilder) processCall(node *normalizer.NormalizedNode) string {
	if node == nil {
		return ""
	}

	// Generate SSA result variable
	resultVar := b.newSSATemp()

	// Process arguments
	operands := make([]interface{}, 0)
	for _, arg := range node.Arguments {
		if childNode, ok := arg.(*normalizer.NormalizedNode); ok {
			if childNode == nil {
				operands = append(operands, "")
				continue
			}
			result := b.processNode(childNode)
			operands = append(operands, result)
		} else {
			operands = append(operands, arg)
		}
	}

	// Infer result type
	resultType := b.typeInference.InferCallType(node.FunctionName, operands)
	b.symbolTable[resultVar] = resultType.String()
	// Best-effort value tracking for nested calls
	b.setTrackedValue(resultVar, resultVar)

	// Create call instruction
	instr := IRInstruction{
		Opcode:   CALL,
		Result:   resultVar,
		Operands: append([]interface{}{node.FunctionName}, operands...),
		Metadata: map[string]interface{}{
			"function": node.FunctionName,
		},
		Line: node.Line,
	}

	if b.currentBlock != nil {
		b.currentBlock.AddInstruction(instr)
	}

	// Check for security effects
	b.checkForEffects(node)

	// Track COM object variable by result
	if node.Operation == normalizer.FILE_OPEN && len(node.Arguments) > 0 {
		openTarget := b.resolveEffectTarget(node.Arguments, 0)
		if openTarget != "" && openTarget != "unknown" {
			b.setTrackedValue(resultVar, b.cleanTarget(openTarget))
		}
	} else if node.Operation == normalizer.COM_CREATE && len(operands) > 0 {
		comName := b.cleanTarget(operands[0])
		b.setTrackedValue(resultVar, comName)
	} else if normalizeFunc(node.FunctionName) == "strcat" || normalizeFunc(node.FunctionName) == "vl-string-subst" {
		// Best-effort string propagation for path/command reconstruction
		parts := []string{}
		for _, arg := range operands {
			if s, ok := arg.(string); ok {
				// Check valueTable for resolved values
				val := s
				if v, ok := b.valueTable[s]; ok && v != "" && v != s {
					val = v
				}
				parts = append(parts, b.cleanTarget(val))
			}
		}
		if len(parts) > 0 {
			joined := strings.Join(parts, "")
			b.setTrackedValue(resultVar, joined)
		}
	}

	return resultVar
}

// newSSATemp generates a new SSA temporary variable
func (b *IRBuilder) newSSATemp() string {
	varName := fmt.Sprintf("t%d", b.ssaCounter)
	b.ssaCounter++
	return varName
}

// checkForEffects checks for security effects in a node
func (b *IRBuilder) checkForEffects(node *normalizer.NormalizedNode) {
	var effectType EffectType
	var target string
	var source string
	metadata := make(map[string]interface{})

	// Copy existing metadata
	for k, v := range node.Metadata {
		metadata[k] = v
	}

	switch node.Operation {
	case normalizer.FILE_WRITE, normalizer.FILE_OPEN:
		// Special handling for princ/print: only FILE_WRITE if writing to file (2 args)
		// Single argument means printing to command line (benign)
		funcLower := strings.ToLower(node.FunctionName)
		if (funcLower == "princ" || funcLower == "print") && len(node.Arguments) < 2 {
			// Printing to command line - not a file write
			return
		}
		effectType = FILE_WRITE
		// Try to resolve the target from arguments or valueTable
		target = b.resolveFileWriteTarget(node)

		// Special handling for vl-file-copy: track both source and destination
		if funcLower == "vl-file-copy" && len(node.Arguments) >= 2 {
			sourceTarget := b.resolveEffectTarget(node.Arguments, 0)
			destTarget := b.resolveEffectTarget(node.Arguments, 1)
			// Create a FILE_READ effect for the source
			if sourceTarget != "" && sourceTarget != "unknown" {
				sourceEffect := IREffect{
					EffectType: FILE_READ,
					Target:     b.cleanTarget(sourceTarget),
					Source:     node.FunctionName,
					Metadata:   metadata,
					Line:       node.Line,
				}
				b.appendEffect(sourceEffect)
			}
			// Use the destination as the primary target for FILE_WRITE
			if destTarget != "" && destTarget != "unknown" {
				target = destTarget
			}
		}
	case normalizer.FILE_READ:
		effectType = FILE_READ
		target = b.resolveEffectTarget(node.Arguments, 0)
		// Add code_load metadata for load operations
		if node.Operation == normalizer.LOAD || strings.ToLower(node.FunctionName) == "load" {
			metadata["code_load"] = true
		}
	case normalizer.REG_WRITE:
		effectType = REGISTRY_MODIFY
		if len(node.Arguments) > 0 {
			if t, ok := node.Arguments[0].(string); ok {
				target = t
			}
		}
	case normalizer.REG_READ:
		effectType = REGISTRY_READ
		if len(node.Arguments) > 0 {
			if t, ok := node.Arguments[0].(string); ok {
				target = t
			}
		}
	case normalizer.OS_EXEC:
		effectType = PROCESS_CREATE
		if len(node.Arguments) > 0 {
			if t, ok := node.Arguments[0].(string); ok {
				target = t
			}
		}
	case normalizer.COM_CREATE:
		effectType = COM_CREATE
		source = node.FunctionName
		if len(node.Arguments) > 0 {
			if t, ok := node.Arguments[0].(string); ok {
				target = t
			}
		}
	case normalizer.COM_INVOKE:
		effectType = COM_INVOKE
		source = node.FunctionName
		if len(node.Arguments) > 0 {
			if t, ok := node.Arguments[0].(string); ok {
				target = t
			}
		}
	case normalizer.EVAL:
		effectType = DATA_DESTROY
		source = node.FunctionName
	case normalizer.LOAD:
		// `load` imports and executes external AutoLISP code.
		// It should be treated as code loading, not data exfiltration.
		effectType = FILE_READ
		target = b.resolveEffectTarget(node.Arguments, 0)
		source = node.FunctionName
		metadata["code_load"] = true
	case normalizer.CAD_COMMAND:
		// Check for command hijacking (undefine, rename dangerous commands)
		if b.isCommandHijack(node) {
			effectType = COMMAND_HIJACK
			source = node.FunctionName
			// Extract the command being hijacked
			if len(node.Arguments) > 1 {
				if t, ok := node.Arguments[1].(string); ok {
					target = t
				}
			}
			metadata["hijack_type"] = "undefine"
		} else {
			// AutoCAD internal commands are benign - no dangerous effects
			return
		}
	case normalizer.UNKNOWN:
		// Infer effects from unknown function arguments
		b.inferUnknownEffects(node)
		return
	default:
		// Check for environment check functions
		funcNameLower := strings.ToLower(node.FunctionName)
		if funcNameLower == "getvar" || funcNameLower == "ver" || funcNameLower == "getenv" {
			effectType = ENV_CHECK
			if len(node.Arguments) > 0 {
				if t, ok := node.Arguments[0].(string); ok {
					target = b.cleanTarget(t)
				}
			} else {
				target = "system"
			}
		} else {
			return
		}
	}

	if effectType != "" {
		if source == "" {
			source = node.FunctionName
		}
		effect := IREffect{
			EffectType: effectType,
			Target:     b.cleanTarget(target),
			Source:     source,
			Metadata:   metadata,
			Line:       node.Line,
		}

		b.appendEffect(effect)
	}
}

// inferUnknownEffects infers effects from unknown function arguments
func (b *IRBuilder) inferUnknownEffects(node *normalizer.NormalizedNode) {
	args := []string{}
	for _, arg := range node.Arguments {
		if s, ok := arg.(string); ok {
			args = append(args, b.cleanTarget(s))
		}
	}

	argText := strings.ToLower(strings.Join(args, " "))
	funcLower := strings.ToLower(node.FunctionName)

	// Registry-like wrapper
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), "hkey_") {
			effect := IREffect{
				EffectType: REGISTRY_MODIFY,
				Target:     a,
				Source:     node.FunctionName,
				Metadata: map[string]interface{}{
					"inferred_from": "unknown_call_args",
					"confidence":    0.5,
				},
				Line: node.Line,
			}
			b.appendEffect(effect)
		}
	}

	// Command-exec-like wrapper
	cmdKeywords := []string{"cmd.exe", "rundll32", "regsvr32", "powershell", "wscript.exe"}
	for _, kw := range cmdKeywords {
		if strings.Contains(argText, kw) {
			cmd := "unknown"
			for _, a := range args {
				aLower := strings.ToLower(a)
				for _, k := range cmdKeywords {
					if strings.Contains(aLower, k) {
						cmd = a
						break
					}
				}
				if cmd != "unknown" {
					break
				}
			}
			effect := IREffect{
				EffectType: PROCESS_CREATE,
				Target:     cmd,
				Source:     node.FunctionName,
				Metadata: map[string]interface{}{
					"inferred_from": "unknown_call_args",
					"confidence":    0.5,
				},
				Line: node.Line,
			}
			b.appendEffect(effect)

			// Check for file hidden (attrib +h)
			if strings.Contains(argText, "attrib") && strings.Contains(argText, "+h") {
				hiddenEffect := IREffect{
					EffectType: FILE_HIDDEN,
					Target:     cmd,
					Source:     node.FunctionName,
					Metadata: map[string]interface{}{
						"inferred_from": "unknown_call_args",
						"confidence":    0.5,
					},
					Line: node.Line,
				}
				b.appendEffect(hiddenEffect)
			}
			break
		}
	}

	// Network-like wrapper
	for _, a := range args {
		aLower := strings.ToLower(a)
		if isLikelyNetworkIndicator(funcLower, aLower) {
			effect := IREffect{
				EffectType: NETWORK_CONNECT,
				Target:     a,
				Source:     node.FunctionName,
				Metadata: map[string]interface{}{
					"inferred_from": "unknown_call_args",
					"confidence":    0.5,
				},
				Line: node.Line,
			}
			b.appendEffect(effect)
			break
		}
	}

	// File-write-like wrapper (copy/rename/write behavior)
	pathArgs := []string{}
	urlArgs := []string{}
	for _, a := range args {
		aLower := strings.ToLower(a)
		hasPathChar := isLikelyFilePathCandidate(aLower)
		notRegistry := !strings.Contains(aLower, "hkey_")
		isURL := strings.HasPrefix(aLower, "http://") || strings.HasPrefix(aLower, "https://")
		if isURL {
			urlArgs = append(urlArgs, a)
		}
		notCommand := true
		for _, kw := range cmdKeywords {
			if strings.Contains(aLower, kw) {
				notCommand = false
				break
			}
		}
		if hasPathChar && notRegistry && !isURL && notCommand {
			pathArgs = append(pathArgs, a)
		}
	}

	if len(pathArgs) >= 2 && isLikelyFileWriteWrapper(funcLower, pathArgs) {
		effect := IREffect{
			EffectType: FILE_WRITE,
			Target:     pathArgs[len(pathArgs)-1],
			Source:     node.FunctionName,
			Metadata: map[string]interface{}{
				"content":       pathArgs[0],
				"inferred_from": "unknown_call_args",
				"confidence":    0.5,
			},
			Line: node.Line,
		}
		b.appendEffect(effect)
	} else if len(urlArgs) > 0 && len(pathArgs) > 0 {
		networkEffect := IREffect{
			EffectType: NETWORK_CONNECT,
			Target:     urlArgs[0],
			Source:     node.FunctionName,
			Metadata: map[string]interface{}{
				"inferred_from": "unknown_call_args",
				"confidence":    0.5,
			},
			Line: node.Line,
		}
		b.appendEffect(networkEffect)

		// Preserve generic download wrappers like (~ "http://..." "payload.dcl")
		// without treating arbitrary labels as file paths.
		effect := IREffect{
			EffectType: FILE_WRITE,
			Target:     pathArgs[len(pathArgs)-1],
			Source:     node.FunctionName,
			Metadata: map[string]interface{}{
				"content":       urlArgs[0],
				"inferred_from": "unknown_call_args",
				"confidence":    0.5,
			},
			Line: node.Line,
		}
		b.appendEffect(effect)
	}
}

func isLikelyNetworkIndicator(funcLower, valueLower string) bool {
	if !strings.HasPrefix(valueLower, "http://") && !strings.HasPrefix(valueLower, "https://") {
		return false
	}

	networkFuncs := []string{
		"http", "https", "xmlhttp", "serverxmlhttp", "winhttp", "internet",
		"url", "download", "upload", "post", "get", "request", "openurl",
		"web", "socket",
	}
	for _, kw := range networkFuncs {
		if strings.Contains(funcLower, kw) {
			return true
		}
	}

	if strings.Contains(valueLower, "?") || strings.Contains(valueLower, "%") {
		return true
	}

	suspiciousExts := []string{
		".exe", ".dll", ".scr", ".hta", ".js", ".vbs", ".wsf", ".bat", ".cmd",
		".ps1", ".zip", ".rar", ".cab", ".dat", ".bin",
	}
	for _, ext := range suspiciousExts {
		if strings.Contains(valueLower, ext) {
			return true
		}
	}

	return false
}

func isLikelyFilePathCandidate(valueLower string) bool {
	if valueLower == "" {
		return false
	}
	if strings.HasPrefix(valueLower, "http://") || strings.HasPrefix(valueLower, "https://") {
		return false
	}
	if strings.Contains(valueLower, "\\") {
		return true
	}
	if strings.HasPrefix(valueLower, "/") || strings.HasPrefix(valueLower, "./") || strings.HasPrefix(valueLower, "../") {
		return true
	}
	if strings.Contains(valueLower, "/") && !strings.Contains(valueLower, " / ") {
		return true
	}

	fileExts := []string{
		".lsp", ".fas", ".vlx", ".mnl", ".dcl", ".scr", ".exe", ".dll", ".ocx",
		".dat", ".txt", ".log", ".bak", ".cfg", ".ini", ".vbs", ".js", ".wsf",
		".jpg", ".png", ".dwg", ".dxf", ".csv",
	}
	for _, ext := range fileExts {
		if strings.HasSuffix(valueLower, ext) {
			return true
		}
	}
	return false
}

func isLikelyFileWriteWrapper(funcLower string, pathArgs []string) bool {
	if len(pathArgs) < 2 {
		return false
	}

	writeFuncs := []string{
		"write", "save", "copy", "rename", "move", "export", "dump", "create",
		"append", "put", "store", "output", "open",
	}
	for _, kw := range writeFuncs {
		if strings.Contains(funcLower, kw) {
			return true
		}
	}

	last := strings.ToLower(pathArgs[len(pathArgs)-1])
	first := strings.ToLower(pathArgs[0])
	return isLikelyFilePathCandidate(last) && isLikelyFilePathCandidate(first)
}

func (b *IRBuilder) appendEffect(effect IREffect) {
	if effect.EffectType == "" || effect.Target == "" {
		return
	}
	if len(b.globalEffects) >= maxGlobalEffects {
		return
	}
	key := string(effect.EffectType) + "|" + effect.Target + "|" + effect.Source
	if _, exists := b.effectSeen[key]; exists {
		return
	}
	b.effectSeen[key] = struct{}{}
	b.globalEffects = append(b.globalEffects, effect)
	if b.currentBlock != nil {
		b.currentBlock.AddEffect(effect)
	}
}

func (b *IRBuilder) setTrackedValue(name, value string) {
	if name == "" {
		return
	}
	if existing, ok := b.valueTable[name]; ok && existing == value {
		return
	}
	b.valueTable[name] = value
	b.valueVersion++
}

// newBlockID generates a new block ID
func (b *IRBuilder) newBlockID() string {
	id := b.blockCounter
	b.blockCounter++
	return "block_" + strconv.Itoa(id)
}

// newSSAVariable generates a new SSA variable
func (b *IRBuilder) newSSAVariable(base string) string {
	version := b.varVersions[base]
	b.varVersions[base] = version + 1
	return base + "_" + strconv.Itoa(version)
}

// cleanTarget cleans target value, handling various edge cases
// Matches Python version's _clean_target method
func (b *IRBuilder) cleanTarget(value interface{}) string {
	if value == nil {
		return "unknown"
	}

	raw := b.resolveArgValue(value)
	if cached, ok := b.cleanStringCache[raw]; ok {
		return cached
	}
	cleaned := b.cleanResolvedTarget(raw)
	b.cleanStringCache[raw] = cleaned
	return cleaned
}

func (b *IRBuilder) cleanResolvedTarget(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "\"")
	s = strings.Trim(s, "'")

	// Handle empty string
	if s == "" {
		return "unknown"
	}

	// Remove stream2 pollution suffixes like "Microsoft.XMLHTTP[VIAX-IXMDX"
	if strings.Contains(s, "[") {
		parts := strings.SplitN(s, "[", 2)
		s = parts[0]
	}

	// Collapse accidental spaces
	s = strings.Join(strings.Fields(s), " ")

	// Check empty string again
	if s == "" {
		return "unknown"
	}

	// Recover list-like targets: "['\\\\DivX.fin', 'vlax-release-object']"
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && len(s) <= b.maxLiteralEvalLen {
		// Try to parse as list and extract first path-like item
		if items := b.parseListLiteral(s); len(items) > 0 {
			for _, item := range items {
				if strings.Contains(item, "\\") || strings.Contains(item, "/") || strings.Contains(item, ".") {
					return item
				}
			}
			if len(items) > 0 {
				return items[0]
			}
		}
	}

	if s == "" {
		return "unknown"
	}
	return s
}

// evaluateStringExpression recursively evaluates a string expression
// Handles strcat, chr, and variable references
func (b *IRBuilder) evaluateStringExpression(arg interface{}) string {
	switch v := arg.(type) {
	case string:
		// Look up in value table in case it's a variable name
		if val, ok := b.valueTable[v]; ok {
			return val
		}
		return v
	case *normalizer.NormalizedNode:
		if v == nil {
			return ""
		}
		if cached, ok := b.evalStringCache[v]; ok && cached.version == b.valueVersion {
			return cached.value
		}
		result := ""
		funcName := strings.ToLower(v.FunctionName)
		switch funcName {
		case "strcat":
			// Concatenate all arguments
			var result strings.Builder
			for _, child := range v.Arguments {
				childVal := b.evaluateStringExpression(child)
				if childVal != "" {
					result.WriteString(childVal)
				}
			}
			resultString := result.String()
			b.evalStringCache[v] = cachedStringEval{version: b.valueVersion, value: resultString}
			return resultString
		case "chr":
			// Evaluate chr(97) -> "a"
			if len(v.Arguments) > 0 {
				switch code := v.Arguments[0].(type) {
				case int:
					result = string(rune(code))
				case float64:
					result = string(rune(int(code)))
				case string:
					// Try to parse as number
					if val, ok := b.valueTable[code]; ok {
						if intVal, err := strconv.Atoi(val); err == nil {
							result = string(rune(intVal))
							break
						}
					}
					if intVal, err := strconv.Atoi(code); err == nil {
						result = string(rune(intVal))
					}
				}
			}
		case "strcase":
			// strcase converts case - evaluate argument and convert
			if len(v.Arguments) > 0 {
				argVal := b.evaluateStringExpression(v.Arguments[0])
				result = strings.ToUpper(argVal)
			}
		case "substr":
			// substr(string start end) - extract substring
			if len(v.Arguments) >= 3 {
				strVal := b.evaluateStringExpression(v.Arguments[0])
				start := 0
				end := len(strVal)
				if s, ok := v.Arguments[1].(int); ok {
					start = s - 1 // AutoLISP is 1-indexed
				}
				if e, ok := v.Arguments[2].(int); ok {
					end = e
				}
				if start >= 0 && start < len(strVal) && end <= len(strVal) && end > start {
					result = strVal[start:end]
				}
			}
		default:
			// Check if it's a variable that resolves to a string
			if val, ok := b.valueTable[v.FunctionName]; ok {
				result = val
				break
			}
			// For other function calls, try to evaluate arguments
			if len(v.Arguments) > 0 {
				if s, ok := v.Arguments[0].(string); ok {
					result = s
				}
			}
		}
		if result == "" {
			result = v.FunctionName
		}
		b.evalStringCache[v] = cachedStringEval{version: b.valueVersion, value: result}
		return result
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.Itoa(int(v))
	default:
		s := fmt.Sprintf("%v", v)
		if val, ok := b.valueTable[s]; ok {
			return val
		}
		return s
	}
}

// resolveEffectTarget resolves a target from node arguments at given index
// It tries to get the literal string value, or looks up in valueTable if it's a variable
func (b *IRBuilder) resolveEffectTarget(args []interface{}, index int) string {
	if index >= len(args) {
		return ""
	}

	arg := args[index]
	if arg == nil {
		return ""
	}

	// Try direct string first
	if s, ok := arg.(string); ok {
		// Check if it's a variable name in valueTable
		if val, ok := b.valueTable[s]; ok {
			return b.cleanTarget(val)
		}
		return s
	}

	// If it's a normalized node, evaluate it as string expression
	if node, ok := arg.(*normalizer.NormalizedNode); ok {
		if node == nil {
			return ""
		}
		evaluated := b.evaluateStringExpression(node)
		if evaluated != "" && evaluated != node.FunctionName {
			return b.cleanTarget(evaluated)
		}
		// Fallback: try to get first argument
		if len(node.Arguments) > 0 {
			if s, ok := node.Arguments[0].(string); ok {
				if val, ok := b.valueTable[s]; ok {
					return b.cleanTarget(val)
				}
				// Evaluate nested expression
				nested := b.evaluateStringExpression(node.Arguments[0])
				if nested != "" {
					return b.cleanTarget(nested)
				}
				return s
			}
		}
		return node.FunctionName
	}

	// Try to convert to string and look up in valueTable
	s := fmt.Sprintf("%v", arg)
	if val, ok := b.valueTable[s]; ok {
		return val
	}

	return s
}

func (b *IRBuilder) resolveFileWriteTarget(node *normalizer.NormalizedNode) string {
	if node == nil {
		return ""
	}
	funcLower := strings.ToLower(node.FunctionName)
	switch funcLower {
	case "write-line", "write-char", "princ", "print":
		if len(node.Arguments) >= 2 {
			return b.resolveEffectTarget(node.Arguments, len(node.Arguments)-1)
		}
	case "open":
		if len(node.Arguments) >= 1 {
			return b.resolveEffectTarget(node.Arguments, 0)
		}
	}
	return b.resolveEffectTarget(node.Arguments, 0)
}

// resolveArgValue resolves argument value, ensuring string return
func (b *IRBuilder) resolveArgValue(value interface{}) string {
	if value == nil {
		return ""
	}
	s := ""
	switch v := value.(type) {
	case string:
		s = v
	case int:
		s = strconv.Itoa(v)
	case float64:
		s = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			s = "true"
		} else {
			s = "false"
		}
	default:
		s = fmt.Sprintf("%v", v)
	}
	// Check value table
	if val, ok := b.valueTable[s]; ok {
		return val
	}
	return s
}

// parseListLiteral parses a list literal string
func (b *IRBuilder) parseListLiteral(s string) []string {
	items := []string{}
	// Simple parser for list literals like "['item1', 'item2']"
	content := strings.Trim(s, "[]")
	if content == "" {
		return items
	}

	// Split by comma and clean each item
	parts := strings.Split(content, ",")
	for _, part := range parts {
		item := strings.TrimSpace(part)
		item = strings.Trim(item, "\"")
		item = strings.Trim(item, "'")
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

// isCommandHijack checks if a CAD_COMMAND node is actually a command hijack attempt
// (e.g., (command "undefine" "line") to disable the line command)
func (b *IRBuilder) isCommandHijack(node *normalizer.NormalizedNode) bool {
	funcLower := strings.ToLower(node.FunctionName)
	if funcLower != "command" {
		return false
	}

	// Check if first argument is a hijack command
	if len(node.Arguments) > 0 {
		firstArg := b.resolveArgValue(node.Arguments[0])
		// Handle string literals with quotes
		firstArg = strings.TrimSpace(firstArg)
		firstArg = strings.Trim(firstArg, `"'`)
		firstArgLower := strings.ToLower(firstArg)

		hijackCommands := []string{"undefine", "rename", "undef", "u"}
		for _, hijack := range hijackCommands {
			if firstArgLower == hijack {
				return true
			}
		}

		// Also check if the raw argument contains undefine (for non-string arguments)
		if strings.Contains(firstArgLower, "undefine") {
			return true
		}
	}

	return false
}
