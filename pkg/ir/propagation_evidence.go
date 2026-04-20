package ir

import (
	"strconv"
	"strings"
)

// PropagationGraph represents worm propagation graph
type PropagationGraph struct {
	Sources               []string          // Source files (e.g., acaddoc.lsp)
	Targets               []PropagationNode // Target files
	Methods               []string          // Functions involved
	Complexity            int               // Number of propagation paths
	IsWorm                bool
	ReplicationAssessment string
}

// PropagationNode represents a node in propagation graph
type PropagationNode struct {
	Path   string
	Method string // Function that writes to this path
	Line   int
}

// ResolvedPath represents resolved file path with metadata
// Implements Partial Effect Resolution Model:
// - Fully resolved: path is concrete (e.g., "acaddoc.lsp")
// - Partially resolved: path contains symbolic parts (e.g., "<dwgprefix>/acaddoc.lsp")
// - Unresolved: path is "unknown" (conservative fallback)
type ResolvedPath struct {
	Path            string
	Origin          string // "constant", "strcat", "getvar", "conservative_fallback", "unknown"
	PathType        string // "startup_file", "menu_file", "data_file", "unknown"
	Severity        string // "high", "medium", "low"
	Components      []string
	ResolutionLevel string // "full", "partial", "unresolved"
}

// EnvCheckType represents environment check classification
type EnvCheckType string

const (
	EnvCheckTime        EnvCheckType = "TIME"         // cdate, date
	EnvCheckHostID      EnvCheckType = "HOST_ID"      // macaddr, hostname
	EnvCheckFileContext EnvCheckType = "FILE_CONTEXT" // dwgprefix, dwgname
	EnvCheckAppContext  EnvCheckType = "APP_CONTEXT"  // menuname, acadver
	EnvCheckSystem      EnvCheckType = "SYSTEM"       // platform, version
)

// ResolvedEnvCheck represents resolved environment check with classification
type ResolvedEnvCheck struct {
	CheckType EnvCheckType
	Source    string
	Severity  string // "high", "medium", "low"
	Purpose   string // "delayed_execution", "targeting", "propagation", "detection"
}

// PropagationEvidence represents propagation evidence for security analysis
type PropagationEvidence struct {
	Targets           []PropagationTarget
	Chains            []PropagationChain
	EntryPoints       []string
	StartupTargets    []string
	MenuTargets       []string
	AutoloadTargets   []string
	LateralTargets    []string
	RemovableTargets  []string
	CodeLoaderTargets []string
	Methods           []string
	PropagationGraph  *PropagationGraph
	CoverageHint      float64
	MaxChainDepth     int
	LocalAutoload     bool
	LateralMovement   bool
	PropagationLikely bool
}

// PropagationTarget represents a target for propagation analysis
type PropagationTarget struct {
	Path            string
	PathType        string
	Severity        string
	ResolutionLevel string
	Function        string
	Line            int
	TargetKind      string
	Origin          string
	FromEntry       bool
}

// PropagationChain represents a propagation chain
type PropagationChain struct {
	EntryPoint   string
	SinkFunction string
	SinkPath     string
	TargetKind   string
	Chain        []string
	Depth        int
}

// PropagationEvidenceExtractor extracts propagation evidence from IR
type PropagationEvidenceExtractor struct {
	functions    map[string]*IRFunction
	effects      []IREffect
	effectToFunc map[string]string
	callGraph    map[string][]string
}

// NewPropagationEvidenceExtractor creates a new propagation evidence extractor
func NewPropagationEvidenceExtractor(functions map[string]*IRFunction, effects []IREffect) *PropagationEvidenceExtractor {
	return NewPropagationEvidenceExtractorWithCallGraph(functions, effects, BuildCallGraph(functions))
}

func NewPropagationEvidenceExtractorWithCallGraph(functions map[string]*IRFunction, effects []IREffect, callGraph map[string][]string) *PropagationEvidenceExtractor {
	extractor := &PropagationEvidenceExtractor{
		functions:    functions,
		effects:      effects,
		effectToFunc: make(map[string]string),
		callGraph:    callGraph,
	}
	extractor.buildEffectToFunc()
	return extractor
}

// buildEffectToFunc maps effects to their source functions
func (e *PropagationEvidenceExtractor) buildEffectToFunc() {
	for _, fn := range e.functions {
		for _, block := range fn.Blocks {
			for _, effect := range block.Effects {
				e.effectToFunc[effectKey(effect)] = fn.Name
			}
		}
	}
}

// Extract extracts propagation evidence
func (e *PropagationEvidenceExtractor) Extract() *PropagationEvidence {
	evidence := &PropagationEvidence{
		Targets:           []PropagationTarget{},
		Chains:            []PropagationChain{},
		EntryPoints:       e.findEntryPoints(),
		StartupTargets:    []string{},
		MenuTargets:       []string{},
		AutoloadTargets:   []string{},
		LateralTargets:    []string{},
		RemovableTargets:  []string{},
		CodeLoaderTargets: []string{},
		Methods:           []string{},
		PropagationGraph:  e.buildPropagationGraph(),
		CoverageHint:      0.0,
		MaxChainDepth:     0,
		LocalAutoload:     false,
		LateralMovement:   false,
		PropagationLikely: false,
	}

	// Classify targets
	for _, effect := range e.effects {
		target := e.classifyTarget(effect)
		if target != nil {
			evidence.Targets = append(evidence.Targets, *target)

			// Track startup targets
			if e.isStartupTarget(target.Path) {
				evidence.StartupTargets = append(evidence.StartupTargets, target.Path)
			}

			// Track menu targets
			if e.isMenuTarget(target.Path) {
				evidence.MenuTargets = append(evidence.MenuTargets, target.Path)
			}

			// Track autoload targets
			if e.isAutoloadTarget(target.Path) {
				evidence.AutoloadTargets = append(evidence.AutoloadTargets, target.Path)
			}
		}
	}

	// Calculate coverage hint
	if len(e.effects) > 0 {
		evidence.CoverageHint = float64(len(evidence.Targets)) / float64(len(e.effects))
	}

	// Check for local autoload
	evidence.LocalAutoload = len(evidence.StartupTargets) > 0 || len(evidence.AutoloadTargets) > 0

	// Check for lateral movement
	evidence.LateralMovement = e.detectLateralMovement(evidence.Targets)

	// Populate methods from propagation graph
	if evidence.PropagationGraph != nil {
		evidence.Methods = evidence.PropagationGraph.Methods
	}

	// Classify lateral targets
	for _, target := range evidence.Targets {
		if e.isLateralTarget(target.Path) {
			evidence.LateralTargets = append(evidence.LateralTargets, target.Path)
		}
		// Classify removable targets (files that can be deleted)
		if e.isRemovableTarget(target.Path) {
			evidence.RemovableTargets = append(evidence.RemovableTargets, target.Path)
		}
		// Classify code loader targets (files that load other code)
		if e.isCodeLoaderTarget(target.Path) {
			evidence.CodeLoaderTargets = append(evidence.CodeLoaderTargets, target.Path)
		}
	}

	// Assess propagation likelihood
	evidence.PropagationLikely = e.assessPropagationLikelihood(evidence)

	return evidence
}

// detectLateralMovement detects lateral movement indicators
func (e *PropagationEvidenceExtractor) detectLateralMovement(targets []PropagationTarget) bool {
	for _, target := range targets {
		path := strings.ToLower(target.Path)
		// Check for network shares or remote paths
		if strings.Contains(path, "\\\\") || strings.Contains(path, "//") ||
			strings.Contains(path, "network") || strings.Contains(path, "share") {
			return true
		}
		// Check for writing to other user directories
		if strings.Contains(path, "\\users\\") && !strings.Contains(path, "\\users\\public") {
			return true
		}
	}
	return false
}

// buildPropagationGraph constructs propagation graph from IR effects
func (e *PropagationEvidenceExtractor) buildPropagationGraph() *PropagationGraph {
	graph := &PropagationGraph{
		Sources:               []string{},
		Targets:               []PropagationNode{},
		Methods:               []string{},
		Complexity:            0,
		IsWorm:                false,
		ReplicationAssessment: "none",
	}

	// Track source files (files that are read)
	sourceSet := make(map[string]bool)
	// Track target files (files that are written)
	targetSet := make(map[string]bool)
	// Track methods involved
	methodSet := make(map[string]bool)

	for _, effect := range e.effects {
		funcName := "unknown"
		if id, ok := e.effectToFunc[effectKey(effect)]; ok {
			funcName = id
		}

		// Classify effect type
		switch effect.EffectType {
		case FILE_READ:
			sourceSet[effect.Target] = true
		case FILE_WRITE, FILE_DELETE, FILE_HIDDEN:
			targetSet[effect.Target] = true
			graph.Targets = append(graph.Targets, PropagationNode{
				Path:   effect.Target,
				Method: funcName,
				Line:   effect.Line,
			})
		}

		methodSet[funcName] = true
	}

	// Convert sets to slices
	for source := range sourceSet {
		graph.Sources = append(graph.Sources, source)
	}

	for method := range methodSet {
		graph.Methods = append(graph.Methods, method)
	}

	// Calculate complexity (number of distinct propagation paths)
	graph.Complexity = len(graph.Targets)

	// Assess worm characteristics
	graph.IsWorm = e.assessWormCharacteristics(graph)
	if graph.IsWorm {
		graph.ReplicationAssessment = e.assessReplication(graph)
	}

	return graph
}

// assessWormCharacteristics assesses if the behavior shows worm-like characteristics
func (e *PropagationEvidenceExtractor) assessWormCharacteristics(graph *PropagationGraph) bool {
	// Worm indicators:
	// 1. Multiple file writes to different locations
	// 2. Startup file modification
	// 3. Command hijacking
	// 4. Network activity

	targetPaths := make(map[string]bool)
	hasStartupTarget := false
	hasCommandHijack := false
	hasNetworkActivity := false

	for _, node := range graph.Targets {
		targetPaths[node.Path] = true
		if e.isStartupTarget(node.Path) {
			hasStartupTarget = true
		}
	}

	for _, effect := range e.effects {
		if effect.EffectType == COMMAND_HIJACK || effect.EffectType == COMMAND_UNDEFINE {
			hasCommandHijack = true
		}
		if effect.EffectType == NETWORK_CONNECT {
			hasNetworkActivity = true
		}
	}

	// Worm requires at least 2 distinct target paths and one of the other indicators
	return len(targetPaths) >= 2 && (hasStartupTarget || hasCommandHijack || hasNetworkActivity)
}

// assessReplication assesses the replication capability
func (e *PropagationEvidenceExtractor) assessReplication(graph *PropagationGraph) string {
	if graph.Complexity >= 5 {
		return "high"
	} else if graph.Complexity >= 3 {
		return "medium"
	} else if graph.Complexity >= 1 {
		return "low"
	}
	return "none"
}

// isLateralTarget checks if a target path indicates lateral movement
func (e *PropagationEvidenceExtractor) isLateralTarget(path string) bool {
	lowerPath := strings.ToLower(path)
	// Network shares
	return strings.Contains(lowerPath, "\\\\") || strings.Contains(lowerPath, "//") ||
		strings.Contains(lowerPath, "network") || strings.Contains(lowerPath, "share")
}

// isRemovableTarget checks if a target is a removable file
func (e *PropagationEvidenceExtractor) isRemovableTarget(path string) bool {
	lowerPath := strings.ToLower(path)
	// Files that can be deleted (not system files)
	return strings.Contains(lowerPath, ".lsp") || strings.Contains(lowerPath, ".fas") ||
		strings.Contains(lowerPath, ".vlx") || strings.Contains(lowerPath, ".mnl")
}

// isCodeLoaderTarget checks if a target is a code loader file
func (e *PropagationEvidenceExtractor) isCodeLoaderTarget(path string) bool {
	lowerPath := strings.ToLower(path)
	// Files that load other code
	return strings.Contains(lowerPath, "acaddoc.lsp") || strings.Contains(lowerPath, "acad.fas") ||
		strings.Contains(lowerPath, "acad.lsp") || strings.Contains(lowerPath, "startup")
}

// assessPropagationLikelihood assesses the likelihood of propagation
func (e *PropagationEvidenceExtractor) assessPropagationLikelihood(evidence *PropagationEvidence) bool {
	// Propagation is likely if:
	// 1. Has worm characteristics
	// 2. Has lateral movement
	// 3. Has multiple startup targets
	// 4. Has command hijacking

	if evidence.PropagationGraph != nil && evidence.PropagationGraph.IsWorm {
		return true
	}

	if evidence.LateralMovement {
		return true
	}

	if len(evidence.StartupTargets) > 0 && len(evidence.AutoloadTargets) > 0 {
		return true
	}

	// Check for command hijacking in effects
	hasCommandHijack := false
	for _, effect := range e.effects {
		if effect.EffectType == COMMAND_HIJACK || effect.EffectType == COMMAND_UNDEFINE {
			hasCommandHijack = true
			break
		}
	}

	return hasCommandHijack && len(evidence.StartupTargets) > 0
}

// findEntryPoints finds entry points in the IR
func (e *PropagationEvidenceExtractor) findEntryPoints() []string {
	entries := []string{}

	// Check for c: commands (AutoCAD commands)
	for name := range e.functions {
		if len(name) > 2 && name[0:2] == "c:" {
			entries = append(entries, name)
		}
	}

	// Check for S::STARTUP
	if _, ok := e.functions["S::STARTUP"]; ok {
		entries = append(entries, "S::STARTUP")
	}

	// Check for reactor functions
	for name := range e.functions {
		if strings.Contains(name, "VLR-") || strings.Contains(name, "reactor") {
			entries = append(entries, name)
		}
	}

	return entries
}

// classifyTarget classifies a target based on its properties
func (e *PropagationEvidenceExtractor) classifyTarget(effect IREffect) *PropagationTarget {
	if effect.Target == "" {
		return nil
	}

	funcName := "unknown"
	if id, ok := e.effectToFunc[effectKey(effect)]; ok {
		funcName = id
	}

	target := &PropagationTarget{
		Path:            effect.Target,
		PathType:        "file",
		Severity:        e.getSeverity(effect.EffectType),
		ResolutionLevel: "high",
		Function:        funcName,
		Line:            effect.Line,
		TargetKind:      e.classifyTargetKind(effect.Target),
		Origin:          effect.Source,
		FromEntry:       e.isEntryFunction(funcName),
	}

	return target
}

// getSeverity returns severity based on effect type
func (e *PropagationEvidenceExtractor) getSeverity(effectType EffectType) string {
	switch effectType {
	case FILE_WRITE, FILE_DELETE, REGISTRY_MODIFY, REGISTRY_DELETE:
		return "high"
	case FILE_READ, REGISTRY_READ:
		return "medium"
	case PROCESS_CREATE, COMMAND_HIJACK:
		return "critical"
	default:
		return "low"
	}
}

// classifyTargetKind classifies the kind of target
func (e *PropagationEvidenceExtractor) classifyTargetKind(path string) string {
	path = strings.ToLower(path)

	// Startup files
	if strings.Contains(path, "acad.lsp") || strings.Contains(path, "acaddoc.lsp") ||
		strings.Contains(path, "startup") || strings.Contains(path, ".mnl") {
		return "startup"
	}

	// Menu files
	if strings.Contains(path, "menu") || strings.Contains(path, ".mnu") {
		return "menu"
	}

	// Code files
	if strings.HasSuffix(path, ".lsp") || strings.HasSuffix(path, ".fas") ||
		strings.HasSuffix(path, ".vlx") || strings.HasSuffix(path, ".scr") {
		return "code"
	}

	// Registry
	if strings.Contains(path, "HKEY_") || strings.Contains(path, "registry") {
		return "registry"
	}

	// Configuration
	if strings.Contains(path, "config") || strings.Contains(path, ".ini") || strings.HasSuffix(path, ".cfg") {
		return "config"
	}

	// Executable
	if strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dll") ||
		strings.HasSuffix(path, ".bat") || strings.HasSuffix(path, ".cmd") {
		return "executable"
	}

	return "other"
}

// isStartupTarget checks if a target is a startup target
func (e *PropagationEvidenceExtractor) isStartupTarget(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "acad.lsp") || strings.Contains(path, "acaddoc.lsp") ||
		strings.Contains(path, "startup") || strings.Contains(path, ".mnl") ||
		strings.Contains(path, "s::startup")
}

// isMenuTarget checks if a target is a menu target
func (e *PropagationEvidenceExtractor) isMenuTarget(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "menu") || strings.HasSuffix(path, ".mnu")
}

// isAutoloadTarget checks if a target is an autoload target
func (e *PropagationEvidenceExtractor) isAutoloadTarget(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "autoload") || strings.Contains(path, "load") ||
		strings.Contains(path, "require")
}

// isEntryFunction checks if a function is an entry point
func (e *PropagationEvidenceExtractor) isEntryFunction(funcName string) bool {
	if len(funcName) > 2 && funcName[0:2] == "c:" {
		return true
	}
	return funcName == "S::STARTUP" || strings.Contains(funcName, "reactor")
}

// Helper functions
func effectKey(effect IREffect) string {
	return string(effect.EffectType) + "|" + effect.Target + "|" + effect.Source + "|" + strconv.Itoa(effect.Line)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

func toLower(s string) string {
	return strings.ToLower(s)
}
