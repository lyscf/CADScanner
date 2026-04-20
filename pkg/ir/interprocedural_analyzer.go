package ir

import (
	"fmt"
	"regexp"
	"strings"
)

// FunctionSummary represents a summary of function effects
type FunctionSummary struct {
	Name              string
	DirectEffects     []EffectType
	InheritedEffects  []EffectType
	Calls             []string
	InferredBehaviors map[string]bool
	cacheValid        bool
	cachedAllEffects  []EffectType
}

// AllEffects returns all effects (direct + inherited) with caching
func (fs *FunctionSummary) AllEffects() []EffectType {
	if !fs.cacheValid || fs.cachedAllEffects == nil {
		// Direct effects take precedence (they're more specific)
		combined := make([]EffectType, 0, len(fs.DirectEffects))
		combined = append(combined, fs.DirectEffects...)

		directSet := make(map[EffectType]bool)
		for _, eff := range fs.DirectEffects {
			directSet[eff] = true
		}

		// Add inherited effects that aren't already in direct effects
		for _, eff := range fs.InheritedEffects {
			if !directSet[eff] {
				combined = append(combined, eff)
				directSet[eff] = true
			}
		}

		fs.cachedAllEffects = combined
		fs.cacheValid = true
	}
	return fs.cachedAllEffects
}

// InvalidateCache invalidates the effects cache when inherited_effects changes
func (fs *FunctionSummary) InvalidateCache() {
	fs.cacheValid = false
	fs.cachedAllEffects = nil
}

// PropagationRule represents a propagation rule for behavior inference
type PropagationRule struct {
	Name       string
	Conditions []Condition
	Inferred   string
}

// Condition represents a condition in a propagation rule
type Condition struct {
	Effect           EffectType
	CountExpr        string
	FunctionPattern  string
	HasStartupHook   bool
	InferredBehavior string
}

// InterproceduralAnalyzer analyzes effects across function boundaries
type InterproceduralAnalyzer struct {
	IRFunctions         map[string]*IRFunction
	Summaries           map[string]*FunctionSummary
	CallGraph           map[string][]string
	EffectMetadata      map[string]map[string]interface{}
	PropagationEvidence *PropagationEvidence
}

// NewInterproceduralAnalyzer creates a new interprocedural analyzer
func NewInterproceduralAnalyzer(irFunctions map[string]*IRFunction, callGraph map[string][]string, propEvidence *PropagationEvidence) *InterproceduralAnalyzer {
	return &InterproceduralAnalyzer{
		IRFunctions:         irFunctions,
		Summaries:           make(map[string]*FunctionSummary),
		CallGraph:           callGraph,
		EffectMetadata:      make(map[string]map[string]interface{}),
		PropagationEvidence: propEvidence,
	}
}

// PROPAGATION_RULES contains rules for behavior inference
var PROPAGATION_RULES = []PropagationRule{
	{
		Name: "SELF_REPLICATION",
		Conditions: []Condition{
			{Effect: FILE_WRITE, CountExpr: ">=2"},
			{FunctionPattern: "^(s::startup|chklsp|writelsp)"},
		},
		Inferred: "self_replication",
	},
	{
		Name: "COMMAND_HIJACK",
		Conditions: []Condition{
			{Effect: COMMAND_UNDEFINE},
			{FunctionPattern: "^c:"},
		},
		Inferred: "command_hijack",
	},
	{
		Name: "STEALTH_PERSISTENCE",
		Conditions: []Condition{
			{Effect: REGISTRY_MODIFY},
			{Effect: FILE_WRITE},
		},
		Inferred: "stealth_persistence",
	},
	{
		Name: "WORM_BEHAVIOR",
		Conditions: []Condition{
			{Effect: FILE_WRITE, CountExpr: ">=3"},
			{HasStartupHook: true},
		},
		Inferred: "worm",
	},
	{
		Name: "DATA_DESTRUCTION",
		Conditions: []Condition{
			{Effect: DATA_DESTROY},
		},
		Inferred: "destructive_payload",
	},
}

// Analyze performs interprocedural analysis
func (ia *InterproceduralAnalyzer) Analyze() map[string]*FunctionSummary {
	// Step 1: Extract direct effects (call graph already provided)
	ia.extractDirectEffects()

	// Step 2: Propagate effects bottom-up
	ia.propagateEffects()

	// Step 3: Infer high-level behaviors
	ia.inferBehaviors()

	return ia.Summaries
}

// extractDirectEffects extracts direct effects from each function
func (ia *InterproceduralAnalyzer) extractDirectEffects() {
	for funcName, fn := range ia.IRFunctions {
		summary := &FunctionSummary{
			Name:              funcName,
			DirectEffects:     []EffectType{},
			InheritedEffects:  []EffectType{},
			Calls:             ia.CallGraph[funcName],
			InferredBehaviors: make(map[string]bool),
			cacheValid:        false,
			cachedAllEffects:  nil,
		}

		for _, block := range fn.Blocks {
			// Extract effects only (calls already provided via CallGraph)
			for _, effect := range block.Effects {
				summary.DirectEffects = append(summary.DirectEffects, effect.EffectType)

				// Store metadata for later analysis
				effectKey := funcName + ":" + string(effect.EffectType) + ":" + string(rune(effect.Line))
				ia.EffectMetadata[effectKey] = map[string]interface{}{
					"target":   effect.Target,
					"source":   effect.Source,
					"metadata": effect.Metadata,
				}
			}
		}

		ia.Summaries[funcName] = summary
	}
}

// propagateEffects propagates effects across call graph with iterative fixed-point
func (ia *InterproceduralAnalyzer) propagateEffects() {
	maxRounds := len(ia.IRFunctions) * 2
	if maxRounds < 1 {
		maxRounds = 1
	}

	// Pre-compute all_effects for each function to avoid repeated list creation
	calleeEffectsCache := make(map[string][]EffectType)
	for name, summary := range ia.Summaries {
		calleeEffectsCache[name] = summary.AllEffects()
	}

	for round := 0; round < maxRounds; round++ {
		changed := false
		for funcName, summary := range ia.Summaries {
			// Use set for O(1) lookup of existing effects
			currentEffectsSet := make(map[EffectType]bool)
			for _, eff := range summary.InheritedEffects {
				currentEffectsSet[eff] = true
			}

			newEffects := make([]EffectType, 0, len(summary.InheritedEffects))
			newEffects = append(newEffects, summary.InheritedEffects...)
			effectsAdded := false

			for _, callee := range summary.Calls {
				calleeEffects, ok := calleeEffectsCache[callee]
				if !ok {
					continue
				}

				for _, eff := range calleeEffects {
					if !currentEffectsSet[eff] {
						newEffects = append(newEffects, eff)
						currentEffectsSet[eff] = true
						effectsAdded = true
					}
				}
			}

			if effectsAdded {
				summary.InheritedEffects = newEffects
				summary.InvalidateCache()
				calleeEffectsCache[funcName] = summary.AllEffects()
				changed = true
			}
		}

		if !changed {
			break
		}
	}
}

// inferBehaviors infers high-level behaviors from effect patterns
func (ia *InterproceduralAnalyzer) inferBehaviors() {
	for funcName, summary := range ia.Summaries {
		allEffects := summary.AllEffects()

		// Apply propagation rules
		for _, rule := range PROPAGATION_RULES {
			if ia.matchesRule(funcName, summary, allEffects, rule) {
				summary.InferredBehaviors[rule.Inferred] = true
			}
		}

		ia.applyPropagationEvidence(funcName, summary)
	}
}

// applyPropagationEvidence injects unified propagation evidence into interprocedural inference
func (ia *InterproceduralAnalyzer) applyPropagationEvidence(funcName string, summary *FunctionSummary) {
	evidence := ia.PropagationEvidence
	if evidence == nil {
		return
	}

	targetKinds := make(map[string]bool)
	for _, target := range evidence.Targets {
		if target.Function == funcName {
			targetKinds[target.TargetKind] = true
		}
	}

	fromEntry := false
	for _, target := range evidence.Targets {
		if target.Function == funcName && target.FromEntry {
			fromEntry = true
			break
		}
	}

	inChain := false
	for _, chain := range evidence.Chains {
		for _, fn := range chain.Chain {
			if fn == funcName {
				inChain = true
				break
			}
		}
	}

	if targetKinds["startup"] || targetKinds["menu"] || targetKinds["autoload"] {
		summary.InferredBehaviors["autoload_propagation"] = true
	}
	if targetKinds["lateral"] {
		summary.InferredBehaviors["lateral_propagation"] = true
	}
	if targetKinds["removable"] {
		summary.InferredBehaviors["removable_media_propagation"] = true
	}
	if targetKinds["code_load"] {
		summary.InferredBehaviors["payload_staging"] = true
	}

	if fromEntry && (targetKinds["startup"] || targetKinds["menu"] || targetKinds["autoload"]) {
		summary.InferredBehaviors["entrypoint_propagation_chain"] = true
	}

	if fromEntry && evidence.LocalAutoload && len(evidence.AutoloadTargets) >= 1 && len(evidence.EntryPoints) >= 1 {
		summary.InferredBehaviors["worm"] = true
		summary.InferredBehaviors["self_replication"] = true
	}

	if evidence.LateralMovement && (targetKinds["lateral"] || inChain) {
		summary.InferredBehaviors["lateral_movement"] = true
	}
}

// matchesRule checks if function matches a propagation rule
func (ia *InterproceduralAnalyzer) matchesRule(funcName string, summary *FunctionSummary, allEffects []EffectType, rule PropagationRule) bool {
	for _, condition := range rule.Conditions {
		if condition.Effect != "" {
			effectType := condition.Effect

			// Check count condition
			if condition.CountExpr != "" {
				actualCount := 0
				for _, eff := range allEffects {
					if eff == effectType {
						actualCount++
					}
				}

				required := 0
				if strings.HasPrefix(condition.CountExpr, ">=") {
					required = parseInt(condition.CountExpr[2:])
					if actualCount < required {
						return false
					}
				} else if strings.HasPrefix(condition.CountExpr, ">") {
					required = parseInt(condition.CountExpr[1:])
					if actualCount <= required {
						return false
					}
				} else {
					required = parseInt(condition.CountExpr)
					if actualCount != required {
						return false
					}
				}
			} else {
				// Just check presence
				found := false
				for _, eff := range allEffects {
					if eff == effectType {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		} else if condition.FunctionPattern != "" {
			matched, _ := regexp.MatchString(condition.FunctionPattern, funcName)
			if !matched {
				return false
			}
		} else if condition.HasStartupHook {
			if !strings.HasPrefix(funcName, "s::") {
				return false
			}
		} else if condition.InferredBehavior != "" {
			if !summary.InferredBehaviors[condition.InferredBehavior] {
				return false
			}
		}
	}
	return true
}

// parseInt parses an integer from string
func parseInt(s string) int {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return 0
	}
	return result
}

// GetInferredBehaviors gets all inferred behaviors
func (ia *InterproceduralAnalyzer) GetInferredBehaviors() map[string][]string {
	result := make(map[string][]string)
	for funcName, summary := range ia.Summaries {
		behaviors := []string{}
		for behavior := range summary.InferredBehaviors {
			behaviors = append(behaviors, behavior)
		}
		if len(behaviors) > 0 {
			result[funcName] = behaviors
		}
	}
	return result
}

// GetFunctionSummary gets summary for a specific function
func (ia *InterproceduralAnalyzer) GetFunctionSummary(funcName string) *FunctionSummary {
	return ia.Summaries[funcName]
}
