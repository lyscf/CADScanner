package graph

import (
	"fmt"
	"math"

	"github.com/evilcad/cadscanner/pkg/ir"
)

// PredicateResult represents the result of predicate evaluation with proof
type PredicateResult struct {
	Satisfied            bool
	Confidence           float64
	Proof                map[string]interface{}
	NecessaryConditions  []string
	SufficientConditions []string
}

// FormalPredicates provides formal predicates for malware behavior classification
type FormalPredicates struct {
}

// NewFormalPredicates creates a new formal predicates instance
func NewFormalPredicates() *FormalPredicates {
	return &FormalPredicates{}
}

// WormPredicate evaluates worm behavior predicate (SCC-based)
func (fp *FormalPredicates) WormPredicate(sccResults []*SCCResult, irFunctions map[string]*ir.IRFunction, callGraph map[string][]string) *PredicateResult {
	necessary := []string{}
	sufficient := []string{}
	proof := make(map[string]interface{})

	// Necessary Condition 1: SCC exists
	if len(sccResults) == 0 {
		return &PredicateResult{
			Satisfied:            false,
			Confidence:           0.0,
			Proof:                map[string]interface{}{"reason": "No SCC detected", "scc_count": 0},
			NecessaryConditions:  []string{"SCC(G) ≠ ∅"},
			SufficientConditions: []string{},
		}
	}
	necessary = append(necessary, "SCC(G) ≠ ∅")

	// Find non-trivial SCCs with FILE_WRITE
	candidateSCCs := []struct {
		scc      *SCCResult
		hasEntry bool
		strength float64
	}{}

	for _, scc := range sccResults {
		// Necessary Condition 2: Non-trivial cycle
		if len(scc.Nodes) < 2 {
			continue
		}
		necessary = append(necessary, "|S| ≥ 2")

		// Necessary Condition 3: FILE_WRITE in cycle
		hasFileWrite := false
		for _, effect := range scc.Effects {
			if effect == ir.FILE_WRITE {
				hasFileWrite = true
				break
			}
		}
		if !hasFileWrite {
			continue
		}
		necessary = append(necessary, "∃v ∈ S: FILE_WRITE ∈ φ(v)")

		// Sufficient Condition 1: Entry point in cycle
		hasEntry := false
		for _, node := range scc.EntryPoints {
			if len(node) >= 3 && node[0:3] == "s::" {
				hasEntry = true
				break
			}
		}
		if hasEntry {
			sufficient = append(sufficient, "∃v ∈ S: v is entry point")
		}

		// Sufficient Condition 2: Strong connectivity
		if scc.CycleStrength > 0.5 {
			sufficient = append(sufficient, "cycle_strength(S) > 0.5")
		}

		candidateSCCs = append(candidateSCCs, struct {
			scc      *SCCResult
			hasEntry bool
			strength float64
		}{scc, hasEntry, scc.CycleStrength})
	}

	if len(candidateSCCs) == 0 {
		return &PredicateResult{
			Satisfied:            false,
			Confidence:           0.0,
			Proof:                map[string]interface{}{"reason": "No SCC satisfies necessary conditions", "scc_count": len(sccResults), "necessary_failed": necessary},
			NecessaryConditions:  necessary,
			SufficientConditions: sufficient,
		}
	}

	// Select best SCC (highest cycle strength with entry point)
	var bestSCC *SCCResult
	var bestHasEntry bool
	var bestStrength float64
	for _, candidate := range candidateSCCs {
		if candidate.hasEntry && candidate.strength > bestStrength {
			bestSCC = candidate.scc
			bestHasEntry = candidate.hasEntry
			bestStrength = candidate.strength
		}
	}
	if bestSCC == nil {
		// Fallback to first candidate
		bestSCC = candidateSCCs[0].scc
		bestHasEntry = candidateSCCs[0].hasEntry
		bestStrength = candidateSCCs[0].strength
	}

	// Check sufficient conditions
	allSufficient := bestHasEntry && bestStrength > 0.5

	// Compute confidence based on proof strength
	confidence := fp.computeWormConfidence(bestSCC, bestHasEntry, bestStrength)

	// Build formal proof
	effectStrs := make([]string, 0, len(bestSCC.Effects))
	for _, e := range bestSCC.Effects {
		effectStrs = append(effectStrs, string(e))
	}

	backEdgeDicts := make([]map[string]string, 0, len(bestSCC.BackEdges))
	for _, be := range bestSCC.BackEdges {
		backEdgeDicts = append(backEdgeDicts, map[string]string{
			"source": be.Source,
			"target": be.Target,
		})
	}

	proof = map[string]interface{}{
		"theorem": "worm(G) ⇔ ∃S ∈ SCC(G): (|S| ≥ 2 ∧ FILE_WRITE ∈ φ(S) ∧ entry(S))",
		"scc": map[string]interface{}{
			"nodes":          bestSCC.Nodes,
			"size":           len(bestSCC.Nodes),
			"back_edges":     backEdgeDicts,
			"cycle_strength": bestSCC.CycleStrength,
			"entry_points":   bestSCC.EntryPoints,
		},
		"effects":              effectStrs,
		"has_entry_point":      bestHasEntry,
		"tarjan_proof":         "SCC detected by Tarjan's algorithm",
		"back_edge_proof":      fmt.Sprintf("%d back-edges prove cycle", len(bestSCC.BackEdges)),
		"necessary_satisfied":  len(necessary),
		"sufficient_satisfied": len(sufficient),
	}

	return &PredicateResult{
		Satisfied:            allSufficient,
		Confidence:           confidence,
		Proof:                proof,
		NecessaryConditions:  necessary,
		SufficientConditions: sufficient,
	}
}

// computeWormConfidence computes worm confidence based on proof strength
func (fp *FormalPredicates) computeWormConfidence(scc *SCCResult, hasEntry bool, strength float64) float64 {
	w1, w2, w3, w4 := 0.4, 0.3, 0.15, 0.15

	entryScore := 0.0
	if hasEntry {
		entryScore = 1.0
	} else {
		entryScore = 0.5
	}

	strengthScore := strength
	sizeScore := math.Min(float64(len(scc.Nodes))/10.0, 1.0)
	backEdgeScore := 0.0
	if len(scc.Nodes) > 0 {
		backEdgeScore = math.Min(float64(len(scc.BackEdges))/float64(len(scc.Nodes)), 1.0)
	}

	confidence := w1*entryScore + w2*strengthScore + w3*sizeScore + w4*backEdgeScore

	return math.Min(confidence, 1.0)
}

// StealthPersistencePredicate evaluates stealth persistence predicate
func (fp *FormalPredicates) StealthPersistencePredicate(irFunctions map[string]*ir.IRFunction, callGraph map[string][]string) *PredicateResult {
	necessary := []string{}
	sufficient := []string{}

	// Find functions with both FILE_WRITE and REGISTRY_MODIFY
	candidates := []struct {
		funcName string
		effects  map[ir.EffectType]bool
	}{}

	for funcName, fn := range irFunctions {
		effects := make(map[ir.EffectType]bool)
		for _, block := range fn.Blocks {
			for _, effect := range block.Effects {
				effects[effect.EffectType] = true
			}
		}

		hasWrite := effects[ir.FILE_WRITE]
		hasReg := effects[ir.REGISTRY_MODIFY]
		hasEnv := effects[ir.ENV_CHECK]

		if hasWrite && hasReg {
			necessary = append(necessary, "FILE_WRITE ∧ REGISTRY_MODIFY in "+funcName)

			if !hasEnv {
				sufficient = append(sufficient, "¬ENV_CHECK in "+funcName)
				candidates = append(candidates, struct {
					funcName string
					effects  map[ir.EffectType]bool
				}{funcName, effects})
			}
		}
	}

	if len(candidates) == 0 {
		return &PredicateResult{
			Satisfied:            false,
			Confidence:           0.0,
			Proof:                map[string]interface{}{"reason": "No function with FILE_WRITE ∧ REGISTRY_MODIFY"},
			NecessaryConditions:  necessary,
			SufficientConditions: sufficient,
		}
	}

	// Select first candidate
	funcName := candidates[0].funcName
	effects := candidates[0].effects

	effectStrs := make([]string, 0, len(effects))
	for e := range effects {
		effectStrs = append(effectStrs, string(e))
	}

	proof := map[string]interface{}{
		"theorem":  "stealth_persistence ⇔ FILE_WRITE ∧ REGISTRY_MODIFY ∧ ¬ENV_CHECK",
		"function": funcName,
		"effects":  effectStrs,
		"stealth":  !effects[ir.ENV_CHECK],
	}

	confidence := 0.85
	if len(sufficient) == 0 {
		confidence = 0.70
	}

	return &PredicateResult{
		Satisfied:            len(sufficient) > 0,
		Confidence:           confidence,
		Proof:                proof,
		NecessaryConditions:  necessary,
		SufficientConditions: sufficient,
	}
}

// PropagationClosurePredicate evaluates propagation closure predicate
func (fp *FormalPredicates) PropagationClosurePredicate(closures map[string]*PropagationClosure, threshold float64) *PredicateResult {
	if len(closures) == 0 {
		return &PredicateResult{
			Satisfied:            false,
			Confidence:           0.0,
			Proof:                map[string]interface{}{"reason": "No propagation closures computed"},
			NecessaryConditions:  []string{},
			SufficientConditions: []string{},
		}
	}

	// Find best closure
	var bestSource string
	var bestClosure *PropagationClosure
	for source, closure := range closures {
		if bestClosure == nil || closure.Coverage > bestClosure.Coverage {
			bestSource = source
			bestClosure = closure
		}
	}

	necessary := []string{}
	sufficient := []string{}

	// Necessary Condition 1: Reachable nodes exist
	if len(bestClosure.ReachableNodes) > 0 {
		necessary = append(necessary, "R("+bestSource+") ≠ ∅ (|R| = "+fmt.Sprintf("%d", len(bestClosure.ReachableNodes))+")")
	}

	// Necessary Condition 2: Reaches write sinks
	if len(bestClosure.WriteSinks) > 0 {
		necessary = append(necessary, "R ∩ W ≠ ∅ (|R ∩ W| = "+fmt.Sprintf("%d", len(bestClosure.WriteSinks))+")")
	}

	// Sufficient Condition 1: Coverage threshold
	if bestClosure.Coverage > threshold {
		sufficient = append(sufficient, "coverage > "+fmt.Sprintf("%.3f", threshold)+" ("+fmt.Sprintf("%.3f", bestClosure.Coverage)+")")
	}

	// Sufficient Condition 2: Multi-hop propagation
	if bestClosure.MaxDepth > 2 {
		sufficient = append(sufficient, "depth > 2 ("+fmt.Sprintf("%d", bestClosure.MaxDepth)+")")
	}

	satisfied := len(sufficient) >= 1

	// Confidence based on coverage and depth
	confidence := math.Min(
		0.5*bestClosure.Coverage/threshold+
			0.3*math.Min(float64(bestClosure.MaxDepth)/5.0, 1.0)+
			0.2*math.Min(float64(bestClosure.PathCount)/10.0, 1.0),
		1.0,
	)

	writeSinkList := make([]string, 0, len(bestClosure.WriteSinks))
	for sink := range bestClosure.WriteSinks {
		writeSinkList = append(writeSinkList, sink)
	}

	reachableList := make([]string, 0, len(bestClosure.ReachableNodes))
	for node := range bestClosure.ReachableNodes {
		reachableList = append(reachableList, node)
	}

	proof := map[string]interface{}{
		"theorem":     "propagation ⇔ |R(v) ∩ W| / |W| > θ",
		"source":      bestSource,
		"reachable":   len(bestClosure.ReachableNodes),
		"write_sinks": writeSinkList,
		"coverage":    bestClosure.Coverage,
		"threshold":   threshold,
		"max_depth":   bestClosure.MaxDepth,
		"path_count":  bestClosure.PathCount,
		"bfs_proof":   "Reachability computed by BFS",
	}

	return &PredicateResult{
		Satisfied:            satisfied,
		Confidence:           confidence,
		Proof:                proof,
		NecessaryConditions:  necessary,
		SufficientConditions: sufficient,
	}
}
