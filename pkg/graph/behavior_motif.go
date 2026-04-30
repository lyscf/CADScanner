package graph

import (
	"github.com/evilcad/cadscanner/pkg/ir"
)

// MotifType represents graph motif types
type MotifType string

const (
	MotifCycle           MotifType = "cycle"
	MotifDominator       MotifType = "dominator"
	MotifEffectChain     MotifType = "effect_chain"
	MotifPersistenceLoop MotifType = "persistence_loop"
)

// BehaviorMotif represents graph motif with evidence
type BehaviorMotif struct {
	MotifType  MotifType
	Nodes      []string
	Edges      []Edge
	Effects    []ir.EffectType
	Evidence   map[string]interface{}
	Confidence float64
}

// Edge represents a graph edge
type Edge struct {
	Source string
	Target string
}

// ToDict converts BehaviorMotif to dictionary
func (bm *BehaviorMotif) ToDict() map[string]interface{} {
	edgeDicts := make([]map[string]string, 0, len(bm.Edges))
	for _, edge := range bm.Edges {
		edgeDicts = append(edgeDicts, map[string]string{
			"source": edge.Source,
			"target": edge.Target,
		})
	}

	effectStrs := make([]string, 0, len(bm.Effects))
	for _, e := range bm.Effects {
		effectStrs = append(effectStrs, string(e))
	}

	return map[string]interface{}{
		"type":       string(bm.MotifType),
		"nodes":      bm.Nodes,
		"edges":      edgeDicts,
		"effects":    effectStrs,
		"evidence":   bm.Evidence,
		"confidence": bm.Confidence,
	}
}

// ProofType represents type of proof for behavior synthesis
type ProofType string

const (
	ProofFormal    ProofType = "formal"
	ProofHeuristic ProofType = "heuristic"
	ProofHybrid    ProofType = "hybrid"
)

// BehaviorMotifExtractor extracts behavior motifs from graphs
type BehaviorMotifExtractor struct {
	analyzer    *FormalGraphAnalyzer
	predicates  *FormalPredicates
	irFunctions map[string]*ir.IRFunction
	callGraph   map[string][]string
}

// NewBehaviorMotifExtractor creates a new behavior motif extractor
func NewBehaviorMotifExtractor(irFunctions map[string]*ir.IRFunction, callGraph map[string][]string) *BehaviorMotifExtractor {
	analyzer := NewFormalGraphAnalyzer(irFunctions, callGraph)
	return &BehaviorMotifExtractor{
		analyzer:    analyzer,
		predicates:  NewFormalPredicates(),
		irFunctions: irFunctions,
		callGraph:   callGraph,
	}
}

// Extract extracts behavior motifs from the graph
func (bme *BehaviorMotifExtractor) Extract() []*BehaviorMotif {
	motifs := []*BehaviorMotif{}

	// Detect SCCs first
	sccs := bme.analyzer.DetectSCCs()

	// Extract cycle motifs
	cycleMotifs := bme.extractCycleMotifs(sccs)
	motifs = append(motifs, cycleMotifs...)

	// Extract persistence loop motifs
	persistenceMotifs := bme.extractPersistenceLoopMotifs(sccs)
	motifs = append(motifs, persistenceMotifs...)

	// Extract effect chain motifs
	effectChainMotifs := bme.extractEffectChainMotifs()
	motifs = append(motifs, effectChainMotifs...)

	return motifs
}

// extractCycleMotifs extracts cycle motifs from SCCs
func (bme *BehaviorMotifExtractor) extractCycleMotifs(sccs []*SCCResult) []*BehaviorMotif {
	motifs := []*BehaviorMotif{}

	for _, scc := range sccs {
		if !scc.IsCycle {
			continue
		}

		// Build edges for this SCC
		edges := buildEdgesWithinSet(bme.callGraph, scc.Nodes)

		motif := &BehaviorMotif{
			MotifType: MotifCycle,
			Nodes:     scc.Nodes,
			Edges:     edges,
			Effects:   scc.Effects,
			Evidence: map[string]interface{}{
				"back_edges":     scc.BackEdges,
				"cycle_strength": scc.CycleStrength,
				"entry_points":   scc.EntryPoints,
			},
			Confidence: scc.CycleStrength,
		}

		motifs = append(motifs, motif)
	}

	return motifs
}

// extractPersistenceLoopMotifs extracts persistence loop motifs
func (bme *BehaviorMotifExtractor) extractPersistenceLoopMotifs(sccs []*SCCResult) []*BehaviorMotif {
	motifs := []*BehaviorMotif{}

	for _, scc := range sccs {
		if !scc.IsCycle {
			continue
		}

		// Check if SCC has entry point and FILE_WRITE
		hasEntry := len(scc.EntryPoints) > 0
		hasFileWrite := false
		for _, effect := range scc.Effects {
			if effect == ir.FILE_WRITE {
				hasFileWrite = true
				break
			}
		}

		if hasEntry && hasFileWrite {
			// Build edges
			edges := buildEdgesWithinSet(bme.callGraph, scc.Nodes)

			confidence := 0.5*scc.CycleStrength + 0.3*float64(len(scc.BackEdges))/float64(len(scc.Nodes))
			if len(scc.Nodes) > 0 {
				confidence += 0.2
			}
			if confidence > 1.0 {
				confidence = 1.0
			}

			motif := &BehaviorMotif{
				MotifType: MotifPersistenceLoop,
				Nodes:     scc.Nodes,
				Edges:     edges,
				Effects:   scc.Effects,
				Evidence: map[string]interface{}{
					"entry_point":    hasEntry,
					"file_write":     hasFileWrite,
					"cycle_strength": scc.CycleStrength,
				},
				Confidence: confidence,
			}

			motifs = append(motifs, motif)
		}
	}

	return motifs
}

func buildEdgesWithinSet(callGraph map[string][]string, nodes []string) []Edge {
	nodeSet := makeNodeSet(nodes)
	edges := make([]Edge, 0)
	for _, node := range nodes {
		for _, neighbor := range callGraph[node] {
			if _, ok := nodeSet[neighbor]; ok {
				edges = append(edges, Edge{
					Source: node,
					Target: neighbor,
				})
			}
		}
	}
	return edges
}

// extractEffectChainMotifs extracts effect chain motifs
func (bme *BehaviorMotifExtractor) extractEffectChainMotifs() []*BehaviorMotif {
	motifs := []*BehaviorMotif{}

	// Find chains of effects across function calls
	for funcName, fn := range bme.irFunctions {
		effects := []ir.EffectType{}
		for _, block := range fn.Blocks {
			for _, effect := range block.Effects {
				effects = append(effects, effect.EffectType)
			}
		}

		// Check if function has FILE_WRITE followed by other effects
		if len(effects) >= 2 {
			hasFileWrite := false
			for _, effect := range effects {
				if effect == ir.FILE_WRITE {
					hasFileWrite = true
					break
				}
			}

			if hasFileWrite {
				// Build call chain
				callers := []string{}
				for caller, callees := range bme.callGraph {
					for _, callee := range callees {
						if callee == funcName {
							callers = append(callers, caller)
							break
						}
					}
				}

				edges := []Edge{}
				for _, caller := range callers {
					edges = append(edges, Edge{
						Source: caller,
						Target: funcName,
					})
				}

				effectStrs := make([]string, 0, len(effects))
				for _, e := range effects {
					effectStrs = append(effectStrs, string(e))
				}

				// Calculate confidence based on chain characteristics
				// Base confidence reduced from 0.7 to 0.4 for benign file operations
				confidence := 0.4
				// Increase if multiple callers (more complex propagation)
				if len(callers) > 1 {
					confidence += 0.1 * float64(len(callers)-1)
				}
				// Cap at 0.7
				if confidence > 0.7 {
					confidence = 0.7
				}

				motif := &BehaviorMotif{
					MotifType: MotifEffectChain,
					Nodes:     append([]string{funcName}, callers...),
					Edges:     edges,
					Effects:   effects,
					Evidence: map[string]interface{}{
						"chain_length": len(callers) + 1,
						"effect_count": len(effects),
					},
					Confidence: confidence,
				}

				motifs = append(motifs, motif)
			}
		}
	}

	return motifs
}
