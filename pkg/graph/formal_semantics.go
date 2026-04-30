package graph

import (
	"github.com/evilcad/cadscanner/pkg/ir"
)

// SCCResult represents a Strongly Connected Component with formal proof
type SCCResult struct {
	Nodes         []string
	BackEdges     []BackEdge
	EntryPoints   []string
	Effects       []ir.EffectType
	IsCycle       bool
	CycleStrength float64
}

// BackEdge represents a back-edge in SCC (proof of cycle)
type BackEdge struct {
	Source string
	Target string
}

// ToDict converts SCCResult to dictionary
func (scc *SCCResult) ToDict() map[string]interface{} {
	backEdgeDicts := make([]map[string]string, 0, len(scc.BackEdges))
	for _, be := range scc.BackEdges {
		backEdgeDicts = append(backEdgeDicts, map[string]string{
			"source": be.Source,
			"target": be.Target,
		})
	}

	effectStrs := make([]string, 0, len(scc.Effects))
	for _, e := range scc.Effects {
		effectStrs = append(effectStrs, string(e))
	}

	return map[string]interface{}{
		"nodes":          scc.Nodes,
		"back_edges":     backEdgeDicts,
		"entry_points":   scc.EntryPoints,
		"effects":        effectStrs,
		"is_cycle":       scc.IsCycle,
		"cycle_strength": scc.CycleStrength,
		"formal_proof":   "Tarjan_SCC",
	}
}

// PropagationClosure represents propagation closure with reachability proof
type PropagationClosure struct {
	Source         string
	ReachableNodes map[string]bool
	WriteSinks     map[string]bool
	Coverage       float64
	PathCount      int
	MaxDepth       int
}

// ToDict converts PropagationClosure to dictionary
func (pc *PropagationClosure) ToDict() map[string]interface{} {
	reachableList := make([]string, 0, len(pc.ReachableNodes))
	for node := range pc.ReachableNodes {
		reachableList = append(reachableList, node)
	}

	writeSinkList := make([]string, 0, len(pc.WriteSinks))
	for sink := range pc.WriteSinks {
		writeSinkList = append(writeSinkList, sink)
	}

	return map[string]interface{}{
		"source":          pc.Source,
		"reachable_count": len(reachableList),
		"write_sinks":     writeSinkList,
		"coverage":        pc.Coverage,
		"path_count":      pc.PathCount,
		"max_depth":       pc.MaxDepth,
		"formal_proof":    "reachability_closure",
	}
}

// FormalGraphAnalyzer performs formal graph analysis with mathematical proofs
type FormalGraphAnalyzer struct {
	IRFunctions         map[string]*ir.IRFunction
	CallGraph           map[string][]string
	ReverseCallGraph    map[string][]string
	SCCs                []*SCCResult
	PropagationClosures map[string]*PropagationClosure
}

// NewFormalGraphAnalyzer creates a new formal graph analyzer
func NewFormalGraphAnalyzer(irFunctions map[string]*ir.IRFunction, callGraph map[string][]string) *FormalGraphAnalyzer {
	analyzer := &FormalGraphAnalyzer{
		IRFunctions:         irFunctions,
		CallGraph:           callGraph,
		ReverseCallGraph:    make(map[string][]string),
		SCCs:                make([]*SCCResult, 0),
		PropagationClosures: make(map[string]*PropagationClosure),
	}
	analyzer.buildReverseCallGraph()
	return analyzer
}

// buildReverseCallGraph builds reverse call graph (callee -> callers)
func (fga *FormalGraphAnalyzer) buildReverseCallGraph() {
	for caller, callees := range fga.CallGraph {
		for _, callee := range callees {
			if fga.ReverseCallGraph[callee] == nil {
				fga.ReverseCallGraph[callee] = []string{}
			}
			fga.ReverseCallGraph[callee] = append(fga.ReverseCallGraph[callee], caller)
		}
	}
}

// DetectSCCs detects Strongly Connected Components using Tarjan's algorithm
func (fga *FormalGraphAnalyzer) DetectSCCs() []*SCCResult {
	indexCounter := 0
	stack := []string{}
	lowlinks := make(map[string]int)
	index := make(map[string]int)
	onStack := make(map[string]bool)
	sccs := [][]string{}

	var strongconnect func(node string)
	strongconnect = func(node string) {
		index[node] = indexCounter
		lowlinks[node] = indexCounter
		indexCounter++
		stack = append(stack, node)
		onStack[node] = true

		// Consider successors
		for _, successor := range fga.CallGraph[node] {
			if _, exists := index[successor]; !exists {
				strongconnect(successor)
				if lowlinks[successor] < lowlinks[node] {
					lowlinks[node] = lowlinks[successor]
				}
			} else if onStack[successor] {
				if index[successor] < lowlinks[node] {
					lowlinks[node] = index[successor]
				}
			}
		}

		// Root node: pop SCC
		if lowlinks[node] == index[node] {
			scc := []string{}
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == node {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}

	// Run Tarjan's algorithm
	for node := range fga.IRFunctions {
		if _, exists := index[node]; !exists {
			strongconnect(node)
		}
	}

	// Process SCCs
	fga.SCCs = make([]*SCCResult, 0, len(sccs))
	for _, scc := range sccs {
		if len(scc) > 1 { // Only cycles
			sccResult := fga.analyzeSCC(scc)
			fga.SCCs = append(fga.SCCs, sccResult)
		}
	}

	return fga.SCCs
}

// analyzeSCC analyzes SCC and computes metrics
func (fga *FormalGraphAnalyzer) analyzeSCC(scc []string) *SCCResult {
	sccSet := makeNodeSet(scc)
	// Find back-edges (proof of cycle)
	backEdges := fga.findBackEdges(scc, sccSet)

	// Find entry points (nodes reachable from outside)
	entryPoints := []string{}
	for _, node := range scc {
		// Check if any caller is outside SCC
		callers := fga.ReverseCallGraph[node]
		for _, caller := range callers {
			if _, found := sccSet[caller]; !found {
				entryPoints = append(entryPoints, node)
				break
			}
		}
	}

	// Collect effects
	effects := fga.getEffectsInFunctions(scc)

	// Compute cycle strength (edge density)
	edgeCount := 0
	for _, node := range scc {
		for _, neighbor := range fga.CallGraph[node] {
			if _, ok := sccSet[neighbor]; ok {
				edgeCount++
			}
		}
	}
	maxEdges := len(scc) * (len(scc) - 1)
	cycleStrength := float64(edgeCount) / float64(maxEdges)
	if maxEdges == 0 {
		cycleStrength = 0.0
	}

	return &SCCResult{
		Nodes:         scc,
		BackEdges:     backEdges,
		EntryPoints:   entryPoints,
		Effects:       effects,
		IsCycle:       len(backEdges) > 0,
		CycleStrength: cycleStrength,
	}
}

// findBackEdges finds back-edges in SCC (formal proof of cycle)
func (fga *FormalGraphAnalyzer) findBackEdges(scc []string, sccSet map[string]struct{}) []BackEdge {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	backEdges := []BackEdge{}

	var dfs func(node string)
	dfs = func(node string) {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range fga.CallGraph[node] {
			if _, ok := sccSet[neighbor]; !ok {
				continue
			}

			if recStack[neighbor] {
				// Back-edge found
				backEdges = append(backEdges, BackEdge{
					Source: node,
					Target: neighbor,
				})
			} else if !visited[neighbor] {
				dfs(neighbor)
			}
		}

		delete(recStack, node)
	}

	for _, node := range scc {
		if !visited[node] {
			dfs(node)
		}
	}

	return backEdges
}

func makeNodeSet(nodes []string) map[string]struct{} {
	set := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		set[node] = struct{}{}
	}
	return set
}

// ComputePropagationClosure computes propagation closure from source
func (fga *FormalGraphAnalyzer) ComputePropagationClosure(source string) *PropagationClosure {
	reachable := make(map[string]bool)
	queue := []string{source}
	visited := make(map[string]bool)
	pathCount := 0
	maxDepth := 0
	depthMap := make(map[string]int)
	depthMap[source] = 0

	// BFS for reachability
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if visited[node] {
			continue
		}
		visited[node] = true
		reachable[node] = true

		currentDepth := depthMap[node]
		if currentDepth > maxDepth {
			maxDepth = currentDepth
		}

		for _, neighbor := range fga.CallGraph[node] {
			if !visited[neighbor] {
				queue = append(queue, neighbor)
				depthMap[neighbor] = currentDepth + 1
				pathCount++
			}
		}
	}

	// Find write sinks
	writeSinks := make(map[string]bool)
	allWriteSinks := make(map[string]bool)

	for funcName, fn := range fga.IRFunctions {
		// Check if function has FILE_WRITE effects
		hasWrite := false
		for _, block := range fn.Blocks {
			for _, effect := range block.Effects {
				if effect.EffectType == ir.FILE_WRITE {
					hasWrite = true
					break
				}
			}
			if hasWrite {
				break
			}
		}

		if hasWrite {
			allWriteSinks[funcName] = true
			if reachable[funcName] {
				writeSinks[funcName] = true
			}
		}
	}

	// Compute coverage
	coverage := 0.0
	if len(allWriteSinks) > 0 {
		coverage = float64(len(writeSinks)) / float64(len(allWriteSinks))
	}

	closure := &PropagationClosure{
		Source:         source,
		ReachableNodes: reachable,
		WriteSinks:     writeSinks,
		Coverage:       coverage,
		PathCount:      pathCount,
		MaxDepth:       maxDepth,
	}

	fga.PropagationClosures[source] = closure
	return closure
}

// getEffectsInFunctions gets all effects in multiple functions
func (fga *FormalGraphAnalyzer) getEffectsInFunctions(funcNames []string) []ir.EffectType {
	allEffects := []ir.EffectType{}
	effectSet := make(map[ir.EffectType]bool)

	for _, funcName := range funcNames {
		if fn, ok := fga.IRFunctions[funcName]; ok {
			for _, block := range fn.Blocks {
				for _, effect := range block.Effects {
					if !effectSet[effect.EffectType] {
						allEffects = append(allEffects, effect.EffectType)
						effectSet[effect.EffectType] = true
					}
				}
			}
		}
	}

	return allEffects
}
