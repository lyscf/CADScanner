package graph

import (
	"fmt"

	"github.com/evilcad/cadscanner/pkg/normalizer"
)

// GraphNode represents a node in the behavior graph
type GraphNode struct {
	ID        string
	Operation normalizer.OperationType
	Function  string
	Arguments []interface{}
	Metadata  map[string]interface{}
	Line      int
}

// GraphEdge represents an edge in the behavior graph
type GraphEdge struct {
	Source   string
	Target   string
	EdgeType string // 'call', 'data_flow', 'control_flow'
}

// BehaviorGraph represents the program execution flow graph
type BehaviorGraph struct {
	Nodes       map[string]*GraphNode
	Edges       []*GraphEdge
	EntryPoints map[string]bool
	Functions   map[string]string // function_name -> node_id
	outEdges    map[string][]string
	inEdges     map[string][]string
}

// NewBehaviorGraph creates a new behavior graph
func NewBehaviorGraph() *BehaviorGraph {
	return &BehaviorGraph{
		Nodes:       make(map[string]*GraphNode),
		Edges:       make([]*GraphEdge, 0),
		EntryPoints: make(map[string]bool),
		Functions:   make(map[string]string),
		outEdges:    make(map[string][]string),
		inEdges:     make(map[string][]string),
	}
}

// AddNode adds a node to the graph
func (bg *BehaviorGraph) AddNode(node *GraphNode) {
	bg.Nodes[node.ID] = node
}

// AddEdge adds an edge to the graph
func (bg *BehaviorGraph) AddEdge(source, target, edgeType string) {
	edge := &GraphEdge{
		Source:   source,
		Target:   target,
		EdgeType: edgeType,
	}
	bg.Edges = append(bg.Edges, edge)
	bg.outEdges[source] = append(bg.outEdges[source], target)
	bg.inEdges[target] = append(bg.inEdges[target], source)
}

// GetNode gets a node by ID
func (bg *BehaviorGraph) GetNode(nodeID string) *GraphNode {
	return bg.Nodes[nodeID]
}

// GetSuccessors gets successor nodes
func (bg *BehaviorGraph) GetSuccessors(nodeID string) []string {
	successors := bg.outEdges[nodeID]
	if len(successors) == 0 {
		return []string{}
	}
	out := make([]string, len(successors))
	copy(out, successors)
	return out
}

// GetPredecessors gets predecessor nodes
func (bg *BehaviorGraph) GetPredecessors(nodeID string) []string {
	predecessors := bg.inEdges[nodeID]
	if len(predecessors) == 0 {
		return []string{}
	}
	out := make([]string, len(predecessors))
	copy(out, predecessors)
	return out
}

// BehaviorGraphBuilder builds behavior graph from normalized AST
type BehaviorGraphBuilder struct {
	graph           *BehaviorGraph
	nodeCounter     int
	currentFunction string
	functionBodies  map[string][]string
}

// NewBehaviorGraphBuilder creates a new behavior graph builder
func NewBehaviorGraphBuilder() *BehaviorGraphBuilder {
	return &BehaviorGraphBuilder{
		graph:          NewBehaviorGraph(),
		nodeCounter:    0,
		functionBodies: make(map[string][]string),
	}
}

// Build builds behavior graph from normalized nodes
func (bgb *BehaviorGraphBuilder) Build(normalized []*normalizer.NormalizedNode) *BehaviorGraph {
	// First pass: create nodes and track functions
	for _, node := range normalized {
		if node.Operation == normalizer.DEFUN {
			bgb.processDefun(node)
		} else {
			bgb.processNode(node)
		}
	}

	// Second pass: create edges
	bgb.createEdges()

	return bgb.graph
}

// processDefun processes a function definition
func (bgb *BehaviorGraphBuilder) processDefun(node *normalizer.NormalizedNode) {
	funcName := "anonymous"
	if len(node.Arguments) > 0 {
		if name, ok := node.Arguments[0].(string); ok {
			funcName = name
		}
	}

	// Create function entry node
	nodeID := bgb.newNodeID()
	funcNode := &GraphNode{
		ID:        nodeID,
		Operation: node.Operation,
		Function:  node.FunctionName,
		Arguments: node.Arguments,
		Metadata:  node.Metadata,
		Line:      node.Line,
	}
	bgb.graph.AddNode(funcNode)
	bgb.graph.Functions[funcName] = nodeID
	bgb.graph.EntryPoints[nodeID] = true

	// Track function body
	bgb.functionBodies[funcName] = make([]string, 0)
	bgb.currentFunction = funcName

	// Process function body
	for i := 2; i < len(node.Arguments); i++ {
		if childNode, ok := node.Arguments[i].(*normalizer.NormalizedNode); ok {
			childID := bgb.processNode(childNode)
			bgb.functionBodies[funcName] = append(bgb.functionBodies[funcName], childID)
		}
	}

	bgb.currentFunction = ""
}

// processNode processes a single node
func (bgb *BehaviorGraphBuilder) processNode(node *normalizer.NormalizedNode) string {
	nodeID := bgb.newNodeID()
	graphNode := &GraphNode{
		ID:        nodeID,
		Operation: node.Operation,
		Function:  node.FunctionName,
		Arguments: node.Arguments,
		Metadata:  node.Metadata,
		Line:      node.Line,
	}
	bgb.graph.AddNode(graphNode)

	// If we're in a function, add to function body
	if bgb.currentFunction != "" {
		bgb.functionBodies[bgb.currentFunction] = append(bgb.functionBodies[bgb.currentFunction], nodeID)
	}

	return nodeID
}

// createEdges creates edges between nodes
func (bgb *BehaviorGraphBuilder) createEdges() {
	// Create control flow edges within functions
	for funcName, bodyNodes := range bgb.functionBodies {
		if len(bodyNodes) < 2 {
			continue
		}

		// Create sequential edges
		for i := 0; i < len(bodyNodes)-1; i++ {
			bgb.graph.AddEdge(bodyNodes[i], bodyNodes[i+1], "control_flow")
		}

		// Mark function entry
		if entryNodeID, ok := bgb.graph.Functions[funcName]; ok {
			if len(bodyNodes) > 0 {
				bgb.graph.AddEdge(entryNodeID, bodyNodes[0], "control_flow")
			}
		}
	}

	// Create call edges for function calls
	for _, node := range bgb.graph.Nodes {
		if node.Operation == normalizer.EVAL || node.Operation == normalizer.LOAD {
			// This is a potential function call
			if len(node.Arguments) > 0 {
				if funcName, ok := node.Arguments[0].(string); ok {
					if targetNodeID, ok := bgb.graph.Functions[funcName]; ok {
						bgb.graph.AddEdge(node.ID, targetNodeID, "call")
					}
				}
			}
		}
	}
}

// newNodeID generates a new node ID
func (bgb *BehaviorGraphBuilder) newNodeID() string {
	id := bgb.nodeCounter
	bgb.nodeCounter++
	return fmt.Sprintf("node_%d", id)
}
