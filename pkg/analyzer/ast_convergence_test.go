package analyzer

import (
	"testing"

	"github.com/evilcad/cadscanner/pkg/parser"
)

func TestConvergeASTNodesLimitsAdjacentDuplicates(t *testing.T) {
	node := &parser.ASTNode{
		Type:  "call",
		Value: "setq",
		Children: []*parser.ASTNode{
			{Type: "symbol", Value: "flagx"},
			{Type: "symbol", Value: "t"},
		},
	}

	nodes := make([]*parser.ASTNode, 0, maxAdjacentDuplicateAST+3)
	for i := 0; i < maxAdjacentDuplicateAST+3; i++ {
		nodes = append(nodes, node)
	}

	converged := convergeASTNodes(nodes)
	if len(converged) != maxAdjacentDuplicateAST {
		t.Fatalf("converged len = %d, want %d", len(converged), maxAdjacentDuplicateAST)
	}
}

func TestConvergeASTNodesPreservesDistinctRuns(t *testing.T) {
	a := &parser.ASTNode{Type: "call", Value: "setq", Children: []*parser.ASTNode{{Type: "symbol", Value: "a"}}}
	b := &parser.ASTNode{Type: "call", Value: "setq", Children: []*parser.ASTNode{{Type: "symbol", Value: "b"}}}

	nodes := []*parser.ASTNode{a, a, b, b, a}
	converged := convergeASTNodes(nodes)

	if len(converged) != len(nodes) {
		t.Fatalf("converged len = %d, want %d", len(converged), len(nodes))
	}
}

func TestConvergeASTNodesLimitsTotalDuplicateSignatures(t *testing.T) {
	a := &parser.ASTNode{Type: "call", Value: "setq", Children: []*parser.ASTNode{{Type: "symbol", Value: "a"}}}
	b := &parser.ASTNode{Type: "call", Value: "load", Children: []*parser.ASTNode{{Type: "string", Value: "x"}}}

	nodes := make([]*parser.ASTNode, 0, maxTotalDuplicateAST*3)
	for i := 0; i < maxTotalDuplicateAST*2; i++ {
		nodes = append(nodes, a)
		if i < maxTotalDuplicateAST {
			nodes = append(nodes, b)
		}
	}

	converged := convergeASTNodes(nodes)
	countA := 0
	countB := 0
	for _, node := range converged {
		switch node {
		case a:
			countA++
		case b:
			countB++
		}
	}

	if countA != maxTotalDuplicateAST {
		t.Fatalf("countA = %d, want %d", countA, maxTotalDuplicateAST)
	}
	if countB != maxTotalDuplicateAST {
		t.Fatalf("countB = %d, want %d", countB, maxTotalDuplicateAST)
	}
}
