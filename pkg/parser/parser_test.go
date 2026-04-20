package parser

import "testing"

func TestExtractCallsFromNodeDoesNotDuplicateChildCalls(t *testing.T) {
	p := NewFromTokens(nil)

	grandchild := &ASTNode{Type: "call", Value: "grandchild"}
	child := &ASTNode{Type: "call", Value: "child", Children: []*ASTNode{grandchild}}
	root := &ASTNode{Type: "list", Children: []*ASTNode{child}}

	results := p.extractCallsFromNode(root)
	if len(results) != 2 {
		t.Fatalf("extractCallsFromNode returned %d calls, want 2", len(results))
	}
	if results[0] != child {
		t.Fatalf("first extracted call = %v, want child node", results[0])
	}
	if results[1] != grandchild {
		t.Fatalf("second extracted call = %v, want grandchild node", results[1])
	}
}

func TestExtractCallsFromNodeAppliesBudget(t *testing.T) {
	p := NewFromTokens(nil)
	root := &ASTNode{Type: "list"}
	for i := 0; i < maxUnclosedDefunExtractCalls+100; i++ {
		root.Children = append(root.Children, &ASTNode{Type: "call", Value: i})
	}

	results := p.extractCallsFromNode(root)
	if len(results) != maxUnclosedDefunExtractCalls {
		t.Fatalf("extractCallsFromNode returned %d calls, want %d", len(results), maxUnclosedDefunExtractCalls)
	}
}
