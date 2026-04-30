package graph

import "testing"

func TestBehaviorGraphUsesAdjacencyIndexesForNeighbors(t *testing.T) {
	bg := NewBehaviorGraph()
	bg.AddNode(&GraphNode{ID: "a"})
	bg.AddNode(&GraphNode{ID: "b"})
	bg.AddNode(&GraphNode{ID: "c"})

	bg.AddEdge("a", "b", "control_flow")
	bg.AddEdge("a", "c", "call")
	bg.AddEdge("b", "c", "control_flow")

	successors := bg.GetSuccessors("a")
	if len(successors) != 2 || successors[0] != "b" || successors[1] != "c" {
		t.Fatalf("unexpected successors for a: %v", successors)
	}

	predecessors := bg.GetPredecessors("c")
	if len(predecessors) != 2 || predecessors[0] != "a" || predecessors[1] != "b" {
		t.Fatalf("unexpected predecessors for c: %v", predecessors)
	}
}

func TestBehaviorGraphNeighborResultsAreDefensiveCopies(t *testing.T) {
	bg := NewBehaviorGraph()
	bg.AddNode(&GraphNode{ID: "a"})
	bg.AddNode(&GraphNode{ID: "b"})
	bg.AddEdge("a", "b", "control_flow")

	successors := bg.GetSuccessors("a")
	successors[0] = "mutated"

	again := bg.GetSuccessors("a")
	if len(again) != 1 || again[0] != "b" {
		t.Fatalf("expected stored adjacency to remain unchanged, got %v", again)
	}
}
