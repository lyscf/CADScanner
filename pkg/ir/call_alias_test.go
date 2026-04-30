package ir

import "testing"

func TestBuildCallGraphResolvesGlobalAliasAssignments(t *testing.T) {
	functions := map[string]*IRFunction{
		"__toplevel__": testIRFunction("__toplevel__", IRInstruction{
			Opcode:   ASSIGN,
			Result:   "alias-fn",
			Operands: []interface{}{"helper-fn"},
		}),
		"caller-fn": testIRFunction("caller-fn", IRInstruction{
			Opcode:   CALL,
			Operands: []interface{}{"alias-fn"},
		}),
		"helper-fn": testIRFunction("helper-fn"),
	}

	callGraph := BuildCallGraph(functions)
	if len(callGraph["caller-fn"]) != 1 || callGraph["caller-fn"][0] != "helper-fn" {
		t.Fatalf("expected alias-fn to resolve to helper-fn, got %v", callGraph["caller-fn"])
	}
}

func TestBuildCallGraphResolvesLocalAliasAssignments(t *testing.T) {
	functions := map[string]*IRFunction{
		"caller-fn": testIRFunction("caller-fn",
			IRInstruction{
				Opcode:   ASSIGN,
				Result:   "local_0",
				Operands: []interface{}{"helper-fn"},
			},
			IRInstruction{
				Opcode:   CALL,
				Operands: []interface{}{"local_0"},
			},
		),
		"helper-fn": testIRFunction("helper-fn"),
	}

	callGraph := BuildCallGraph(functions)
	if len(callGraph["caller-fn"]) != 1 || callGraph["caller-fn"][0] != "helper-fn" {
		t.Fatalf("expected local alias to resolve to helper-fn, got %v", callGraph["caller-fn"])
	}
}

func testIRFunction(name string, instructions ...IRInstruction) *IRFunction {
	fn := &IRFunction{
		Name:       name,
		Params:     []string{},
		Blocks:     make(map[string]*IRBasicBlock),
		EntryBlock: "entry",
		LocalVars:  make(map[string]bool),
		Metadata:   make(map[string]interface{}),
	}
	fn.AddBlock(&IRBasicBlock{
		ID:           "entry",
		Instructions: instructions,
		Effects:      []IREffect{},
		Successors:   []string{},
		Predecessors: []string{},
	})
	return fn
}
