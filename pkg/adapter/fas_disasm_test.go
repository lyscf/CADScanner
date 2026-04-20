package adapter

import (
	"strings"
	"testing"
)

func TestDisassemblerRecoversFunctionFrameMetadata(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x01, 0x00, 0x00, 0x00, 0x00, // FUNC nargs=1 idx=0 flags=0
		0x18, 0x03, 0x00, // INIT_ARGS frame=3
		0x05, 0x00, 0x00, // LOAD_LVAR arg_0
		0x35, 0x01, 0x01, 0x00, 0x00, // CALL nargs=1 idx=1 flags=0
		0x32, 0x02, // SETQ slot 2 -> local_1
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"demo-fn", "helper-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}

	fn := functions[0]
	if fn.Name != "demo-fn" {
		t.Fatalf("expected recovered function name demo-fn, got %q", fn.Name)
	}
	if fn.NumOfArgs != 1 {
		t.Fatalf("expected 1 arg, got %d", fn.NumOfArgs)
	}
	if fn.FrameSize != 3 {
		t.Fatalf("expected frame size 3, got %d", fn.FrameSize)
	}
	if fn.VarsCount != 2 {
		t.Fatalf("expected vars count 2, got %d", fn.VarsCount)
	}
	if fn.EndOffset < fn.StartOffset {
		t.Fatalf("expected valid function offsets, start=%d end=%d", fn.StartOffset, fn.EndOffset)
	}
	if len(fn.Calls) != 1 || fn.Calls[0] != "helper-fn" {
		t.Fatalf("expected recovered call to helper-fn, got %v", fn.Calls)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(load-lvar arg_0)") {
		t.Fatalf("expected argument slot rendering in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(setq local_1 (helper-fn arg_0))") {
		t.Fatalf("expected local slot assignment rendering in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "calls=[helper-fn]") {
		t.Fatalf("expected recovered function call list in pseudo lisp, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecoversDefunHeaderMetadata(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x14, 0x02, 0x01, 0x03, 0x01, // DEFUN locals=2 args=1..3 gc=1
		0x05, 0x00, 0x00, // LOAD_LVAR arg_0
		0x5D, 0x02, 0x00, // SETQ_LVAR local_1
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}

	fn := functions[0]
	if fn.Kind != "defun" {
		t.Fatalf("expected kind defun, got %q", fn.Kind)
	}
	if fn.NumOfArgs != 1 || fn.MaxArgs != 3 {
		t.Fatalf("expected arg range 1..3, got %d..%d", fn.NumOfArgs, fn.MaxArgs)
	}
	if fn.VarsCount != 2 {
		t.Fatalf("expected 2 locals, got %d", fn.VarsCount)
	}
	if !fn.GC {
		t.Fatalf("expected GC bit to be set")
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(defun fn_0004 (arg_0))") {
		t.Fatalf("expected defun header rendering, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(setq arg_0 ") && !strings.Contains(pseudo, "(setq local_1 ") {
		t.Fatalf("expected local slot rendering, got:\n%s", pseudo)
	}
}

func TestDisassemblerUsesSignedBranchOffsets(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x0F, 0xFD, 0xFF, // JMP -3
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(instrs))
	}
	if instrs[0].Operands[0] != -3 {
		t.Fatalf("expected signed jump offset -3, got %d", instrs[0].Operands[0])
	}
	if !strings.Contains(instrs[0].Comment, "target=0004") {
		t.Fatalf("expected computed jump target in comment, got %q", instrs[0].Comment)
	}
}

func TestDisassemblerRecoversFunctionNameFromSymbolBinding(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x03, 0x00, 0x00, // PUSH_SYM 0 => named-fn
		0x14, 0x00, 0x01, 0x01, 0x00, // DEFUN locals=0 args=1..1 gc=0
		0x1A, 0x00, 0x00, // SETQ_DEFUN 0 => bind to named-fn
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"named-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "named-fn" {
		t.Fatalf("expected recovered function name named-fn, got %q", functions[0].Name)
	}
	if functions[0].SymbolIndex != 0 {
		t.Fatalf("expected symbol index 0, got %d", functions[0].SymbolIndex)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(defun named-fn (arg_0))") {
		t.Fatalf("expected named defun rendering, got:\n%s", pseudo)
	}
}

func TestScoreRecoveredFunctionNameCandidateFromBodyKeepsHelperSuffixes(t *testing.T) {
	name, score := scoreRecoveredFunctionNameCandidateFromBody("ASSOC++", 0)
	if name != "assoc++" {
		t.Fatalf("expected assoc++ helper candidate, got %q", name)
	}
	if score < 60 {
		t.Fatalf("expected strong helper score, got %d", score)
	}
}

func TestDisassemblerSynthesizesHelperNameFromBodyStrings(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00,
		0x09, 0x01, 0x00,
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, []string{"ASSOC++", "THELIST"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "assoc++" {
		t.Fatalf("expected synthesized helper name assoc++, got %q", functions[0].Name)
	}
}

func TestDisassemblerSynthesizesAssocStarFromStructure(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x05, 0x00,
		0x03, 0x00, 0x00,
		0x03, 0x01, 0x00,
		0x16,
	}

	disasm := NewDisassembler(bytecode, []string{"subst", "cons"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "assoc*" {
		t.Fatalf("expected synthesized helper name assoc*, got %q", functions[0].Name)
	}
}

func TestDisassemblerSynthesizesJdCarCdrFromStructure(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x02, 0x00,
		0x34, 0x01,
		0x28,
		0x34, 0x01,
		0x29,
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "jd:carcdr" {
		t.Fatalf("expected synthesized helper name jd:carcdr, got %q", functions[0].Name)
	}
}

func TestDisassemblerSynthesizesMakeVarNotNilFromStructure(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x02, 0x00,
		0x09, 0x00, 0x00,
		0x09, 0x01, 0x00,
		0x34, 0x01,
		0x34, 0x01,
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, []string{"VARIABLENAME", "VALUETOSETIFEMPTY"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "makevarnotnil" {
		t.Fatalf("expected synthesized helper name makevarnotnil, got %q", functions[0].Name)
	}
}

func TestDisassemblerSynthesizesListSearchFromStructure(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x05, 0x00,
		0x09, 0x00, 0x00,
		0x09, 0x01, 0x00,
		0x09, 0x02, 0x00,
		0x34, 0x01,
		0x4D,
		0x4F,
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, []string{"criteria", "thelist", "length"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "listsearch" {
		t.Fatalf("expected synthesized helper name listsearch, got %q", functions[0].Name)
	}
}

func TestDisassemblerSynthesizesSortFromStructure(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x18, 0x02, 0x00,
		0x09, 0x00, 0x00,
		0x09, 0x01, 0x00,
		0x09, 0x02, 0x00,
		0x09, 0x03, 0x00,
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, []string{"thelist", "functionname", "mapcar", "nth"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	if functions[0].Name != "sort" {
		t.Fatalf("expected synthesized helper name sort, got %q", functions[0].Name)
	}
}

func TestCanonicalizeResourceSymbolKeepsPlusHelpers(t *testing.T) {
	if got := canonicalizeResourceSymbol("ASSOC+QTY"); got != "assoc+qty" {
		t.Fatalf("expected assoc+qty, got %q", got)
	}
}

func TestCanonicalizeResourceSymbolNormalizesKnownHelperSuffixVariants(t *testing.T) {
	if got := canonicalizeResourceSymbol("UNQTYLISTU"); got != "unqtylist" {
		t.Fatalf("expected unqtylist, got %q", got)
	}
	if got := sanitizeHelperFunctionName("SORTU"); got != "sort" {
		t.Fatalf("expected sort, got %q", got)
	}
}

func TestPromoteKnownLambdaHelpersRenamesUnQtyListShape(t *testing.T) {
	disasm := NewDisassembler(nil, nil, []string{"UNQTYLIST"})
	fn := &FASFunction{
		Name:      "c:testfunctions",
		Kind:      "func",
		IsLambda:  true,
		NumOfArgs: 1,
		VarsCount: 2,
		Calls:     []string{"jd:displayassoclist"},
		StartOffset: 0,
		EndOffset:   2,
	}
	disasm.functions = []*FASFunction{fn}
	disasm.instructions = []Instruction{
		{Offset: 0, Name: "FUNC"},
		{Offset: 1, Name: "PUSH_CONST", Operands: []int{0}},
		{Offset: 2, Name: "END_DEFUN"},
	}

	disasm.promoteKnownLambdaHelpers()

	if fn.Name != "unqtylist" {
		t.Fatalf("expected unqtylist, got %q", fn.Name)
	}
}

func TestPromoteKnownLambdaHelpersRenamesUnQtyListByContext(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)
	qtyList := &FASFunction{Name: "qtylist", Kind: "defun"}
	fn := &FASFunction{
		Name:        "c:testfunctions",
		Kind:        "func",
		IsLambda:    true,
		NumOfArgs:   1,
		VarsCount:   2,
		Calls:       []string{"jd:displayassoclist"},
		StartOffset: 10,
		EndOffset:   12,
	}
	resetCutList := &FASFunction{Name: "resetcutlist", Kind: "defun"}
	disasm.functions = []*FASFunction{qtyList, fn, resetCutList}

	disasm.promoteKnownLambdaHelpers()

	if fn.Name != "unqtylist" {
		t.Fatalf("expected unqtylist, got %q", fn.Name)
	}
}

func TestPromoteKnownLambdaHelpersRenamesAssocPlusQtyShape(t *testing.T) {
	disasm := NewDisassembler(nil, nil, []string{"ASSOC+QTY"})
	prev := &FASFunction{
		Name:      "fn_07B1",
		Kind:      "defun",
		NumOfArgs: 1,
		VarsCount: 1,
	}
	fn := &FASFunction{
		Name:        "c:testfunctions",
		Kind:        "func",
		IsLambda:    true,
		NumOfArgs:   1,
		VarsCount:   0,
		Calls:       []string{"vl-remove"},
		StartOffset: 10,
		EndOffset:   12,
	}
	disasm.functions = []*FASFunction{prev, fn}
	disasm.instructions = []Instruction{
		{Offset: 10, Name: "FUNC"},
		{Offset: 11, Name: "PUSH_CONST", Operands: []int{0}},
		{Offset: 12, Name: "END_DEFUN"},
	}

	disasm.promoteKnownLambdaHelpers()

	if fn.Name != "assoc+qty" {
		t.Fatalf("expected assoc+qty, got %q", fn.Name)
	}
}

func TestDisassemblerSynthesizesDisplayCountFromStructure(t *testing.T) {
	disasm := NewDisassembler(nil, []string{"princ"}, []string{"\n"})
	fn := &FASFunction{
		Name:        "fn_0788",
		Kind:        "defun",
		NumOfArgs:   1,
		VarsCount:   1,
		StartOffset: 0,
		EndOffset:   2,
		Calls:       []string{"princ"},
	}
	disasm.functions = []*FASFunction{fn}
	disasm.instructions = []Instruction{
		{Offset: 0, Name: "PUSH_CONST", Operands: []int{0}},
		{Offset: 1, Name: "CALL", Operands: []int{1, 0, 0}},
		{Offset: 2, Name: "END_DEFUN"},
	}

	disasm.synthesizeFunctionNames()

	if fn.Name != "displaycount" {
		t.Fatalf("expected displaycount, got %q", fn.Name)
	}
}

func TestDisassemblerRecoversStackIndirectCallHints(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC nargs=0 idx=0 flags=0
		0x03, 0x01, 0x00, // PUSH_SYM 1 => indirect-target
		0x2E, 0x00, // STACK_CALL_JMP argc=0
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"caller-fn", "indirect-target"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	fn := functions[0]
	if len(fn.IndirectCalls) != 1 || fn.IndirectCalls[0] != "indirect-target" {
		t.Fatalf("expected one indirect call to indirect-target, got %v", fn.IndirectCalls)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "indirect_calls=[indirect-target]") {
		t.Fatalf("expected indirect call list in pseudo lisp, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecoversBasicBlockStartsAndEdges(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC nargs=0 idx=0 flags=0
		0x0D, 0x03, 0x00, // BR_IF_FALSE +3
		0x01, // PUSH_NIL (fallthrough target)
		0x16, // END_DEFUN
		0x02, // PUSH_T (branch target)
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"cfg-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	functions := disasm.Functions()
	if len(functions) != 1 {
		t.Fatalf("expected 1 recovered function, got %d", len(functions))
	}
	fn := functions[0]
	if len(fn.BlockStarts) < 2 {
		t.Fatalf("expected recovered block starts, got %v", fn.BlockStarts)
	}
	if len(fn.ControlEdges) < 2 {
		t.Fatalf("expected recovered control edges, got %v", fn.ControlEdges)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "block_starts=") {
		t.Fatalf("expected block start rendering, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "edges=") {
		t.Fatalf("expected edge rendering, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecoversGlobalBindingFlow(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x03, 0x01, 0x00, // PUSH_SYM 1 => helper-fn
		0x06, 0x00, 0x00, // SETQ_GVAR 0 => alias-fn = helper-fn
		0x0C, 0x00, 0x00, // PUSH_GVAR 0
	}

	disasm := NewDisassembler(bytecode, []string{"alias-fn", "helper-fn"}, nil)
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) < 3 {
		t.Fatalf("expected at least 3 instructions, got %d", len(instrs))
	}
	if !strings.Contains(instrs[1].Comment, "bind-global alias-fn=helper-fn") {
		t.Fatalf("expected global binding comment, got %q", instrs[1].Comment)
	}
	if !strings.Contains(instrs[2].Comment, "global alias-fn -> helper-fn") {
		t.Fatalf("expected global dereference comment, got %q", instrs[2].Comment)
	}
}

func TestDisassemblerSnapshotsBindingValuesPerInstruction(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x09, 0x00, 0x00, // PUSH_CONST 0 => first
		0x06, 0x00, 0x00, // SETQ_GVAR 0
		0x09, 0x01, 0x00, // PUSH_CONST 1 => second
		0x06, 0x00, 0x00, // SETQ_GVAR 0
		0x0C, 0x00, 0x00, // PUSH_GVAR 0
	}

	disasm := NewDisassembler(bytecode, []string{"alias"}, []string{"first", "second"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'alias \"first\")") {
		t.Fatalf("expected first assignment snapshot in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(setq 'alias \"second\")") {
		t.Fatalf("expected second assignment snapshot in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(push-gvar alias ; => \"second\")") {
		t.Fatalf("expected latest dereference snapshot in pseudo lisp, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecognizesOrJmpAsWideConditionalBranch(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x68, 0x04, 0x00, 0x00, 0x00, // OR_JMP +4
		0x01, // PUSH_NIL (fallthrough)
		0x16, // END_DEFUN
		0x02, // PUSH_T (target)
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) == 0 || instrs[0].Name != "OR_JMP" {
		t.Fatalf("expected first instruction to decode as OR_JMP, got %#v", instrs)
	}
	if instrs[0].Operands[0] != 4 {
		t.Fatalf("expected OR_JMP signed delta 4, got %d", instrs[0].Operands[0])
	}
	if !strings.Contains(instrs[0].Comment, "target=000D") {
		t.Fatalf("expected OR_JMP target comment, got %q", instrs[0].Comment)
	}
}

func TestDisassemblerRecognizesCallByOffset(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x14, 0x00, 0x02, 0x02, 0x00, // DEFUN argc=2..2
		0x19, 0x00, 0x00, // CLEAR_ARGS 0 (filler)
		0x16,             // END_DEFUN
		0x09, 0x00, 0x00, // PUSH_CONST 0 => arg
		0x5F, 0x01, 0x04, 0x00, 0x00, 0x00, // CALL_BY_OFFSET argc=1 target=0x0004
	}

	disasm := NewDisassembler(bytecode, nil, []string{"arg"})
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) < 2 || instrs[len(instrs)-1].Name != "CALL_BY_OFFSET" {
		t.Fatalf("expected CALL_BY_OFFSET, got %#v", instrs)
	}
	if !strings.Contains(instrs[len(instrs)-1].Comment, "call-by-offset fn_0004 argc=1") {
		t.Fatalf("expected call-by-offset comment, got %q", instrs[len(instrs)-1].Comment)
	}
	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(call-by-offset fn_0004 \"arg\")") {
		t.Fatalf("expected call-by-offset pseudo output, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecognizesFixnumBinaryOps(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x33, 0x01, 0x00, 0x00, 0x00, // PUSH_INT32 1
		0x33, 0x02, 0x00, 0x00, 0x00, // PUSH_INT32 2
		0x4B, // LE_FIXNUM
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) < 3 || instrs[2].Name != "LE_FIXNUM" {
		t.Fatalf("expected LE_FIXNUM, got %#v", instrs)
	}
	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(<= 1 2)") {
		t.Fatalf("expected fixnum op pseudo output, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersUnaryAndShortCircuitOperands(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x33, 0x03, 0x00, 0x00, 0x00, // PUSH_INT32 3
		0x50,                         // DEC1
		0x68, 0x01, 0x00, 0x00, 0x00, // OR_JMP +1
		0x02, // PUSH_T
	}

	disasm := NewDisassembler(bytecode, nil, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(1- 3)") {
		t.Fatalf("expected unary operand rendering, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(or-jmp (1- 3) <target>)") {
		t.Fatalf("expected OR_JMP condition rendering, got:\n%s", pseudo)
	}
}

func TestDisassemblerSynthesizesEndOffsetForUnclosedFunctions(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC at 0004
		0x01,                               // PUSH_NIL
		0x51, 0x00, 0x01, 0x00, 0x00, 0x00, // FUNC at 000B
		0x02, // PUSH_T
	}

	disasm := NewDisassembler(bytecode, []string{"fn0", "fn1"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	fns := disasm.Functions()
	if len(fns) != 2 {
		t.Fatalf("expected 2 functions, got %d", len(fns))
	}
	if fns[0].EndOffset != 0x000A {
		t.Fatalf("expected first function synthetic end at 000A, got %04X", fns[0].EndOffset)
	}
	if fns[1].EndOffset < fns[1].StartOffset {
		t.Fatalf("expected second function synthetic end >= start, got start=%04X end=%04X", fns[1].StartOffset, fns[1].EndOffset)
	}
}

func TestDisassemblerUsesResolvedValueForPushSym(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x09, 0x00, 0x00, // PUSH_CONST 0 => [RN
		0x06, 0x00, 0x00, // SETQ_GVAR 0
		0x03, 0x00, 0x00, // PUSH_SYM 0
		0x50, // DEC1
	}

	disasm := NewDisassembler(bytecode, []string{"tag"}, []string{"[RN"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(push-sym tag ; => \"[RN\")") {
		t.Fatalf("expected PUSH_SYM to render resolved binding, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(1- \"[RN\")") {
		t.Fatalf("expected downstream unary op to use resolved binding, got:\n%s", pseudo)
	}
}

func TestDisassemblerRecoversLocalSlotBindingFlow(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC caller-fn
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x5D, 0x00, 0x00, // SETQ_LVAR arg/local slot 0
		0x05, 0x00, 0x00, // LOAD_LVAR 0
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"caller-fn", "helper-fn"}, nil)
	instrs, err := disasm.Disassemble()
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(instrs) < 4 {
		t.Fatalf("expected at least 4 instructions, got %d", len(instrs))
	}
	if !strings.Contains(instrs[3].Comment, "-> helper-fn") {
		t.Fatalf("expected slot binding comment on load, got %q", instrs[3].Comment)
	}
}

func TestDisassemblerExportsRecoveredBindings(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x06, 0x00, 0x00, // SETQ_GVAR alias-fn = helper-fn
		0x51, 0x00, 0x02, 0x00, 0x00, 0x00, // FUNC caller-fn
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x5D, 0x00, 0x00, // SETQ_LVAR slot0 = helper-fn
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"alias-fn", "helper-fn", "caller-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	bindings := disasm.Bindings()
	if len(bindings) < 2 {
		t.Fatalf("expected at least 2 bindings, got %d", len(bindings))
	}

	foundGlobal := false
	foundSlot := false
	for _, b := range bindings {
		if b.Scope == "global" && b.Name == "alias-fn" && b.Value == "helper-fn" {
			foundGlobal = true
		}
		if b.Scope == "slot" && b.Value == "helper-fn" {
			foundSlot = true
		}
	}
	if !foundGlobal {
		t.Fatalf("expected exported global binding, got %+v", bindings)
	}
	if !foundSlot {
		t.Fatalf("expected exported slot binding, got %+v", bindings)
	}
}

func TestDisassemblerRendersRecoveredBindingsInPseudoLisp(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x06, 0x00, 0x00, // SETQ_GVAR alias-fn = helper-fn
		0x0C, 0x00, 0x00, // PUSH_GVAR alias-fn
		0x51, 0x00, 0x02, 0x00, 0x00, 0x00, // FUNC caller-fn
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x5D, 0x00, 0x00, // SETQ_LVAR slot0 = helper-fn
		0x05, 0x00, 0x00, // LOAD_LVAR slot0
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"alias-fn", "helper-fn", "caller-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'alias-fn 'helper-fn)") {
		t.Fatalf("expected rendered global binding in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(push-gvar alias-fn ; => 'helper-fn)") {
		t.Fatalf("expected rendered global dereference in pseudo lisp, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(load-lvar local_0 ; => 'helper-fn)") {
		t.Fatalf("expected rendered local binding in pseudo lisp, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersRecoveredCallArguments(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x06, 0x00, 0x00, // SETQ_GVAR alias-fn = helper-fn
		0x51, 0x00, 0x02, 0x00, 0x00, 0x00, // FUNC caller-fn
		0x0C, 0x00, 0x00, // PUSH_GVAR alias-fn
		0x03, 0x01, 0x00, // PUSH_SYM helper-fn
		0x5D, 0x00, 0x00, // SETQ_LVAR slot0 = helper-fn
		0x05, 0x00, 0x00, // LOAD_LVAR slot0
		0x35, 0x02, 0x03, 0x00, 0x00, // CALL target-fn with 2 args
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"alias-fn", "helper-fn", "caller-fn", "target-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(target-fn 'helper-fn 'helper-fn)") {
		t.Fatalf("expected rendered call arguments in pseudo lisp, got:\n%s", pseudo)
	}
}

func TestDisassemblerReducesCallIntoAssignment(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x09, 0x00, 0x00, // PUSH_CONST acad.dcl
		0x35, 0x01, 0x01, 0x00, 0x00, // CALL dlbsf argc=1
		0x06, 0x00, 0x00, // SETQ_GVAR OPEN
	}

	disasm := NewDisassembler(bytecode, []string{"OPEN", "dlbsf"}, []string{"acad.dcl"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'open (dlbsf \"acad.dcl\"))") {
		t.Fatalf("expected reduced call assignment, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersBlockLabelsAndBranchTargets(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC branch-fn
		0x0D, 0x03, 0x00, // BR_IF_FALSE +3
		0x01, // PUSH_NIL
		0x16, // END_DEFUN
		0x02, // PUSH_T
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"branch-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, ";; <branch-fn_block_0004>") {
		t.Fatalf("expected entry block label, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "branch-fn_block_0010") {
		t.Fatalf("expected labeled branch target, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(if (not arg) branch-fn_block_0010 branch-fn_block_000D)") {
		t.Fatalf("expected branch to render target and fallthrough labels, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersGotoForUnconditionalJump(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC jump-fn
		0x0F, 0x02, 0x00, // JMP +2
		0x01, // PUSH_NIL
		0x16, // END_DEFUN
		0x02, // PUSH_T
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"jump-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(goto jump-fn_block_000F)") {
		t.Fatalf("expected goto rendering for unconditional jump, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersStructuredPreviewForSimpleBranch(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC branch-fn
		0x0D, 0x03, 0x00, // BR_IF_FALSE +3
		0x01, // PUSH_NIL
		0x16, // END_DEFUN
		0x02, // PUSH_T
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"branch-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, ";; Structured Preview") {
		t.Fatalf("expected structured preview section, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(if (not arg)") {
		t.Fatalf("expected recovered if predicate preview, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(if (not arg) branch-fn_block_0010 branch-fn_block_000D)") {
		t.Fatalf("expected structured if preview, got:\n%s", pseudo)
	}
}

func TestDisassemblerStructuredPreviewUsesRecoveredPredicate(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00, // header
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC cfg-fn
		0x33, 0x03, 0x00, 0x00, 0x00, // PUSH_INT32 3
		0x6A, 0x01, 0x00, 0x00, 0x00, // AND_JMP +1
		0x02, // PUSH_T
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"cfg-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(if (not 3)") {
		t.Fatalf("expected structured predicate recovery, got:\n%s", pseudo)
	}
}

func TestDisassemblerCollapsesConstantStructuredBranch(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC const-branch
		0x02, // PUSH_T
		0x0E, 0x03, 0x00, // BR_IF_TRUE +3
		0x01, // PUSH_NIL
		0x16, // END_DEFUN
		0x02, // PUSH_T
		0x16, // END_DEFUN
	}

	disasm := NewDisassembler(bytecode, []string{"const-branch"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(goto const-branch_block_0011)") {
		t.Fatalf("expected constant branch to render direct goto, got:\n%s", pseudo)
	}
	if strings.Contains(pseudo, ";; function const-branch\n(if t ") {
		t.Fatalf("expected structured preview constant branch to collapse, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersStructuredPreviewForTopTestLoop(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC loop-fn
		0x0D, 0x04, 0x00, // BR_IF_FALSE +4 -> exit
		0x01, // PUSH_NIL body
		0x0F, 0xF9, 0xFF, // JMP -7 -> loop head
		0x16, // END_DEFUN exit
	}

	disasm := NewDisassembler(bytecode, []string{"loop-fn"}, nil)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(while arg loop-fn_block_000D)") {
		t.Fatalf("expected structured while preview, got:\n%s", pseudo)
	}
}

func TestDisassemblerSynthesizesReadableGlobalAlias(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, // PUSH_CONST [RZ
		0x06, 0x10, 0x01, // SETQ_GVAR 272
		0x03, 0x10, 0x01, // PUSH_SYM 272
	}

	disasm := NewDisassembler(bytecode, nil, []string{"[RZ"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'rz \"[RZ\")") {
		t.Fatalf("expected synthesized global alias, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(push-sym rz ; => \"[RZ\")") && !strings.Contains(pseudo, "(push-symbol rz)") {
		t.Fatalf("expected alias to be reused on load, got:\n%s", pseudo)
	}
}

func TestDisassemblerNormalizesControlTaggedStrings(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, // PUSH_CONST U\x01
		0x06, 0x00, 0x00, // SETQ_GVAR alias
	}

	disasm := NewDisassembler(bytecode, []string{"alias"}, []string{"U\x01"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(push-token \"U\" 0x01)") {
		t.Fatalf("expected control-tagged string to be identified, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "#<tok \"U\" 0x01>") {
		t.Fatalf("expected normalized token in expression rendering, got:\n%s", pseudo)
	}
}

func TestDisassemblerAliasesLocalSlotFromAssignedValue(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x14, 0x01, 0x00, 0x00, 0x00, // DEFUN locals=1 args=0..0
		0x09, 0x00, 0x00, // PUSH_CONST acad.dcl\x04
		0x5D, 0x00, 0x00, // SETQ_LVAR slot0
		0x05, 0x00, 0x00, // LOAD_LVAR slot0
		0x16,
	}

	disasm := NewDisassembler(bytecode, nil, []string{"acad.dcl\x04"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq local_0 #<tok \"acad.dcl\" 0x04>)") {
		t.Fatalf("expected control-tagged local to avoid unstable aliasing, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(load-lvar local_0 ; => #<tok \"acad.dcl\" 0x04>)") {
		t.Fatalf("expected local name to stay structural for control-tagged token, got:\n%s", pseudo)
	}
}

func TestDisassemblerFallsBackToStringTableForSymbolNames(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, // PUSH_SYM 0
		0x35, 0x01, 0x00, 0x00, 0x00, // CALL idx 0 argc=1
	}

	disasm := NewDisassembler(bytecode, nil, []string{"[SUBSTR"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(push-symbol substr)") {
		t.Fatalf("expected string-table symbol fallback, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(substr 'substr)") {
		t.Fatalf("expected call target to use canonicalized name, got:\n%s", pseudo)
	}
}

func TestDisassemblerRejectsNonCallableStringTableCallTargetFallback(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, // PUSH_SYM 0
		0x35, 0x01, 0x00, 0x00, 0x00, // CALL idx 0 argc=1
	}

	disasm := NewDisassembler(bytecode, nil, []string{"[END_PLATE"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(push-symbol end_plate)") {
		t.Fatalf("expected plain symbol rendering to remain available, got:\n%s", pseudo)
	}
	if strings.Contains(pseudo, "(end_plate 'end_plate)") {
		t.Fatalf("expected non-callable string-backed target to be rejected for CALL, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(sym_0 'end_plate)") {
		t.Fatalf("expected unresolved call target while preserving pushed symbol, got:\n%s", pseudo)
	}
}

func TestDisassemblerCanonicalizesViaxCreateObjectAlias(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x03, 0x09, 0x00, // PUSH_SYM 9 -> vlax-create-object from string table
		0x06, 0x08, 0x00, // SETQ_GVAR 8
		0x03, 0x08, 0x00, // PUSH_SYM 8
		0x09, 0x00, 0x00, // PUSH_CONST Microsoft.XMLHTTP
		0x35, 0x01, 0x08, 0x00, 0x03, // CALL sym_8 argc=1 flags=3
	}

	stringsTable := []string{
		"Microsoft.XMLHTTP",
		"", "", "", "", "", "", "",
		"U\x01",
		"[VIAX-IXMDX",
	}

	disasm := NewDisassembler(bytecode, nil, stringsTable)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'vlax-create-object 'vlax-create-object)") {
		t.Fatalf("expected VIAX alias binding, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(vlax-create-object \"Microsoft.XMLHTTP\")") {
		t.Fatalf("expected canonicalized COM creation call, got:\n%s", pseudo)
	}
}

func TestDisassemblerRejectsNumericOnlyRecoveredNames(t *testing.T) {
	if got := canonicalizeResourceSymbol("1\x01"); got != "" {
		t.Fatalf("expected numeric-only polluted symbol to be rejected, got %q", got)
	}
	if got := canonicalizeResourceSymbol("3\x01"); got != "" {
		t.Fatalf("expected numeric-only polluted symbol to be rejected, got %q", got)
	}
}

func TestRenderAlias254DispatchPatterns(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)

	gotGet := disasm.renderCallExpr("alias_254", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
		{Kind: "const", Value: "c\x01"},
		{Kind: "const", Value: "[DT"},
	})
	if gotGet != `(dispatch-get (vlax-create-object "[RC") :dt)` {
		t.Fatalf("expected dispatch-get reduction, got %q", gotGet)
	}

	gotPut := disasm.renderCallExpr("alias_254", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
		{Kind: "const", Value: " \x03"},
		{Kind: "const", Value: "[DT"},
		{Kind: "literal", Value: "nil"},
	})
	if gotPut != `(dispatch-put (vlax-create-object "[RC") :dt nil)` {
		t.Fatalf("expected dispatch-put reduction, got %q", gotPut)
	}

	gotCall := disasm.renderCallExpr("alias_254", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[CO")`},
		{Kind: "const", Value: "9\x16"},
		{Kind: "call", Value: `(substr "a" "b" "c")`},
	})
	if gotCall != `(dispatch-call (vlax-create-object "[CO") (substr "a" "b" "c"))` {
		t.Fatalf("expected dispatch-call reduction, got %q", gotCall)
	}

	gotMemberGet := disasm.renderCallExpr("alias_254", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
		{Kind: "const", Value: "[FS"},
	})
	if gotMemberGet != `(dispatch-get (vlax-create-object "[RC") :fs)` {
		t.Fatalf("expected member dispatch-get reduction, got %q", gotMemberGet)
	}

	gotMemberCall := disasm.renderCallExpr("alias_254", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
		{Kind: "const", Value: "[DT"},
		{Kind: "literal", Value: "nil"},
	})
	if gotMemberCall != `(dispatch-call (vlax-create-object "[RC") :dt nil)` {
		t.Fatalf("expected member dispatch-call reduction, got %q", gotMemberCall)
	}
}

func TestRenderAlias228DispatchPatterns(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)

	gotFirst := disasm.renderCallExpr("alias_228", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RE")`},
		{Kind: "const", Value: "[GF"},
		{Kind: "call", Value: `(dispatch "[x" "[y")`},
	})
	if gotFirst != `(dispatch-apply (vlax-create-object "[RE") :gf (dispatch "[x" "[y"))` {
		t.Fatalf("expected first-arg dispatch reduction, got %q", gotFirst)
	}

	gotLast := disasm.renderCallExpr("alias_228", []StackValue{
		{Kind: "const", Value: "regsvr32 /s scrrun.dll"},
		{Kind: "const", Value: "regsvr32 /s scrrun.dll"},
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
	})
	if gotLast != `(dispatch-apply (vlax-create-object "[RC") "regsvr32 /s scrrun.dll" "regsvr32 /s scrrun.dll")` {
		t.Fatalf("expected last-arg dispatch reduction, got %q", gotLast)
	}
}

func TestRenderConstAtomCondensesEncodedScriptBlob(t *testing.T) {
	got := renderConstAtom(`#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`)
	if got != "#<encoded-script>" {
		t.Fatalf("expected encoded script placeholder, got %q", got)
	}
	if alias := sanitizeIdentifier(`#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`); alias != "encoded_script" {
		t.Fatalf("expected encoded script identifier, got %q", alias)
	}
}

func TestRenderRecoveredSubstrCondensesEncodedScriptArg(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)

	gotMiddle := disasm.renderCallExpr("substr", []StackValue{
		{Kind: "const", Value: "U\x01"},
		{Kind: "const", Value: `#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`},
		{Kind: "const", Value: "[VIAX-IDOMC"},
	})
	if gotMiddle != `(encoded-script-substr #<tok "U" 0x01> "[VIAX-IDOMC")` {
		t.Fatalf("expected encoded-script substr reduction, got %q", gotMiddle)
	}

	gotFirst := disasm.renderCallExpr("substr", []StackValue{
		{Kind: "const", Value: `#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`},
		{Kind: "symbol", Value: "bs"},
		{Kind: "call", Value: `(dispatch-get (vlax-create-object "[RE") "[AS")`},
	})
	if gotFirst != `(encoded-script-substr 'bs (dispatch-get (vlax-create-object "[RE") "[AS"))` {
		t.Fatalf("expected encoded-script source reduction, got %q", gotFirst)
	}

	gotNested := disasm.renderCallExpr("substr", []StackValue{
		{Kind: "const", Value: "[SETINTERVAL"},
		{Kind: "const", Value: "[VIAX-IDOMC"},
		{Kind: "call", Value: `(encoded-script-substr 'bs (dispatch-get (vlax-create-object "[RE") "[AS"))`},
	})
	if gotNested != `(encoded-script-substr "[SETINTERVAL" "[VIAX-IDOMC")` {
		t.Fatalf("expected nested encoded-script substr propagation, got %q", gotNested)
	}

	gotPartial := disasm.renderCallExpr("substr", []StackValue{
		{Kind: "const", Value: "U\x01"},
		{Kind: "const", Value: `#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`},
		{Kind: "call", Value: `(encoded-script-substr 'bs "[SC")`},
	})
	if gotPartial != `(encoded-script-substr-partial #<tok "U" 0x01>)` {
		t.Fatalf("expected partial encoded-script substr marker, got %q", gotPartial)
	}
}

func TestRenderAlias228MarksPartialDispatchApply(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)

	got := disasm.renderCallExpr("alias_228", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RC")`},
	})
	if got != `(dispatch-apply-partial (vlax-create-object "[RC"))` {
		t.Fatalf("expected partial dispatch-apply marker, got %q", got)
	}
}

func TestDeriveAliasFromRenderedExprUsesDecodedSuffix(t *testing.T) {
	if got := deriveAliasFromRenderedExpr(`(encoded-script-substr nil "[SC")`); got != "sc_decoded" {
		t.Fatalf("expected decoded alias from final token, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(encoded-script-substr-partial #<tok "w" 0x06> "[CLOSE")`); got != "close_decoded" {
		t.Fatalf("expected decoded alias from partial expression, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str)`); got != "str_call_result" {
		t.Fatalf("expected dispatch-call member alias, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(dispatch-get (vlax-create-object "[:VLR-beginSave") :rf)`); got != "rf_value" {
		t.Fatalf("expected dispatch-get member alias, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(dispatch-put (vlax-create-object "[:VLR-beginSave") :co (vlax-create-object "[RC"))`); got != "co_set_result" {
		t.Fatalf("expected dispatch-put member alias, got %q", got)
	}
}

func TestSplitTopLevelCallHandlesNestedDispatchExpr(t *testing.T) {
	name, args, ok := splitTopLevelCall(`(dispatch-call (scriptcontrol (vlax-create-object #<tok "U" 0x01>) #<tok "U" 0x01>) :expandenvironmentstrings (dispatch-get (vlax-create-object "[:VLR-beginSave") "%temp%") 1000)`)
	if !ok {
		t.Fatalf("expected top-level call parse to succeed")
	}
	if name != "dispatch-call" {
		t.Fatalf("expected call name dispatch-call, got %q", name)
	}
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(args), args)
	}
	if args[1] != ":expandenvironmentstrings" {
		t.Fatalf("expected member keyword as second arg, got %q", args[1])
	}
}

func TestDeriveAliasFromWrapperExprPropagatesInnerAlias(t *testing.T) {
	if got := deriveAliasFromRenderedExpr(`(scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>)`); got != "str_flow" {
		t.Fatalf("expected scriptcontrol alias propagation, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(timeout "[RF" (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>))`); got != "str_flow" {
		t.Fatalf("expected timeout alias propagation, got %q", got)
	}
	if got := deriveAliasFromRenderedExpr(`(startapp (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok ".dcl" 0x04>))`); got != "str_flow" {
		t.Fatalf("expected startapp alias propagation, got %q", got)
	}
}

func TestMaybeAliasSlotReusesAliasForEquivalentExpression(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)
	fn := &FASFunction{
		Name:         "demo",
		NumOfArgs:    0,
		SlotAliases:  make(map[int]string),
		ExprAliases:  make(map[string]string),
		LocalVarRefs: make(map[int]int),
	}

	expr := StackValue{Kind: "call", Value: `(timeout "[RF" (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>))`}
	disasm.maybeAliasSlot(fn, 8, expr)
	disasm.maybeAliasSlot(fn, 16, expr)

	if fn.SlotAliases[8] != "str_flow" {
		t.Fatalf("expected first slot alias, got %q", fn.SlotAliases[8])
	}
	if fn.SlotAliases[16] != "str_flow" {
		t.Fatalf("expected equivalent expression to reuse alias, got %q", fn.SlotAliases[16])
	}
}

func TestMaybeAliasSlotReusesAliasForNearEquivalentTimeoutExpression(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)
	fn := &FASFunction{
		Name:         "demo",
		NumOfArgs:    0,
		SlotAliases:  make(map[int]string),
		ExprAliases:  make(map[string]string),
		LocalVarRefs: make(map[int]int),
	}

	first := StackValue{Kind: "call", Value: `(timeout #<tok "pacad.fas" 0x01> (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>))`}
	second := StackValue{Kind: "call", Value: `(timeout "[RF" (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>))`}
	disasm.maybeAliasSlot(fn, 8, first)
	disasm.maybeAliasSlot(fn, 16, second)

	if fn.SlotAliases[8] != "str_flow" {
		t.Fatalf("expected first timeout alias, got %q", fn.SlotAliases[8])
	}
	if fn.SlotAliases[16] != "str_flow" {
		t.Fatalf("expected near-equivalent timeout to reuse alias, got %q", fn.SlotAliases[16])
	}
}

func TestRenderValueHintPrefersSemanticFlowAlias(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)
	v := StackValue{Kind: "call", Value: `(timeout "[RF" (scriptcontrol (dispatch-call (vlax-create-object "[*ERROR*") #<tok "U" 0x02> :str) #<tok "acad.dcl" 0x04>))`}
	if got := disasm.renderValueHint(v); got != "str_flow" {
		t.Fatalf("expected semantic flow alias in value hint, got %q", got)
	}
}

func TestDisassemblerKeepsStructuralLocalNameWhenSemanticAliasExists(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x14, 0x01, 0x00, 0x00, 0x00, // DEFUN locals=1 args=0..0
		0x09, 0x00, 0x00, // PUSH_CONST [RC
		0x35, 0x01, 0x01, 0x00, 0x03, // CALL vlax-create-object
		0x09, 0x02, 0x00, // PUSH_CONST U\x02
		0x09, 0x03, 0x00, // PUSH_CONST [STR
		0x35, 0x03, 0x06, 0x00, 0x03, // CALL dispatch
		0x09, 0x04, 0x00, // PUSH_CONST acad.dcl\x04
		0x35, 0x02, 0x07, 0x00, 0x03, // CALL scriptcontrol
		0x5D, 0x00, 0x00, // SETQ_LVAR slot0
		0x05, 0x00, 0x00, // LOAD_LVAR slot0
		0x16,
	}

	symbols := []string{"", "vlax-create-object", "", "", "", "", "alias_254", "scriptcontrol"}
	stringsTable := []string{"[*ERROR*", "", "U\x02", "[STR", "acad.dcl\x04"}
	disasm := NewDisassembler(bytecode, symbols, stringsTable)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq local_0 (scriptcontrol") {
		t.Fatalf("expected structural local name on setq, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "slot[0]=local_0[str_flow] ->") {
		t.Fatalf("expected semantic alias to remain visible in slot comment, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "(load-lvar local_0 ; => str_flow)") {
		t.Fatalf("expected semantic alias to remain in value hint, got:\n%s", pseudo)
	}
	if strings.Contains(pseudo, "(setq str_flow ") {
		t.Fatalf("expected semantic alias not to replace local name, got:\n%s", pseudo)
	}
}

func TestDisassemblerRendersRecoveredFlowsSection(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, // PUSH_CONST [RC
		0x35, 0x01, 0x01, 0x00, 0x03, // CALL vlax-create-object
		0x09, 0x02, 0x00, // PUSH_CONST U\x02
		0x09, 0x03, 0x00, // PUSH_CONST [STR
		0x35, 0x03, 0x06, 0x00, 0x03, // CALL dispatch
		0x09, 0x04, 0x00, // PUSH_CONST acad.dcl\x04
		0x35, 0x02, 0x07, 0x00, 0x03, // CALL scriptcontrol
		0x06, 0x08, 0x00, // SETQ_GVAR sym8
		0x03, 0x08, 0x00, // PUSH_SYM sym8
	}

	symbols := []string{"", "vlax-create-object", "", "", "", "", "alias_254", "scriptcontrol", "flow-holder"}
	stringsTable := []string{"[*ERROR*", "", "U\x02", "[STR", "acad.dcl\x04"}
	disasm := NewDisassembler(bytecode, symbols, stringsTable)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, ";; Recovered Flows") {
		t.Fatalf("expected recovered flows section, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "str_flow") {
		t.Fatalf("expected str_flow summary, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "def_preview=") {
		t.Fatalf("expected flow preview summaries, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "flow-holder :=") {
		t.Fatalf("expected flow def preview to name assigned symbol, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "use_preview=") {
		t.Fatalf("expected flow use preview summaries, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "flow-holder <=") {
		t.Fatalf("expected flow use preview to name consumer symbol, got:\n%s", pseudo)
	}
}

func TestDisassemblerExportsRecoveredBehaviors(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x51, 0x00, 0x00, 0x00, 0x00, 0x00, // FUNC stage-fn
		0x03, 0x01, 0x00, // PUSH_SYM scriptcontrol
		0x35, 0x00, 0x01, 0x00, 0x03, // CALL scriptcontrol argc=0
		0x16,
	}

	symbols := []string{"stage-fn", "scriptcontrol"}
	stringsTable := []string{
		"ADODB.Stream\x10",
		"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
		"[VLR-DWG-Reactor",
		"M=$(edtime,$(getvar,date),YYMODD)",
		"findfile",
		"vl-file-copy",
		".WSF",
	}
	disasm := NewDisassembler(bytecode, symbols, stringsTable)
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	behaviors := disasm.Behaviors()
	if len(behaviors) == 0 {
		t.Fatalf("expected recovered behaviors")
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, ";; Recovered Behaviors") {
		t.Fatalf("expected recovered behaviors section, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "script_payload_staging") {
		t.Fatalf("expected script payload staging behavior, got:\n%s", pseudo)
	}
	if !strings.Contains(pseudo, "wsh_warning_suppression") {
		t.Fatalf("expected WSH behavior, got:\n%s", pseudo)
	}
}

func TestDisassemblerPushConstCondensesEncodedScriptBlob(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00,
	}
	disasm := NewDisassembler(bytecode, nil, []string{`#@~^DwAAAA==!AK]AsvZC"` + "`" + `Fq#*pAMAAA==^#~@`})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(push-encoded-script)") {
		t.Fatalf("expected push const to use encoded script placeholder, got:\n%s", pseudo)
	}
}

func TestDisassemblerSyntheticAliasDropsGlobalPrefix(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, // PUSH_CONST 0 => abc
		0x09, 0x01, 0x00, // PUSH_CONST 1 => def
		0x35, 0x02, 0x05, 0x00, 0x03, // CALL sym_5 argc=2
		0x06, 0x06, 0x00, // SETQ_GVAR 6
	}

	disasm := NewDisassembler(bytecode, nil, []string{"abc", "def", "", "", "", "helper-fn"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(setq 'helper_fn_result (helper-fn \"abc\" \"def\"))") {
		t.Fatalf("expected helper result alias without g_ prefix, got:\n%s", pseudo)
	}
}

func TestDisassemblerCallLineUsesReducedDispatchExpr(t *testing.T) {
	bytecode := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, // PUSH_CONST object name
		0x35, 0x01, 0x01, 0x00, 0x03, // CALL sym_1 => vlax-create-object
		0x09, 0x02, 0x00, // PUSH_CONST c\x01
		0x09, 0x03, 0x00, // PUSH_CONST [DT
		0x35, 0x03, 0x06, 0x00, 0x03, // CALL sym_6 => dispatch
	}

	symbols := []string{
		"", "vlax-create-object", "", "", "", "", "alias_254",
	}
	disasm := NewDisassembler(bytecode, symbols, []string{"[RC", "", "c\x01", "[DT"})
	if _, err := disasm.Disassemble(); err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}

	pseudo := disasm.ToPseudoLisp()
	if !strings.Contains(pseudo, "(dispatch-get (vlax-create-object \"[RC\") :dt)") {
		t.Fatalf("expected CALL line to use reduced dispatch-get, got:\n%s", pseudo)
	}
}

func TestRenderNamedCallNormalizesDispatchMemberTokens(t *testing.T) {
	disasm := NewDisassembler(nil, nil, nil)

	got := disasm.renderNamedCall("dispatch-call", []StackValue{
		{Kind: "call", Value: `(vlax-create-object "[RE")`},
		{Kind: "const", Value: "[EXPANDENVIRONMENTSTRINGS"},
		{Kind: "literal", Value: "nil"},
	})
	if got != `(dispatch-call (vlax-create-object "[RE") :expandenvironmentstrings nil)` {
		t.Fatalf("expected dispatch member normalization, got %q", got)
	}
}
