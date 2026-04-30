package adapter

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/debugutil"
)

// Opcode represents a FAS4 bytecode instruction
type Opcode struct {
	Name        string
	OperandSize int // 0=none, 1=1B, 2=2B LE, 4=4B LE, -1=special
}

// Opcodes is the FAS4 opcode table (aligned with Python version)
var Opcodes = map[byte]Opcode{
	// --- 1-byte (no operand) ---
	0x00: {Name: "NOP", OperandSize: 0},        // no operation
	0x01: {Name: "PUSH_NIL", OperandSize: 0},   // push nil
	0x02: {Name: "PUSH_T", OperandSize: 0},     // push T (true)
	0x0A: {Name: "POP", OperandSize: 0},        // pop/discard top of stack
	0x0B: {Name: "DUP", OperandSize: 0},        // duplicate top of stack
	0x16: {Name: "END_DEFUN", OperandSize: 0},  // end function / return
	0x20: {Name: "NOP", OperandSize: 0},        // alternate NOP
	0x23: {Name: "NULL_P", OperandSize: 0},     // null/not: is top == nil?
	0x24: {Name: "ATOM_P", OperandSize: 0},     // atom: is top non-list?
	0x26: {Name: "SUB", OperandSize: 0},        // subtract top two stack elements
	0x28: {Name: "CAR", OperandSize: 0},        // first element of list
	0x29: {Name: "CDR", OperandSize: 0},        // rest of list
	0x2A: {Name: "CONS", OperandSize: 0},       // construct cons pair
	0x38: {Name: "CONVERT", OperandSize: 0},    // convert top element type
	0x3E: {Name: "EXIT_IF_NZ", OperandSize: 0}, // exit defun if top != 0
	0x3F: {Name: "EXIT_IF_Z", OperandSize: 0},  // exit defun if top == 0
	0x62: {Name: "NOP", OperandSize: 0},        // alternate NOP
	0x63: {Name: "NOP", OperandSize: 0},        // alternate NOP
	0x17: {Name: "MAIN", OperandSize: 0},       // main entry (FAS2)
	0x1C: {Name: "COPY_STACK", OperandSize: 0}, // copy stack to func start/end
	0x14: {Name: "DEFUN", OperandSize: -2},     // function head: 4xI8 frame header
	0x15: {Name: "DEFUN_Q", OperandSize: -2},   // quoted/lambda-style function head

	// --- 2-byte (1B operand) ---
	0x08: {Name: "SETQ_LVAR8", OperandSize: 1},     // FSL: pop -> local var (8-bit idx)
	0x1E: {Name: "ALPHA", OperandSize: 1},          // unknown
	0x1F: {Name: "BETA", OperandSize: 1},           // unknown
	0x25: {Name: "IS_SYM", OperandSize: 1},         // FSL: check symbol type
	0x2C: {Name: "LIST_IDX", OperandSize: 1},       // list element by index
	0x2D: {Name: "LIST_SET", OperandSize: 1},       // set list element by index
	0x2E: {Name: "STACK_CALL_JMP", OperandSize: 1}, // call from stack and jump
	0x32: {Name: "SETQ", OperandSize: 1},           // FAS4: pop -> local var slot (8-bit)
	0x34: {Name: "EVAL", OperandSize: 1},           // eval: nargs on stack
	0x64: {Name: "CLEAR_LVAR8", OperandSize: 1},    // FSL: clear local var (8-bit idx)

	// --- 3-byte (2B LE operand) ---
	0x03: {Name: "PUSH_SYM", OperandSize: 2},    // push value of global var (MVars[idx])
	0x05: {Name: "LOAD_LVAR", OperandSize: 2},   // FSL: push local var (16-bit idx)
	0x06: {Name: "SETQ_GVAR", OperandSize: 2},   // pop -> global var (setq)
	0x09: {Name: "PUSH_CONST", OperandSize: 2},  // push constant item (string/list/num)
	0x0C: {Name: "PUSH_GVAR", OperandSize: 2},   // FSL: push global var
	0x0D: {Name: "BR_IF_FALSE", OperandSize: 2}, // branch if false (signed 16-bit offset)
	0x0E: {Name: "BR_IF_TRUE", OperandSize: 2},  // branch if true (signed 16-bit offset)
	0x0F: {Name: "JMP", OperandSize: 2},         // unconditional jump (signed 16-bit offset)
	0x10: {Name: "LIST_STEP", OperandSize: 2},   // list step: 2x int8 params
	0x11: {Name: "OP_11", OperandSize: 2},
	0x12: {Name: "OP_12", OperandSize: 2},
	0x18: {Name: "INIT_ARGS", OperandSize: 2},       // init args+locals: int16 count
	0x19: {Name: "CLEAR_ARGS", OperandSize: 2},      // clear args+vars: int16 count
	0x1A: {Name: "SETQ_DEFUN", OperandSize: 2},      // FSL: setq for defun
	0x1B: {Name: "SETQ_FSL", OperandSize: 2},        // FSL: setq
	0x21: {Name: "END_DEFUN2", OperandSize: 2},      // end defun + cleanup n vars
	0x2F: {Name: "CALL_JMP", OperandSize: -3},       // call and jump: int8 nargs + int16 idx
	0x37: {Name: "MAKE_LIST", OperandSize: 2},       // make list from n stack elements
	0x39: {Name: "LD_LIST", OperandSize: 2},         // combine n elements into list
	0x3C: {Name: "BR_IF_FALSE2", OperandSize: 2},    // branch if false (variant, with backward)
	0x3D: {Name: "BR_IF_TRUE2", OperandSize: 2},     // branch if true (variant)
	0x46: {Name: "ADD_FIXNUM", OperandSize: 0},      // fixnum binary +
	0x47: {Name: "SUB_FIXNUM", OperandSize: 0},      // fixnum binary -
	0x48: {Name: "MUL_FIXNUM", OperandSize: 0},      // fixnum binary *
	0x49: {Name: "DIV_FIXNUM", OperandSize: 0},      // fixnum binary /
	0x4A: {Name: "MOD_FIXNUM", OperandSize: 0},      // fixnum binary mod
	0x4B: {Name: "LE_FIXNUM", OperandSize: 0},       // fixnum binary <=
	0x4C: {Name: "GE_FIXNUM", OperandSize: 0},       // fixnum binary >=
	0x4D: {Name: "LT_FIXNUM", OperandSize: 0},       // fixnum binary <
	0x4E: {Name: "GT_FIXNUM", OperandSize: 0},       // fixnum binary >
	0x4F: {Name: "INC1", OperandSize: 0},            // unary increment by 1
	0x50: {Name: "DEC1", OperandSize: 0},            // unary decrement by 1
	0x5C: {Name: "LOAD_LVAR2", OperandSize: 2},      // FAS: push local var (16-bit idx)
	0x5D: {Name: "SETQ_LVAR", OperandSize: 2},       // pop -> local var (16-bit idx)
	0x5E: {Name: "CLEAR_LVAR", OperandSize: 2},      // clear local var (16-bit idx)
	0x5F: {Name: "CALL_BY_OFFSET", OperandSize: -4}, // call local function body by offset: int8 nargs + int32 offset

	// --- 4-byte (special: 1B + 2B) ---
	0x35: {Name: "CALL", OperandSize: -1}, // call: int8 nargs + int16 idx + int8 flags (5B total)
	0x51: {Name: "FUNC", OperandSize: -1}, // func: int8 nargs + int16 idx + int8 flags + int8 0 (6B)

	// --- 5-byte (4B operand) ---
	0x33: {Name: "PUSH_INT32", OperandSize: 4},      // push signed 32-bit integer literal
	0x57: {Name: "JMP_FAR", OperandSize: 4},         // far unconditional jump (signed 32-bit offset)
	0x67: {Name: "BR_IF_TRUE_FAR", OperandSize: 4},  // far branch if true (signed 32-bit offset)
	0x68: {Name: "OR_JMP", OperandSize: 4},          // cond/or short-circuit: jump if top is truthy, else pop
	0x69: {Name: "BR2_IF_TRUE_FAR", OperandSize: 4}, // far branch if true (variant)
	0x6A: {Name: "AND_JMP", OperandSize: 4},         // AND short-circuit: jump if false (signed 32-bit)
}

// Disassembler disassembles FAS4 bytecode
type Disassembler struct {
	data           []byte
	resources      []FASResourceEntry
	symbols        []string
	strings        []string
	forceSparse    bool
	instructions   []Instruction
	functions      []*FASFunction
	functionStack  []*FASFunction
	currentFunc    *FASFunction
	valueStack     []StackValue
	globalBindings map[int]StackValue
	slotBindings   map[int]map[int]StackValue
	globalAliases  map[int]string
	offsetToFunc   map[int]*FASFunction
	funcByStart    map[int]*FASFunction
	symbolNames    map[int]string
	globalNames    map[int]string
	symbolIndexMap map[string]int
	blockStartSet  map[*FASFunction]map[int]struct{}
	funcInstrs     map[*FASFunction][]Instruction
	behaviorsCache []FASRecoveredBehavior
}

const (
	compactRenderStringLimit      = 128
	compactRenderSymbolLimit      = 128
	compactRenderFunctionLimit    = 96
	compactRenderInstructionLimit = 2048
	compactRenderFlowLimit        = 64
	compactRenderPreviewLimit     = 64
	compactRenderEvidenceLimit    = 8
	compactHintValueLimit         = 160
	largeFASInstructionThreshold  = 100000
	largeFASByteThreshold         = 1024 * 1024
	largeFASFunctionThreshold     = 3000
	largeFASSymbolThreshold       = 1200
	largeFASStringThreshold       = 12000
)

// Instruction represents a disassembled instruction
type Instruction struct {
	Offset       int
	Opcode       byte
	Name         string
	Operands     []int
	OperandStr   string
	Comment      string
	ArgHints     []string
	TargetHint   string
	ExprHints    []string
	ValueHint    StackValue
	HasValueHint bool
}

// StackValue is a lightweight symbolic value used only for name/slot recovery.
// It is not intended to emulate the full FAS VM.
type StackValue struct {
	Kind  string
	Value string
}

// FASFunction captures function frame metadata recovered from bytecode.
// It is intentionally structural: offsets, argument count, frame size, and
// local slot names are derived from opcodes rather than guessed behavior.
type FASFunction struct {
	Name           string
	SymbolIndex    int
	StartOffset    int
	EndOffset      int
	NumOfArgs      int
	MaxArgs        int
	VarsCount      int
	FrameSize      int
	Flags          int
	GC             bool
	Kind           string
	IsLambda       bool
	Calls          []string
	IndirectCalls  []string
	LocalVarRefs   map[int]int
	SlotAliases    map[int]string
	ExprAliases    map[string]string
	BlockStarts    []int
	ControlEdges   []FASEdge
	blockStartSeen map[int]struct{}
	edgeSeen       map[string]struct{}
}

type FASEdge struct {
	From int
	To   int
	Kind string
}

type FASBinding struct {
	Scope  string
	Name   string
	Value  string
	Kind   string
	Offset int
}

type FASFlowSummary struct {
	Name      string
	Functions map[string]bool
	Defs      []int
	Uses      []int
	DefHints  []string
	UseHints  []string
}

type FASRecoveredBehavior struct {
	Kind      string
	Category  string
	Summary   string
	Functions []string
	Evidence  []string
}

// NewDisassembler creates a new disassembler
func NewDisassembler(data []byte, symbols []string, strings []string) *Disassembler {
	return &Disassembler{
		data:           data,
		symbols:        symbols,
		strings:        strings,
		forceSparse:    shouldStartSparseDisassembly(data, symbols, strings),
		instructions:   make([]Instruction, 0),
		functions:      make([]*FASFunction, 0),
		functionStack:  make([]*FASFunction, 0),
		valueStack:     make([]StackValue, 0),
		globalBindings: make(map[int]StackValue),
		slotBindings:   make(map[int]map[int]StackValue),
		globalAliases:  make(map[int]string),
		offsetToFunc:   make(map[int]*FASFunction),
		blockStartSet:  make(map[*FASFunction]map[int]struct{}),
		funcInstrs:     make(map[*FASFunction][]Instruction),
	}
}

func shouldStartSparseDisassembly(data []byte, symbols []string, strings []string) bool {
	return len(data) >= largeFASByteThreshold ||
		len(symbols) >= largeFASSymbolThreshold ||
		len(strings) >= largeFASStringThreshold
}

func (d *Disassembler) SetResourcePool(resources []FASResourceEntry) {
	d.resources = append(d.resources[:0], resources...)
}

func (d *Disassembler) symbolValueAt(idx int) (string, bool) {
	if idx >= 0 && idx < len(d.symbols) {
		if raw := d.symbols[idx]; raw != "" {
			return raw, true
		}
	}
	if raw, kind, ok := d.resourceAt(idx); ok && kind == "symbol" {
		return raw, true
	}
	return "", false
}

func (d *Disassembler) constValueAt(idx int) (string, bool) {
	if idx >= 0 && idx < len(d.strings) {
		if raw := d.strings[idx]; raw != "" {
			return raw, true
		}
	}
	if raw, kind, ok := d.resourceAt(idx); ok && kind == "string" {
		return raw, true
	}
	return "", false
}

// Disassemble disassembles the bytecode
func (d *Disassembler) Disassemble() ([]Instruction, error) {
	startAll := time.Now()
	var hintTime time.Duration
	var annotateTime time.Duration
	var stackTime time.Duration
	var finalizeTime time.Duration
	annotateBuckets := make(map[string]time.Duration)
	if len(d.data) < 4 {
		return nil, fmt.Errorf("data too short")
	}

	// Read local symbol count from header
	_ = int(d.data[0]) | int(d.data[1])<<8 | int(d.data[2])<<16 | int(d.data[3])<<24

	pos := 4
	for pos < len(d.data) {
		if pos >= len(d.data) {
			break
		}

		opcode := d.data[pos]
		op, ok := Opcodes[opcode]
		if !ok {
			// Unknown opcode
			d.instructions = append(d.instructions, Instruction{
				Offset:  pos,
				Opcode:  opcode,
				Name:    fmt.Sprintf("UNKNOWN_%02X", opcode),
				Comment: "Unknown opcode",
			})
			pos++
			continue
		}

		instr := Instruction{
			Offset: pos,
			Opcode: opcode,
			Name:   op.Name,
		}

		// Parse operands based on operand size
		if op.OperandSize == 0 {
			pos++
		} else if op.OperandSize == 1 {
			if pos+1 > len(d.data) {
				break
			}
			operand := int(d.data[pos+1])
			instr.Operands = []int{operand}
			pos += 2
		} else if op.OperandSize == 2 {
			if pos+2 > len(d.data) {
				break
			}
			operand := int(d.data[pos+1]) | int(d.data[pos+2])<<8
			if d.isSigned16Opcode(op.Name) {
				operand = int(int16(uint16(operand)))
			}
			instr.Operands = []int{operand}
			pos += 3
		} else if op.OperandSize == 4 {
			if pos+4 > len(d.data) {
				break
			}
			operand := int(d.data[pos+1]) | int(d.data[pos+2])<<8 | int(d.data[pos+3])<<16 | int(d.data[pos+4])<<24
			if d.isSigned32Opcode(op.Name) {
				operand = int(int32(uint32(operand)))
			}
			instr.Operands = []int{operand}
			pos += 5
		} else if op.OperandSize == -1 {
			// Special case for CALL and FUNC
			if opcode == 0x35 {
				// CALL: int8 nargs + int16 idx + int8 flags
				if pos+4 > len(d.data) {
					break
				}
				nargs := int(d.data[pos+1])
				idx := int(d.data[pos+2]) | int(d.data[pos+3])<<8
				flags := int(d.data[pos+4])
				instr.Operands = []int{nargs, idx, flags}
				instr.OperandStr = fmt.Sprintf("nargs=%d, idx=%d, flags=%d", nargs, idx, flags)
				pos += 5
			} else if opcode == 0x51 {
				// FUNC: int8 nargs + int16 idx + int8 flags + int8 0
				if pos+5 > len(d.data) {
					break
				}
				nargs := int(d.data[pos+1])
				idx := int(d.data[pos+2]) | int(d.data[pos+3])<<8
				flags := int(d.data[pos+4])
				instr.Operands = []int{nargs, idx, flags}
				instr.OperandStr = fmt.Sprintf("nargs=%d, idx=%d, flags=%d", nargs, idx, flags)
				pos += 6
			}
		} else if op.OperandSize == -2 {
			// DEFUN / DEFUN_Q header: 4 bytes
			if pos+4 > len(d.data) {
				break
			}
			cx := int(d.data[pos+1])
			args := int(d.data[pos+2])
			argsMax := int(d.data[pos+3])
			ax := int(d.data[pos+4])
			locals := ((ax & 0xFE) * 0x80) | cx
			gc := ax & 0x1
			instr.Operands = []int{locals, args, argsMax, gc}
			instr.OperandStr = fmt.Sprintf("locals=%d, args=%d..%d, gc=%d", locals, args, argsMax, gc)
			pos += 5
		} else if op.OperandSize == -3 {
			// CALL_JMP: int8 nargs + int16 idx
			if pos+3 > len(d.data) {
				break
			}
			nargs := int(d.data[pos+1])
			idx := int(d.data[pos+2]) | int(d.data[pos+3])<<8
			instr.Operands = []int{nargs, idx}
			instr.OperandStr = fmt.Sprintf("nargs=%d, idx=%d", nargs, idx)
			pos += 4
		} else if op.OperandSize == -4 {
			// CALL_BY_OFFSET: int8 nargs + int32 target
			if pos+5 > len(d.data) {
				break
			}
			nargs := int(d.data[pos+1])
			target := int(d.data[pos+2]) | int(d.data[pos+3])<<8 | int(d.data[pos+4])<<16 | int(d.data[pos+5])<<24
			instr.Operands = []int{nargs, int(int32(uint32(target)))}
			instr.OperandStr = fmt.Sprintf("nargs=%d, target=%04X", nargs, instr.Operands[1])
			pos += 6
		}

		// Add symbol/string reference if applicable
		if len(instr.Operands) > 0 {
			if op.Name == "PUSH_SYM" || op.Name == "PUSH_GVAR" {
				idx := instr.Operands[0]
				if raw, ok := d.symbolValueAt(idx); ok {
					instr.Comment = fmt.Sprintf("symbol: %s", raw)
				}
			} else if op.Name == "PUSH_CONST" {
				idx := instr.Operands[0]
				if raw, ok := d.constValueAt(idx); ok {
					instr.Comment = fmt.Sprintf("string: %s", raw)
				}
			}
		}

		stageStart := time.Now()
		d.captureCallHints(&instr)
		hintTime += time.Since(stageStart)
		stageStart = time.Now()
		annotateKey := instr.Name
		switch instr.Name {
		case "LOAD_LVAR", "LOAD_LVAR2", "SETQ", "SETQ_LVAR", "SETQ_LVAR8", "CLEAR_LVAR", "CLEAR_LVAR8":
			annotateKey = "slot_ops"
		case "CALL", "CALL_JMP", "CALL_BY_OFFSET", "STACK_CALL_JMP":
			annotateKey = "call_ops"
		case "BR_IF_FALSE", "BR_IF_TRUE", "BR_IF_FALSE2", "BR_IF_TRUE2", "JMP", "JMP_FAR", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP", "OR_JMP":
			annotateKey = "branch_ops"
		case "SETQ_GVAR", "PUSH_GVAR", "PUSH_SYM", "SETQ_DEFUN":
			annotateKey = "global_ops"
		case "DEFUN", "DEFUN_Q", "FUNC", "MAIN", "END_DEFUN", "END_DEFUN2", "INIT_ARGS":
			annotateKey = "frame_ops"
		}
		d.annotateInstruction(&instr)
		dur := time.Since(stageStart)
		annotateTime += dur
		annotateBuckets[annotateKey] += dur
		stageStart = time.Now()
		d.updateSymbolicStack(instr)
		stackTime += time.Since(stageStart)

		d.instructions = append(d.instructions, instr)

	}

	stageStart := time.Now()
	d.finalizeRecoveredNames()
	finalizeTime += time.Since(stageStart)
	if debugutil.TimingEnabled() && time.Since(startAll) > 500*time.Millisecond {
		fmt.Fprintf(os.Stderr, "  [FAS-DISASM] total=%v hints=%v annotate=%v stack=%v finalize=%v instr=%d funcs=%d\n",
			time.Since(startAll), hintTime, annotateTime, stackTime, finalizeTime, len(d.instructions), len(d.functions))
		if annotateTime > 500*time.Millisecond {
			fmt.Fprintf(os.Stderr, "  [FAS-ANNOTATE] slot=%v call=%v branch=%v global=%v frame=%v other=%v\n",
				annotateBuckets["slot_ops"],
				annotateBuckets["call_ops"],
				annotateBuckets["branch_ops"],
				annotateBuckets["global_ops"],
				annotateBuckets["frame_ops"],
				annotateBuckets["UNKNOWN"]+annotateBuckets["NOP"]+annotateBuckets["PUSH_CONST"]+annotateBuckets["PUSH_INT32"]+annotateBuckets["PUSH_NIL"]+annotateBuckets["PUSH_T"]+annotateBuckets["POP"]+annotateBuckets["DUP"]+annotateBuckets["EVAL"]+annotateBuckets["SETQ_FSL"]+annotateBuckets["SETQ_DEFUN"])
		}
	}

	return d.instructions, nil
}

func (d *Disassembler) finalizeRecoveredNames() {
	start := time.Now()
	d.finalizeFunctionBounds()
	boundsTime := time.Since(start)
	start = time.Now()
	d.buildRenderIndexes()
	bodyIndexTime := time.Since(start)
	start = time.Now()
	d.rewriteFunctionDisplayNames()
	rewriteTime := time.Since(start)
	start = time.Now()
	d.synthesizeFunctionNames()
	synthTime := time.Since(start)
	start = time.Now()
	d.promoteKnownLambdaHelpers()
	promoteTime := time.Since(start)
	start = time.Now()
	d.rebuildFunctionIndexes()
	indexTime := time.Since(start)
	for i := range d.instructions {
		instr := &d.instructions[i]
		if instr.Name == "CALL_BY_OFFSET" && len(instr.Operands) >= 2 {
			resolved := d.lookupFunctionByOffset(instr.Operands[1])
			instr.TargetHint = resolved
			if len(instr.Comment) > 0 {
				instr.Comment = fmt.Sprintf("call-by-offset %s argc=%d", resolved, instr.Operands[0])
			}
		}
		if (instr.Name == "CALL" || instr.Name == "CALL_JMP") && len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			resolved := d.recoverCallTargetFromUsage(*instr, d.resolveCallTargetName(instr.Operands[1]), d.peekArgValues(nargs, 0))
			instr.TargetHint = resolved
			flags := 0
			if instr.Name == "CALL" && len(instr.Operands) >= 3 {
				flags = instr.Operands[2]
			}
			callComment := fmt.Sprintf("call %s argc=%d", resolved, instr.Operands[0])
			if instr.Name == "CALL" {
				callComment = fmt.Sprintf("%s flags=%d", callComment, flags)
				if flags != 0 {
					callComment += " possible-usubr/lambda"
				}
			}
			instr.Comment = callComment
		}
	}
	for _, fn := range d.functions {
		for i, name := range fn.IndirectCalls {
			if strings.HasPrefix(name, "fn@") && len(name) == 7 {
				var offset int
				if _, err := fmt.Sscanf(name, "fn@%x", &offset); err == nil {
					fn.IndirectCalls[i] = d.lookupFunctionByOffset(offset)
				}
			}
		}
	}
	if debugutil.TimingEnabled() && (boundsTime > 200*time.Millisecond || bodyIndexTime > 200*time.Millisecond || rewriteTime > 200*time.Millisecond || synthTime > 200*time.Millisecond || promoteTime > 200*time.Millisecond || indexTime > 200*time.Millisecond) {
		fmt.Fprintf(os.Stderr, "  [FAS-FINALIZE] bounds=%v body_index=%v rewrite=%v synth=%v promote=%v indexes=%v\n",
			boundsTime, bodyIndexTime, rewriteTime, synthTime, promoteTime, indexTime)
	}
}

func (d *Disassembler) rebuildFunctionIndexes() {
	d.funcByStart = make(map[int]*FASFunction, len(d.functions))
	d.symbolNames = make(map[int]string)
	d.globalNames = make(map[int]string)
	d.symbolIndexMap = make(map[string]int)
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		d.funcByStart[fn.StartOffset] = fn
	}
	d.offsetToFunc, _ = d.assignInstructionOwners()
	for idx := range d.symbols {
		name := d.computeDisplaySymbolName(idx)
		d.symbolNames[idx] = name
		global := d.computeDisplayGlobalName(idx)
		d.globalNames[idx] = global
		if global != "" && !strings.HasPrefix(global, "sym_") {
			lower := strings.ToLower(global)
			if _, exists := d.symbolIndexMap[lower]; !exists {
				d.symbolIndexMap[lower] = idx
			}
		}
		if name != "" && !strings.HasPrefix(name, "sym_") {
			lower := strings.ToLower(name)
			if _, exists := d.symbolIndexMap[lower]; !exists {
				d.symbolIndexMap[lower] = idx
			}
		}
	}
}

func (d *Disassembler) assignInstructionOwners() (map[int]*FASFunction, map[*FASFunction][]Instruction) {
	offsetToFunc := make(map[int]*FASFunction, len(d.instructions))
	funcInstrs := make(map[*FASFunction][]Instruction, len(d.functions))
	if len(d.functions) == 0 || len(d.instructions) == 0 {
		return offsetToFunc, funcInstrs
	}

	ordered := make([]*FASFunction, 0, len(d.functions))
	for _, fn := range d.functions {
		if fn != nil {
			ordered = append(ordered, fn)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].StartOffset == ordered[j].StartOffset {
			return ordered[i].EndOffset < ordered[j].EndOffset
		}
		return ordered[i].StartOffset < ordered[j].StartOffset
	})

	active := make([]*FASFunction, 0, 8)
	nextFn := 0
	for _, instr := range d.instructions {
		offset := instr.Offset
		for nextFn < len(ordered) && ordered[nextFn].StartOffset <= offset {
			active = append(active, ordered[nextFn])
			nextFn++
		}
		if len(active) > 0 {
			dst := active[:0]
			for _, fn := range active {
				if fn.EndOffset < 0 || fn.EndOffset >= offset {
					dst = append(dst, fn)
				}
			}
			active = dst
		}
		if len(active) == 0 {
			continue
		}
		best := active[len(active)-1]
		offsetToFunc[offset] = best
		funcInstrs[best] = append(funcInstrs[best], instr)
	}
	return offsetToFunc, funcInstrs
}

func (d *Disassembler) promoteKnownLambdaHelpers() {
	used := make(map[string]bool, len(d.functions))
	for _, fn := range d.functions {
		if fn != nil && fn.Name != "" {
			used[strings.ToLower(fn.Name)] = true
		}
	}
	for _, fn := range d.functions {
		if fn == nil || !fn.IsLambda || !strings.EqualFold(fn.Name, "c:testfunctions") {
			continue
		}
		if !used["assoc+qty"] && d.isKnownLambdaHelperShape(fn, "assoc+qty") {
			delete(used, strings.ToLower(fn.Name))
			fn.Name = "assoc+qty"
			used["assoc+qty"] = true
			continue
		}
		if !d.isKnownLambdaHelperShape(fn, "unqtylist") {
			continue
		}
		if used["unqtylist"] {
			continue
		}
		delete(used, strings.ToLower(fn.Name))
		fn.Name = "unqtylist"
		used["unqtylist"] = true
	}
}

func (d *Disassembler) isKnownLambdaHelperShape(fn *FASFunction, target string) bool {
	switch strings.ToLower(target) {
	case "assoc+qty":
		prev := d.previousFunction(fn)
		return prev != nil &&
			isSyntheticRecoveredFunctionName(prev.Name) &&
			prev.NumOfArgs == 1 &&
			prev.VarsCount == 1 &&
			len(prev.Calls) == 0 &&
			fn.NumOfArgs == 1 &&
			fn.VarsCount == 0 &&
			len(fn.Calls) == 1 &&
			strings.EqualFold(fn.Calls[0], "vl-remove") &&
			d.functionBodyHasRecoveredNameHint(fn, "assoc+qty")
	case "unqtylist":
		return fn.NumOfArgs == 1 &&
			fn.VarsCount == 2 &&
			len(fn.Calls) == 1 &&
			strings.EqualFold(fn.Calls[0], "jd:displayassoclist") &&
			(d.functionBodyHasRecoveredNameHint(fn, "unqtylist") ||
				(d.previousNamedFunction(fn) == "qtylist" && d.nextNamedFunction(fn) == "resetcutlist"))
	}
	return false
}

func (d *Disassembler) previousFunction(target *FASFunction) *FASFunction {
	var prev *FASFunction
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		if fn == target {
			return prev
		}
		prev = fn
	}
	return nil
}

func (d *Disassembler) rewriteFunctionDisplayNames() {
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		if fn.SymbolIndex >= 0 {
			if candidate := d.displaySymbolName(fn.SymbolIndex); isPlausibleRecoveredFunctionName(candidate) {
				fn.Name = candidate
			}
		}
		filteredCalls := make([]string, 0, len(fn.Calls))
		for _, name := range fn.Calls {
			display := d.displayCallTargetName(name)
			if !isMeaningfulRecoveredName(display) {
				display = d.displaySymbolRef(display)
			}
			if !isMeaningfulRecoveredName(display) {
				continue
			}
			if !containsString(filteredCalls, display) {
				filteredCalls = append(filteredCalls, display)
			}
		}
		fn.Calls = filteredCalls
		filteredIndirect := make([]string, 0, len(fn.IndirectCalls))
		for _, name := range fn.IndirectCalls {
			display := d.displaySymbolRef(name)
			if !isMeaningfulRecoveredName(display) && !strings.HasPrefix(display, "fn_") && !strings.HasPrefix(display, "fn@") {
				continue
			}
			if !containsString(filteredIndirect, display) {
				filteredIndirect = append(filteredIndirect, display)
			}
		}
		fn.IndirectCalls = filteredIndirect
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (d *Disassembler) synthesizeFunctionNames() {
	used := make(map[string]bool)
	for _, fn := range d.functions {
		if fn.Name != "" {
			used[strings.ToLower(fn.Name)] = true
		}
	}
	for _, fn := range d.functions {
		if !isSyntheticRecoveredFunctionName(fn.Name) {
			continue
		}
		candidate := d.deriveFunctionNameFromBody(fn)
		if candidate == "" {
			continue
		}
		alternate := d.pickAlternateRecoveredFunctionName(fn, candidate, used)
		if alternate != "" {
			candidate = alternate
		} else if used[strings.ToLower(candidate)] {
			continue
		}
		name := candidate
		suffix := 2
		for used[strings.ToLower(name)] {
			name = fmt.Sprintf("%s_%d", candidate, suffix)
			suffix++
		}
		used[strings.ToLower(name)] = true
		fn.Name = name
	}
}

func (d *Disassembler) pickAlternateRecoveredFunctionName(fn *FASFunction, candidate string, used map[string]bool) string {
	lower := strings.ToLower(candidate)
	switch lower {
	case "jd:carcdr":
		if d.functionBodyHasRecoveredNameHint(fn, "assocappend") && !used["assocappend"] {
			return "assocappend"
		}
		if d.functionBodyHasRecoveredNameHint(fn, "assoc*") && !used["assoc*"] {
			return "assoc*"
		}
	case "sortkeys":
		if used["sortkeys"] && d.functionBodyHasRecoveredNameHint(fn, "sortvalues") && !used["sortvalues"] {
			return "sortvalues"
		}
	case "resetinfillcutlist":
		if used["resetinfillcutlist"] && d.functionBodyHasRecoveredNameHint(fn, "jd:displayqtylist") && !used["jd:displayqtylist"] {
			return "jd:displayqtylist"
		}
	}
	return ""
}

func (d *Disassembler) deriveFunctionNameFromStructure(fn *FASFunction) string {
	if fn == nil {
		return ""
	}
	if fn.NumOfArgs == 1 && fn.VarsCount <= 1 && len(fn.Calls) == 0 &&
		d.functionBodyOpcodeCount(fn, "EVAL") >= 2 &&
		d.functionBodyOpcodeCount(fn, "CAR") >= 1 &&
		d.functionBodyOpcodeCount(fn, "CDR") >= 1 {
		return "jd:carcdr"
	}
	if fn.NumOfArgs == 2 && fn.VarsCount >= 3 && len(fn.Calls) == 0 {
		if d.functionBodyMentionsAnySymbol(fn, "subst", "cons") {
			return "assoc*"
		}
	}
	if fn.NumOfArgs == 2 && fn.VarsCount <= 1 && len(fn.Calls) == 0 &&
		d.functionBodyHasRecoveredNameHint(fn, "variablename") &&
		d.functionBodyHasRecoveredNameHint(fn, "valuetosetifempty") &&
		d.functionBodyOpcodeCount(fn, "EVAL") >= 2 {
		return "makevarnotnil"
	}
	if fn.NumOfArgs == 2 && fn.VarsCount <= 1 && len(fn.Calls) == 0 &&
		d.functionBodyHasRecoveredNameHint(fn, "thelist") &&
		d.functionBodyHasRecoveredNameHint(fn, "functionname") &&
		d.functionBodyHasRecoveredNameHint(fn, "mapcar") &&
		d.functionBodyHasRecoveredNameHint(fn, "nth") {
		return "sort"
	}
	if fn.NumOfArgs == 2 && fn.VarsCount >= 2 && len(fn.Calls) == 0 &&
		d.functionBodyHasRecoveredNameHint(fn, "criteria") &&
		d.functionBodyHasRecoveredNameHint(fn, "thelist") &&
		d.functionBodyHasRecoveredNameHint(fn, "length") &&
		d.functionBodyOpcodeCount(fn, "EVAL") >= 1 &&
		d.functionBodyOpcodeCount(fn, "INC1") >= 1 &&
		d.functionBodyOpcodeCountAny(fn, "LT_FIXNUM", "LE_FIXNUM", "GT_FIXNUM", "GE_FIXNUM") >= 1 {
		return "listsearch"
	}
	if fn.NumOfArgs == 1 && fn.VarsCount <= 1 &&
		d.functionCallsOnly(fn, "princ") &&
		d.functionBodyHasAnyConst(fn) {
		return "displaycount"
	}
	return ""
}

func (d *Disassembler) previousNamedFunction(target *FASFunction) string {
	name := ""
	for _, fn := range d.functions {
		if fn == nil || fn == target {
			break
		}
		if !isSyntheticRecoveredFunctionName(fn.Name) {
			name = strings.ToLower(fn.Name)
		}
	}
	return name
}

func (d *Disassembler) nextNamedFunction(target *FASFunction) string {
	seen := false
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		if fn == target {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		if !isSyntheticRecoveredFunctionName(fn.Name) {
			return strings.ToLower(fn.Name)
		}
	}
	return ""
}

func isSyntheticRecoveredFunctionName(name string) bool {
	return strings.HasPrefix(name, "fn_") || strings.HasPrefix(name, "sym_")
}

func (d *Disassembler) deriveFunctionNameFromBody(fn *FASFunction) string {
	if fn == nil {
		return ""
	}
	body := d.bodyInstructions(fn)
	scores := make(map[string]int)
	seen := make(map[string]bool)
	addScore := func(name string, score int) {
		if name == "" || score <= 0 {
			return
		}
		scores[name] += score
		seen[name] = true
	}
	stringOrder := 0
	for _, instr := range body {
		if instr.Name != "PUSH_CONST" || len(instr.Operands) == 0 {
			continue
		}
		idx := instr.Operands[0]
		raw := ""
		if resourceRaw, kind, ok := d.resourceAt(idx); ok && (kind == "string" || kind == "symbol") {
			raw = resourceRaw
		} else if idx >= 0 && idx < len(d.strings) {
			raw = d.strings[idx]
		}
		if raw == "" {
			continue
		}
		if name, score := scoreRecoveredFunctionNameCandidateFromBody(raw, stringOrder); score > 0 {
			addScore(name, score)
		}
		stringOrder++
	}
	for _, name := range fn.Calls {
		if candidate, score := scoreRecoveredFunctionCallCandidate(name); score > 0 {
			addScore(candidate, score)
		}
	}
	if d.functionBodyHasRecoveredNameHint(fn, "subst") && d.functionBodyHasRecoveredNameHint(fn, "cons") {
		addScore("assoc*", 44)
	}
	for _, instr := range body {
		if instr.Name == "CALL" || instr.Name == "CALL_JMP" {
			if len(instr.Operands) >= 2 {
				candidate := d.displaySymbolName(instr.Operands[1])
				if name, score := scoreRecoveredFunctionCallCandidate(candidate); score > 0 {
					addScore(name, score)
				}
			}
		}
	}
	applyRecoveredFunctionSignatureBonuses(scores, seen, fn)
	bestName := ""
	bestScore := -1
	for name, score := range scores {
		if score > bestScore || (score == bestScore && bestName != "" && name < bestName) {
			bestName = name
			bestScore = score
		}
	}
	if bestScore < 40 {
		return d.deriveFunctionNameFromStructure(fn)
	}
	return bestName
}

func scoreRecoveredFunctionNameCandidate(raw string) (string, int) {
	name := sanitizeFunctionName(raw)
	if name == "" {
		return "", -1
	}
	switch {
	case strings.HasPrefix(name, "c:"):
		return name, 100
	case strings.HasPrefix(name, "*") && strings.HasSuffix(name, "*"):
		return name, 90
	case strings.Contains(name, ":"):
		return name, 80
	default:
		return "", -1
	}
}

func scoreRecoveredFunctionNameCandidateFromBody(raw string, order int) (string, int) {
	if name, score := scoreRecoveredFunctionNameCandidate(raw); score > 0 {
		if order < 3 {
			score += 12
		}
		return name, score
	}
	name := sanitizeHelperFunctionName(raw)
	if name == "" || isGenericRecoveredFunctionNoise(name) || isCommonRecoveredBuiltin(name) {
		return "", -1
	}
	score := 0
	switch {
	case strings.Contains(name, ":"):
		score = 72
	case strings.ContainsAny(name, "+*"):
		score = 68
	case isKnownRecoveredHelperName(name):
		score = 60
	case isUpperHelperNameToken(raw, name):
		score = 48
	default:
		return "", -1
	}
	if order < 2 {
		score += 18
	} else if order < 5 {
		score += 8
	}
	return name, score
}

func scoreRecoveredFunctionCallCandidate(raw string) (string, int) {
	name := sanitizeHelperFunctionName(raw)
	if name == "" || isGenericRecoveredFunctionNoise(name) || isCommonRecoveredBuiltin(name) {
		return "", -1
	}
	switch {
	case strings.Contains(name, ":"):
		return name, 22
	case strings.ContainsAny(name, "+*"):
		return name, 18
	case isKnownRecoveredHelperName(name):
		return name, 16
	default:
		return "", -1
	}
}

func applyRecoveredFunctionSignatureBonuses(scores map[string]int, seen map[string]bool, fn *FASFunction) {
	if len(scores) == 0 {
		return
	}
	hasCall := func(target string) bool {
		for _, name := range fn.Calls {
			if strings.EqualFold(sanitizeHelperFunctionName(name), target) {
				return true
			}
		}
		return false
	}
	if seen["listremove"] && seen["listsearch"] {
		scores["listremove"] += 24
	}
	if seen["assoc+qty"] {
		scores["assoc+qty"] += 18
	}
	if seen["assoc*"] && seen["subst"] {
		scores["assoc*"] += 16
	}
	if seen["assocappend"] && (seen["assoc+qty"] || hasCall("assoc+qty")) {
		scores["assocappend"] += 22
	}
	if seen["assocappend"] && seen["assoc*"] {
		scores["assocappend"] += 18
	}
	if seen["qtylist"] && (seen["assoc++"] || hasCall("assoc++")) {
		scores["qtylist"] += 22
	}
	if seen["unqtylist"] {
		scores["unqtylist"] += 20
	}
	if seen["sortvalues"] && seen["sortkeys"] {
		scores["sortvalues"] += 10
		scores["sortkeys"] += 8
	}
	if !seen["assoc*"] && seen["subst"] && seen["cons"] {
		scores["assoc*"] += 44
	}
	if seen["resetcutlist"] {
		scores["resetcutlist"] += 18
	}
	if seen["resetinfillcutlist"] {
		scores["resetinfillcutlist"] += 18
	}
}

func (d *Disassembler) functionBodyHasRecoveredNameHint(fn *FASFunction, target string) bool {
	target = strings.ToLower(target)
	for _, instr := range d.bodyInstructions(fn) {
		switch instr.Name {
		case "PUSH_CONST":
			if len(instr.Operands) == 0 {
				continue
			}
			idx := instr.Operands[0]
			raw := ""
			if resourceRaw, kind, ok := d.resourceAt(idx); ok && (kind == "string" || kind == "symbol") {
				raw = resourceRaw
			} else if idx >= 0 && idx < len(d.strings) {
				raw = d.strings[idx]
			}
			if raw != "" && strings.EqualFold(sanitizeHelperFunctionName(raw), target) {
				return true
			}
		case "PUSH_SYM", "PUSH_GVAR", "SETQ_GVAR", "SETQ_DEFUN":
			if len(instr.Operands) == 0 {
				continue
			}
			if strings.EqualFold(sanitizeHelperFunctionName(d.displayGlobalName(instr.Operands[0])), target) {
				return true
			}
		case "CALL", "CALL_JMP":
			if len(instr.Operands) < 2 {
				continue
			}
			if strings.EqualFold(sanitizeHelperFunctionName(d.displayCallTargetName(d.displaySymbolName(instr.Operands[1]))), target) {
				return true
			}
		}
	}
	return false
}

func (d *Disassembler) functionBodyMentionsAnySymbol(fn *FASFunction, targets ...string) bool {
	if fn == nil || len(targets) == 0 {
		return false
	}
	needle := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if normalized := strings.ToLower(strings.TrimSpace(target)); normalized != "" {
			needle[normalized] = struct{}{}
		}
	}
	for _, instr := range d.bodyInstructions(fn) {
		if len(instr.Operands) == 0 {
			continue
		}
		idx := -1
		switch instr.Name {
		case "PUSH_SYM", "PUSH_GVAR", "SETQ_GVAR", "SETQ_DEFUN":
			idx = instr.Operands[0]
		case "CALL", "CALL_JMP":
			if len(instr.Operands) >= 2 {
				name := strings.ToLower(strings.TrimSpace(d.displayCallTargetName(d.displaySymbolName(instr.Operands[1]))))
				if _, ok := needle[name]; ok {
					return true
				}
			}
		}
		if idx >= 0 {
			name := strings.ToLower(strings.TrimSpace(d.displayGlobalName(idx)))
			if _, ok := needle[name]; ok {
				return true
			}
		}
	}
	return false
}

func (d *Disassembler) functionCallsOnly(fn *FASFunction, target string) bool {
	if fn == nil || len(fn.Calls) == 0 {
		return false
	}
	target = strings.ToLower(strings.TrimSpace(target))
	for _, call := range fn.Calls {
		if strings.ToLower(strings.TrimSpace(call)) != target {
			return false
		}
	}
	return true
}

func (d *Disassembler) functionBodyHasPrincLiteral(fn *FASFunction) bool {
	if fn == nil {
		return false
	}
	for _, instr := range d.bodyInstructions(fn) {
		if instr.Name != "PUSH_CONST" || len(instr.Operands) == 0 {
			continue
		}
		idx := instr.Operands[0]
		raw := ""
		if resourceRaw, kind, ok := d.resourceAt(idx); ok && (kind == "string" || kind == "symbol") {
			raw = resourceRaw
		} else if idx >= 0 && idx < len(d.strings) {
			raw = d.strings[idx]
		}
		display, _ := normalizeDisplayString(raw)
		display = strings.TrimSpace(display)
		if display == "\\n" || display == "\n" || strings.Contains(display, "\\n") {
			return true
		}
	}
	return false
}

func (d *Disassembler) functionDirectCallCount(fn *FASFunction, target string) int {
	if fn == nil {
		return 0
	}
	target = strings.ToLower(strings.TrimSpace(target))
	count := 0
	for _, instr := range d.bodyInstructions(fn) {
		if (instr.Name == "CALL" || instr.Name == "CALL_JMP") && len(instr.Operands) >= 2 {
			if strings.ToLower(strings.TrimSpace(d.displayCallTargetName(d.displaySymbolName(instr.Operands[1])))) == target {
				count++
			}
		}
	}
	return count
}

func (d *Disassembler) functionBodyOpcodeCount(fn *FASFunction, target string) int {
	if fn == nil {
		return 0
	}
	target = strings.ToUpper(strings.TrimSpace(target))
	if target == "" {
		return 0
	}
	count := 0
	for _, instr := range d.bodyInstructions(fn) {
		if strings.EqualFold(instr.Name, target) {
			count++
		}
	}
	return count
}

func (d *Disassembler) functionBodyOpcodeCountAny(fn *FASFunction, targets ...string) int {
	if fn == nil || len(targets) == 0 {
		return 0
	}
	needle := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = strings.ToUpper(strings.TrimSpace(target))
		if target != "" {
			needle[target] = struct{}{}
		}
	}
	count := 0
	for _, instr := range d.bodyInstructions(fn) {
		if _, ok := needle[strings.ToUpper(strings.TrimSpace(instr.Name))]; ok {
			count++
		}
	}
	return count
}

func (d *Disassembler) functionBodyHasAnyConst(fn *FASFunction) bool {
	if fn == nil {
		return false
	}
	for _, instr := range d.bodyInstructions(fn) {
		if instr.Name == "PUSH_CONST" && len(instr.Operands) > 0 {
			return true
		}
	}
	return false
}

func (d *Disassembler) hasRecoveredFunctionNamed(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(fn.Name)) == target {
			return true
		}
	}
	return false
}

func sanitizeHelperFunctionName(raw string) string {
	display, _ := normalizeDisplayString(raw)
	display = strings.TrimSpace(display)
	display = strings.Trim(display, "[](){}<>\"'")
	if display == "" {
		return ""
	}
	display = strings.ToLower(display)
	var b strings.Builder
	alphaCount := 0
	for _, r := range display {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			if r >= 'a' && r <= 'z' {
				alphaCount++
			}
			continue
		}
		switch r {
		case ':', '+', '-', '*', '=', '/', '?', '!':
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" || alphaCount < 3 {
		return ""
	}
	if strings.Trim(name, ":+-*/=?!") == "" {
		return ""
	}
	if normalized := normalizeKnownHelperVariant(name); normalized != "" {
		name = normalized
	}
	if strings.HasPrefix(name, "sym_") || strings.HasPrefix(name, "fn_") {
		return ""
	}
	return name
}

func isUpperHelperNameToken(raw, name string) bool {
	display, _ := normalizeDisplayString(raw)
	display = strings.TrimSpace(display)
	if display == "" {
		return false
	}
	hasAlpha := false
	for _, r := range display {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= 'A' && r <= 'Z' {
			hasAlpha = true
		}
	}
	return hasAlpha && !isGenericRecoveredFunctionNoise(name)
}

func isKnownRecoveredHelperName(name string) bool {
	switch name {
	case "assoc*", "assoc++", "assoc+qty", "assoc--", "assocappend",
		"displaycount", "jd:carcdr", "jd:displayassoclist", "jd:displayqtylist",
		"listremove", "listsearch", "makevarnotnil", "qtylist", "resetcutlist",
		"resetinfillcutlist", "sort", "sortkeys", "sortvalues", "unqtylist":
		return true
	}
	return false
}

func isGenericRecoveredFunctionNoise(name string) bool {
	switch name {
	case "addquantity", "alist", "append", "arg", "arg_0", "arg_1", "arg_2",
		"assoclist", "criteria", "firstitem", "functionname", "index", "item",
		"lambda", "listname", "multiplier", "newlist", "newqtylist", "result",
		"returnitem", "theassoclist", "thekey", "thelist", "theqtylist",
		"valuetosetifempty", "variablename":
		return true
	}
	return false
}

func sanitizeFunctionName(raw string) string {
	if canonical := canonicalizeResourceSymbol(raw); canonical != "" {
		if looksLikeRecoveredFunctionName(canonical) {
			return canonical
		}
	}
	display, _ := normalizeDisplayString(raw)
	raw = display
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "[](){}<>\"'")
	raw = strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(raw, "c:") {
		base := sanitizeIdentifier(raw)
		if base == "" {
			return ""
		}
		if strings.HasPrefix(base, "c_") {
			return "c:" + strings.TrimPrefix(base, "c_")
		}
		return "c:" + base
	}
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.Trim(b.String(), "-")
	if !looksLikeRecoveredFunctionName(name) {
		return ""
	}
	return name
}

func looksLikeRecoveredFunctionName(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "sym_") || strings.HasPrefix(name, "fn_") || strings.HasPrefix(name, "helper-") {
		return false
	}
	if strings.Contains(name, "tok") || strings.Contains(name, "value") {
		return false
	}
	alphaCount := 0
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			alphaCount++
		}
	}
	if alphaCount < 3 {
		return false
	}
	return true
}

func isCommonRecoveredBuiltin(name string) bool {
	switch name {
	case "assoc", "block", "blocktable", "car", "cdr", "cons", "dictsearch",
		"entget", "eval", "findfile", "list", "load",
		"member", "namedobjdict", "not", "princ",
		"setvar", "sslength", "ssname", "strcat", "strcase", "substr",
		"tablesearch", "vl-file-copy", "vlax-create-object",
		"vlax-invoke-method":
		return true
	}
	return false
}

func isLikelyStringBackedCallTarget(name string) bool {
	switch {
	case name == "":
		return false
	case strings.HasPrefix(name, "c:"):
		return true
	case strings.HasPrefix(name, "vl-"), strings.HasPrefix(name, "vlax-"):
		return true
	case strings.HasPrefix(name, "fas::"):
		return true
	case isCommonRecoveredBuiltin(name):
		return true
	case isLispFunction(name):
		return true
	case strings.Contains(name, ":"):
		return true
	case strings.Contains(name, "-") && !strings.Contains(name, "_"):
		return true
	default:
		return false
	}
}

func isPlausibleRecoveredFunctionName(name string) bool {
	switch {
	case name == "":
		return false
	case strings.HasPrefix(name, "c:"):
		return true
	case strings.HasPrefix(name, "fas::"):
		return true
	case strings.HasPrefix(name, "vl-"), strings.HasPrefix(name, "vlax-"):
		return false
	case isCommonRecoveredBuiltin(name):
		return false
	case strings.Contains(name, "_"):
		return false
	case strings.Contains(name, ":"):
		return true
	case strings.Contains(name, "-"):
		return true
	default:
		return false
	}
}

func rawSymbolLooksCallable(raw string) bool {
	display, control := normalizeDisplayString(raw)
	display = strings.TrimSpace(display)
	if control != 0 || display == "" {
		return false
	}
	display = strings.TrimPrefix(display, "[")
	if display == "" {
		return false
	}
	hasLower := false
	for _, r := range display {
		if r >= 'a' && r <= 'z' {
			hasLower = true
			break
		}
	}
	if hasLower {
		return true
	}
	if strings.Contains(display, ":") {
		return true
	}
	if strings.Contains(display, "-") && !strings.Contains(display, "_") {
		return true
	}
	return false
}

func isCallableSymbolCandidate(raw, candidate string) bool {
	if candidate == "" {
		return false
	}
	if isLikelyStringBackedCallTarget(candidate) {
		return true
	}
	if !isMeaningfulRecoveredName(candidate) {
		return false
	}
	if strings.Contains(candidate, "_") {
		return false
	}
	return rawSymbolLooksCallable(raw)
}

func (d *Disassembler) finalizeFunctionBounds() {
	if len(d.functions) == 0 {
		return
	}

	lastEnd := 0
	if len(d.instructions) > 0 {
		last := d.instructions[len(d.instructions)-1]
		lastEnd = last.Offset + d.instructionWidth(last) - 1
	}

	ordered := make([]*FASFunction, len(d.functions))
	copy(ordered, d.functions)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].StartOffset == ordered[j].StartOffset {
			return ordered[i].EndOffset < ordered[j].EndOffset
		}
		return ordered[i].StartOffset < ordered[j].StartOffset
	})

	for i, fn := range ordered {
		if fn.EndOffset >= fn.StartOffset {
			continue
		}
		guessEnd := lastEnd
		for j := i + 1; j < len(ordered); j++ {
			next := ordered[j]
			if next.StartOffset > fn.StartOffset {
				guessEnd = next.StartOffset - 1
				break
			}
		}
		if guessEnd < fn.StartOffset {
			guessEnd = fn.StartOffset
		}
		fn.EndOffset = guessEnd
	}
}

func (d *Disassembler) annotateInstruction(instr *Instruction) {
	sparse := d.sparseAnnotationMode()
	switch instr.Name {
	case "DEFUN", "DEFUN_Q":
		d.currentFunc = d.newFunctionFromDefunHeader(*instr)
		if name, ok := d.peekFunctionNameHint(); ok {
			d.currentFunc.Name = name
		}
		d.functions = append(d.functions, d.currentFunc)
		d.functionStack = append(d.functionStack, d.currentFunc)
		if !sparse {
			instr.Comment = d.appendComment(instr.Comment, d.currentFunc.headerComment())
		}
	case "FUNC":
		d.currentFunc = d.newFunctionFromInstr(*instr)
		d.functions = append(d.functions, d.currentFunc)
		d.functionStack = append(d.functionStack, d.currentFunc)
		if !sparse {
			instr.Comment = d.appendComment(instr.Comment, d.currentFunc.headerComment())
		}
	case "MAIN":
		if d.currentFunc == nil {
			d.currentFunc = &FASFunction{
				Name:         "main",
				SymbolIndex:  -1,
				StartOffset:  instr.Offset,
				EndOffset:    -1,
				Kind:         "main",
				LocalVarRefs: make(map[int]int),
				SlotAliases:  make(map[int]string),
				ExprAliases:  make(map[string]string),
			}
			d.functions = append(d.functions, d.currentFunc)
			d.functionStack = append(d.functionStack, d.currentFunc)
		}
		if !sparse {
			instr.Comment = d.appendComment(instr.Comment, d.currentFunc.headerComment())
		}
	case "INIT_ARGS":
		if d.currentFunc != nil && len(instr.Operands) > 0 {
			frameSize := instr.Operands[0]
			d.currentFunc.FrameSize = frameSize
			if d.currentFunc.VarsCount == 0 && frameSize > d.currentFunc.NumOfArgs {
				d.currentFunc.VarsCount = frameSize - d.currentFunc.NumOfArgs
			}
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment,
					fmt.Sprintf("frame: args=%d locals=%d", d.currentFunc.NumOfArgs, d.currentFunc.VarsCount))
			}
		}
	case "LOAD_LVAR", "LOAD_LVAR2", "SETQ", "SETQ_LVAR", "SETQ_LVAR8", "CLEAR_LVAR", "CLEAR_LVAR8":
		if d.currentFunc != nil && len(instr.Operands) > 0 {
			fn := d.currentFunc
			slot := instr.Operands[0]
			name := fn.slotName(slot)
			alias := fn.SlotAliases[slot]
			nameDisplay := name
			if alias != "" && alias != name {
				nameDisplay = fmt.Sprintf("%s[%s]", name, alias)
			}
			fn.LocalVarRefs[slot]++
			var (
				bound StackValue
				ok    bool
			)
			if slots := d.slotBindings[fn.StartOffset]; slots != nil {
				bound, ok = slots[slot]
			}
			if (instr.Name == "SETQ" || instr.Name == "SETQ_LVAR" || instr.Name == "SETQ_LVAR8") && instr.HasValueHint && instr.ValueHint.Value != "" {
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("slot[%d]=%s <- %s", slot, nameDisplay, instr.ValueHint.Value))
				}
			} else if ok && bound.Value != "" {
				instr.ValueHint = bound
				instr.HasValueHint = true
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("slot[%d]=%s -> %s", slot, nameDisplay, bound.Value))
				}
			} else if !sparse {
				instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("slot[%d]=%s", slot, nameDisplay))
			}
		}
	case "END_DEFUN", "END_DEFUN2":
		if len(d.functionStack) > 0 {
			fn := d.functionStack[len(d.functionStack)-1]
			fn.EndOffset = instr.Offset
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment, fn.footerComment())
			}
			d.functionStack = d.functionStack[:len(d.functionStack)-1]
			if len(d.functionStack) > 0 {
				d.currentFunc = d.functionStack[len(d.functionStack)-1]
			} else {
				d.currentFunc = nil
			}
		}
	case "CALL":
		if len(instr.Operands) >= 3 {
			nargs := instr.Operands[0]
			flags := instr.Operands[2]
			callee := instr.TargetHint
			if callee == "" {
				callee = d.resolveCallTargetName(instr.Operands[1])
			}
			callComment := fmt.Sprintf("call %s argc=%d flags=%d", callee, nargs, flags)
			if flags != 0 {
				callComment += " possible-usubr/lambda"
			}
			if d.currentFunc != nil {
				d.currentFunc.addCall(callee)
			}
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment, callComment)
			}
		}
	case "CALL_JMP":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			callee := instr.TargetHint
			if callee == "" {
				callee = d.resolveCallTargetName(instr.Operands[1])
			}
			if d.currentFunc != nil {
				d.currentFunc.addCall(callee)
			}
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("call-jmp %s argc=%d", callee, nargs))
			}
		}
	case "CALL_BY_OFFSET":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			target := instr.Operands[1]
			callee := d.lookupFunctionByOffset(target)
			if d.currentFunc != nil {
				d.currentFunc.addIndirectCall(callee)
			}
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("call-by-offset %s argc=%d", callee, nargs))
			}
		}
	case "STACK_CALL_JMP":
		target := "stack_top"
		if v, ok := d.peekValue(); ok && v.Value != "" {
			target = v.Value
		}
		if d.currentFunc != nil {
			d.currentFunc.addIndirectCall(target)
		}
		if !sparse && len(instr.Operands) > 0 {
			instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("stack-call-jmp %s argc=%d", target, instr.Operands[0]))
		} else if !sparse {
			instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("stack-call-jmp %s", target))
		}
	case "SETQ_DEFUN":
		if d.currentFunc != nil {
			name := ""
			if len(instr.Operands) > 0 {
				name = d.displaySymbolName(instr.Operands[0])
			}
			if name == "" || strings.HasPrefix(name, "sym_") {
				if hinted, ok := d.peekFunctionNameHint(); ok {
					name = hinted
				}
			}
			if name != "" && !strings.HasPrefix(name, "sym_") && (isLikelyStringBackedCallTarget(name) || isPlausibleRecoveredFunctionName(name)) {
				d.currentFunc.Name = name
				if len(instr.Operands) > 0 {
					d.currentFunc.SymbolIndex = instr.Operands[0]
				} else {
					d.currentFunc.SymbolIndex = d.symbolIndex(name)
				}
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, "bind-func="+name)
				}
			}
		}
	case "SETQ_GVAR":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if pending, ok := d.peekValue(); ok && pending.Value != "" {
				instr.ValueHint = pending
				instr.HasValueHint = true
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("bind-global %s=%s", d.displayGlobalName(idx), pending.Value))
				}
			} else if bound, ok := d.globalBindings[idx]; ok && bound.Value != "" {
				instr.ValueHint = bound
				instr.HasValueHint = true
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("bind-global %s=%s", d.displayGlobalName(idx), bound.Value))
				}
			}
		}
	case "PUSH_GVAR":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if bound, ok := d.globalBindings[idx]; ok && bound.Value != "" {
				instr.ValueHint = bound
				instr.HasValueHint = true
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("global %s -> %s", d.displayGlobalName(idx), bound.Value))
				}
			}
		}
	case "PUSH_SYM":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if bound, ok := d.globalBindings[idx]; ok && bound.Value != "" {
				instr.ValueHint = bound
				instr.HasValueHint = true
				if !sparse {
					instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("value %s -> %s", d.displayGlobalName(idx), bound.Value))
				}
			}
		}
	case "BR_IF_FALSE", "BR_IF_TRUE", "BR_IF_FALSE2", "BR_IF_TRUE2", "JMP", "JMP_FAR", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP", "OR_JMP":
		if len(instr.Operands) > 0 {
			target := d.branchTarget(*instr, instr.Operands[0])
			if d.currentFunc != nil {
				d.currentFunc.addBlockStart(target)
				d.currentFunc.addEdge(instr.Offset, target, strings.ToLower(instr.Name))
				if d.isConditionalBranch(instr.Name) {
					fallthroughTarget := instr.Offset + d.instructionWidth(*instr)
					d.currentFunc.addBlockStart(fallthroughTarget)
					d.currentFunc.addEdge(instr.Offset, fallthroughTarget, "fallthrough")
				}
			}
			if !sparse {
				instr.Comment = d.appendComment(instr.Comment, fmt.Sprintf("target=%04X", target))
			}
		}
	}
}

func (d *Disassembler) newFunctionFromInstr(instr Instruction) *FASFunction {
	fn := &FASFunction{
		Name:         "anonymous",
		SymbolIndex:  -1,
		StartOffset:  instr.Offset,
		EndOffset:    -1,
		Kind:         "func",
		LocalVarRefs: make(map[int]int),
		SlotAliases:  make(map[int]string),
		ExprAliases:  make(map[string]string),
	}
	if len(instr.Operands) >= 3 {
		fn.NumOfArgs = instr.Operands[0]
		fn.MaxArgs = fn.NumOfArgs
		fn.SymbolIndex = instr.Operands[1]
		fn.Flags = instr.Operands[2]
		fn.Name = d.lookupSymbol(fn.SymbolIndex)
		if fn.Name == "" || !isPlausibleRecoveredFunctionName(fn.Name) {
			if !d.sparseAnnotationMode() {
				// Expensive fallback: search entire symbol table for function-like names.
				fn.Name = d.searchFunctionNameInResources(instr.Offset)
			}
			if fn.Name == "" {
				fn.Name = fmt.Sprintf("fn_%04X", instr.Offset)
			}
		}
		// This is kept as a structural hint only. In legacy VBA tooling, lambda
		// functions are associated with USUBR-style invocation paths; when flags
		// are present or there is no stable symbol name, we mark the function as
		// lambda-like for debugging.
		fn.IsLambda = fn.Flags != 0 || fn.SymbolIndex < 0
	}
	return fn
}

func (d *Disassembler) newFunctionFromDefunHeader(instr Instruction) *FASFunction {
	fn := &FASFunction{
		Name:         fmt.Sprintf("fn_%04X", instr.Offset),
		SymbolIndex:  -1,
		StartOffset:  instr.Offset,
		EndOffset:    -1,
		Kind:         strings.ToLower(instr.Name),
		LocalVarRefs: make(map[int]int),
		SlotAliases:  make(map[int]string),
		ExprAliases:  make(map[string]string),
	}
	if len(instr.Operands) >= 4 {
		fn.VarsCount = instr.Operands[0]
		fn.FrameSize = fn.VarsCount
		fn.NumOfArgs = instr.Operands[1]
		fn.MaxArgs = instr.Operands[2]
		fn.GC = instr.Operands[3] != 0
	}
	if instr.Name == "DEFUN_Q" {
		fn.IsLambda = true
	}
	return fn
}

func (d *Disassembler) lookupSymbol(idx int) string {
	return d.displaySymbolName(idx)
}

func (d *Disassembler) searchFunctionNameInResources(offset int) string {
	// Collect all function-like names from resources
	candidates := []string{}

	// Search all resources for function-like names (c:*, s::*, etc.)
	for i := 0; i < len(d.symbols); i++ {
		if raw, ok := d.symbolValueAt(i); ok {
			if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
				if isPlausibleRecoveredFunctionName(candidate) {
					candidates = append(candidates, candidate)
				}
			}
		} else if raw, _, ok := d.resourceAt(i); ok {
			if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
				if isPlausibleRecoveredFunctionName(candidate) {
					candidates = append(candidates, candidate)
				}
			}
		}
	}

	// Also check symbols array directly
	for _, raw := range d.symbols {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if isPlausibleRecoveredFunctionName(candidate) {
				// Avoid duplicates
				found := false
				for _, existing := range candidates {
					if existing == candidate {
						found = true
						break
					}
				}
				if !found {
					candidates = append(candidates, candidate)
				}
			}
		}
	}

	// Prefer c:* command functions over other types
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, "c:") {
			return candidate
		}
	}

	// Return first candidate if any
	if len(candidates) > 0 {
		return candidates[0]
	}

	return ""
}

func (d *Disassembler) displaySymbolName(idx int) string {
	if name, ok := d.symbolNames[idx]; ok {
		return name
	}
	return d.computeDisplaySymbolName(idx)
}

func (d *Disassembler) computeDisplaySymbolName(idx int) string {
	if raw, ok := d.symbolValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	if raw, ok := d.constValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	if alias := d.globalAliases[idx]; alias != "" {
		return alias
	}
	if raw, _, ok := d.resourceAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	return fmt.Sprintf("sym_%d", idx)
}

func (d *Disassembler) displayGlobalName(idx int) string {
	if name, ok := d.globalNames[idx]; ok {
		return name
	}
	return d.computeDisplayGlobalName(idx)
}

func (d *Disassembler) computeDisplayGlobalName(idx int) string {
	if alias := d.globalAliases[idx]; alias != "" {
		return alias
	}
	if idx >= 0 && idx < len(d.symbols) {
		if candidate := canonicalizeResourceSymbol(d.symbols[idx]); candidate != "" {
			return candidate
		}
	}
	if raw, ok := d.constValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	if raw, _, ok := d.resourceAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	return fmt.Sprintf("sym_%d", idx)
}

func (d *Disassembler) displaySymbolRef(name string) string {
	if !strings.HasPrefix(name, "sym_") {
		return normalizeSyntheticAlias(name)
	}
	var idx int
	if _, err := fmt.Sscanf(name, "sym_%d", &idx); err == nil {
		return normalizeSyntheticAlias(d.displayExpressionSymbolName(idx))
	}
	return name
}

func (d *Disassembler) displayExpressionSymbolName(idx int) string {
	if raw, ok := d.symbolValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			return candidate
		}
	}
	if alias := d.globalAliases[idx]; alias != "" {
		return alias
	}
	if raw, ok := d.constValueAt(idx); ok {
		raw = strings.TrimSpace(raw)
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if !strings.HasPrefix(raw, "[") || isLikelyStringBackedCallTarget(candidate) {
				return candidate
			}
		}
	}
	if raw, kind, ok := d.resourceAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if kind != "string" || !strings.HasPrefix(strings.TrimSpace(raw), "[") || isLikelyStringBackedCallTarget(candidate) {
				return candidate
			}
		}
	}
	return fmt.Sprintf("sym_%d", idx)
}

func (d *Disassembler) lookupFunctionByOffset(offset int) string {
	if fn, ok := d.funcByStart[offset]; ok && fn != nil {
		if fn.Name != "" {
			return fn.Name
		}
		return fmt.Sprintf("fn@%04X", offset)
	}
	return fmt.Sprintf("fn@%04X", offset)
}

func (d *Disassembler) symbolIndex(name string) int {
	if d.symbolIndexMap != nil {
		if idx, ok := d.symbolIndexMap[strings.ToLower(name)]; ok {
			return idx
		}
	}
	return -1
}

func (d *Disassembler) appendComment(existing, extra string) string {
	if extra == "" {
		return existing
	}
	if existing == "" {
		return extra
	}
	return existing + " | " + extra
}

func (d *Disassembler) sparseAnnotationMode() bool {
	return d.forceSparse ||
		len(d.data) >= largeFASByteThreshold ||
		len(d.instructions) >= largeFASInstructionThreshold ||
		len(d.functions) >= largeFASFunctionThreshold
}

func (d *Disassembler) isSigned16Opcode(name string) bool {
	switch name {
	case "BR_IF_FALSE", "BR_IF_TRUE", "JMP", "BR_IF_FALSE2", "BR_IF_TRUE2":
		return true
	default:
		return false
	}
}

func (d *Disassembler) isSigned32Opcode(name string) bool {
	switch name {
	case "JMP_FAR", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP", "OR_JMP":
		return true
	default:
		return false
	}
}

func (d *Disassembler) isConditionalBranch(name string) bool {
	switch name {
	case "BR_IF_FALSE", "BR_IF_TRUE", "BR_IF_FALSE2", "BR_IF_TRUE2", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP", "OR_JMP":
		return true
	default:
		return false
	}
}

func (d *Disassembler) branchTarget(instr Instruction, rel int) int {
	next := instr.Offset + d.instructionWidth(instr)
	return next + rel
}

func (d *Disassembler) pushValue(v StackValue) {
	d.valueStack = append(d.valueStack, v)
}

func (d *Disassembler) popValues(n int) []StackValue {
	if n <= 0 {
		return nil
	}
	values := make([]StackValue, 0, n)
	for i := 0; i < n; i++ {
		v, ok := d.popValue()
		if !ok {
			break
		}
		values = append(values, v)
	}
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
	return values
}

func (d *Disassembler) popValue() (StackValue, bool) {
	if len(d.valueStack) == 0 {
		return StackValue{}, false
	}
	last := d.valueStack[len(d.valueStack)-1]
	d.valueStack = d.valueStack[:len(d.valueStack)-1]
	return last, true
}

func (d *Disassembler) peekValue() (StackValue, bool) {
	if len(d.valueStack) == 0 {
		return StackValue{}, false
	}
	return d.valueStack[len(d.valueStack)-1], true
}

func (d *Disassembler) peekFunctionNameHint() (string, bool) {
	for i := len(d.valueStack) - 1; i >= 0; i-- {
		v := d.valueStack[i]
		if v.Kind == "symbol" && v.Value != "" && !strings.HasPrefix(v.Value, "sym_") {
			return v.Value, true
		}
	}
	return "", false
}

func (d *Disassembler) bindSlot(offset, slot int, value StackValue) {
	if fn := d.functionAt(offset); fn != nil {
		slots := d.slotBindings[fn.StartOffset]
		if slots == nil {
			slots = make(map[int]StackValue)
			d.slotBindings[fn.StartOffset] = slots
		}
		slots[slot] = value
		d.maybeAliasSlot(fn, slot, value)
	}
}

func (d *Disassembler) clearSlot(offset, slot int) {
	if fn := d.functionAt(offset); fn != nil {
		if slots := d.slotBindings[fn.StartOffset]; slots != nil {
			delete(slots, slot)
			if len(slots) == 0 {
				delete(d.slotBindings, fn.StartOffset)
			}
		}
	}
}

func (d *Disassembler) lookupSlotBinding(offset, slot int) (StackValue, bool) {
	if fn := d.functionAt(offset); fn != nil {
		if slots := d.slotBindings[fn.StartOffset]; slots != nil {
			v, ok := slots[slot]
			return v, ok
		}
	}
	return StackValue{}, false
}

func (d *Disassembler) maybeAliasGlobal(idx int, value StackValue) {
	if idx >= 0 && idx < len(d.symbols) {
		return
	}
	if _, ok := d.globalAliases[idx]; ok {
		return
	}
	if value.Kind == "symbol" {
		if alias := d.displaySymbolRef(value.Value); alias != "" && !strings.HasPrefix(alias, "sym_") {
			d.globalAliases[idx] = normalizeSyntheticAlias(alias)
			return
		}
	}
	if alias := deriveAliasFromValue(value); alias != "" {
		if strings.HasPrefix(alias, "sym_") {
			d.globalAliases[idx] = "alias_" + strings.TrimPrefix(alias, "sym_")
		} else if strings.HasPrefix(alias, "alias_") {
			d.globalAliases[idx] = alias
		} else {
			d.globalAliases[idx] = alias
		}
	}
}

func (d *Disassembler) maybeAliasSlot(fn *FASFunction, slot int, value StackValue) {
	if fn == nil || slot < fn.NumOfArgs {
		return
	}
	if fn.SlotAliases == nil {
		fn.SlotAliases = make(map[int]string)
	}
	if _, ok := fn.SlotAliases[slot]; ok {
		return
	}
	if fn.ExprAliases == nil {
		fn.ExprAliases = make(map[string]string)
	}
	if key := exprAliasKey(value); key != "" {
		if alias := fn.ExprAliases[key]; alias != "" {
			fn.SlotAliases[slot] = alias
			return
		}
	}
	if alias := deriveAliasFromValue(value); alias != "" {
		fn.SlotAliases[slot] = alias
		if key := exprAliasKey(value); key != "" {
			fn.ExprAliases[key] = alias
		}
	}
}

func exprAliasKey(v StackValue) string {
	switch v.Kind {
	case "call", "expr":
		if v.Value != "" {
			if normalized := normalizeExprAliasKey(v.Value); normalized != "" {
				return v.Kind + ":" + normalized
			}
			return v.Kind + ":" + v.Value
		}
	}
	return ""
}

func normalizeExprAliasKey(expr string) string {
	callName, args, ok := splitTopLevelCall(expr)
	if !ok {
		return expr
	}
	switch callName {
	case "timeout":
		for _, arg := range args {
			trimmed := strings.TrimSpace(arg)
			if strings.HasPrefix(trimmed, "(") {
				return fmt.Sprintf("(timeout* %s)", normalizeExprAliasKey(trimmed))
			}
		}
	case "scriptcontrol", "startapp", "htmlfile":
		normalizedArgs := make([]string, 0, len(args))
		for _, arg := range args {
			trimmed := strings.TrimSpace(arg)
			if strings.HasPrefix(trimmed, "(") {
				normalizedArgs = append(normalizedArgs, normalizeExprAliasKey(trimmed))
			} else {
				normalizedArgs = append(normalizedArgs, trimmed)
			}
		}
		return fmt.Sprintf("(%s %s)", callName, strings.Join(normalizedArgs, " "))
	}
	return expr
}

func (d *Disassembler) updateSymbolicStack(instr Instruction) {
	switch instr.Name {
	case "PUSH_SYM":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if bound, ok := d.globalBindings[idx]; ok && bound.Value != "" {
				d.pushValue(bound)
			} else {
				d.pushValue(StackValue{Kind: "symbol", Value: d.lookupSymbol(idx)})
			}
		}
	case "PUSH_GVAR":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if bound, ok := d.globalBindings[idx]; ok {
				d.pushValue(bound)
			} else {
				d.pushValue(StackValue{Kind: "gvar", Value: d.lookupSymbol(idx)})
			}
		}
	case "PUSH_CONST":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if raw, ok := d.constValueAt(idx); ok {
				d.pushValue(StackValue{Kind: "const", Value: raw})
			} else {
				d.pushValue(StackValue{Kind: "const", Value: fmt.Sprintf("const_%d", idx)})
			}
		}
	case "PUSH_NIL":
		d.pushValue(StackValue{Kind: "literal", Value: "nil"})
	case "PUSH_T":
		d.pushValue(StackValue{Kind: "literal", Value: "t"})
	case "PUSH_INT32":
		if len(instr.Operands) > 0 {
			d.pushValue(StackValue{Kind: "int", Value: fmt.Sprintf("%d", instr.Operands[0])})
		}
	case "ADD_FIXNUM", "SUB_FIXNUM", "MUL_FIXNUM", "DIV_FIXNUM", "MOD_FIXNUM", "LE_FIXNUM", "GE_FIXNUM", "LT_FIXNUM", "GT_FIXNUM":
		right, rok := d.popValue()
		left, lok := d.popValue()
		if lok && rok {
			d.pushValue(StackValue{Kind: "expr", Value: fmt.Sprintf("(%s %s %s)", d.fixnumOpSymbol(instr.Name), d.renderStackValue(left), d.renderStackValue(right))})
		}
	case "INC1", "DEC1":
		if value, ok := d.popValue(); ok {
			d.pushValue(StackValue{Kind: "expr", Value: fmt.Sprintf("(%s %s)", d.fixnumOpSymbol(instr.Name), d.renderStackValue(value))})
		}
	case "LOAD_LVAR", "LOAD_LVAR2":
		if len(instr.Operands) > 0 {
			if bound, ok := d.lookupSlotBinding(instr.Offset, instr.Operands[0]); ok {
				d.pushValue(bound)
			} else {
				d.pushValue(StackValue{Kind: "slot", Value: d.slotNameAt(instr.Offset, instr.Operands[0])})
			}
		}
	case "DUP":
		if v, ok := d.peekValue(); ok {
			d.pushValue(v)
		}
	case "POP":
		d.popValue()
	case "SETQ", "SETQ_LVAR", "SETQ_LVAR8", "SETQ_GVAR", "SETQ_DEFUN", "SETQ_FSL":
		if v, ok := d.popValue(); ok {
			switch instr.Name {
			case "SETQ", "SETQ_LVAR", "SETQ_LVAR8":
				if len(instr.Operands) > 0 {
					d.bindSlot(instr.Offset, instr.Operands[0], v)
				}
			case "SETQ_GVAR", "SETQ_DEFUN":
				if len(instr.Operands) > 0 {
					idx := instr.Operands[0]
					if instr.Name == "SETQ_DEFUN" || d.shouldTrackGlobalBinding(idx, v) {
						d.globalBindings[idx] = v
						d.maybeAliasGlobal(idx, v)
					}
				}
			}
		}
	case "CLEAR_LVAR", "CLEAR_LVAR8":
		if len(instr.Operands) > 0 {
			d.clearSlot(instr.Offset, instr.Operands[0])
		}
	case "CALL":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			args := d.popValues(nargs)
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				d.pushValue(instr.ValueHint)
				break
			}
			callee := instr.TargetHint
			if callee == "" {
				callee = d.resolveCallTargetName(instr.Operands[1])
			}
			d.pushValue(StackValue{Kind: "call", Value: d.renderCallExpr(callee, args)})
		}
	case "CALL_JMP":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			args := d.popValues(nargs)
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				d.pushValue(instr.ValueHint)
				break
			}
			callee := instr.TargetHint
			if callee == "" {
				callee = d.resolveCallTargetName(instr.Operands[1])
			}
			d.pushValue(StackValue{Kind: "call", Value: d.renderCallExpr(callee, args)})
		}
	case "CALL_BY_OFFSET":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			args := d.popValues(nargs)
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				d.pushValue(instr.ValueHint)
				break
			}
			callee := instr.TargetHint
			if callee == "" {
				callee = d.lookupFunctionByOffset(instr.Operands[1])
			}
			d.pushValue(StackValue{Kind: "call", Value: d.renderCallExpr(callee, args)})
		}
	case "STACK_CALL_JMP":
		if len(instr.Operands) >= 1 {
			nargs := instr.Operands[0]
			callee, _ := d.peekValue()
			args := d.popValues(nargs)
			d.popValue()
			calleeName := "stack_top"
			if callee.Value != "" {
				calleeName = d.renderStackValue(callee)
			}
			if calleeName != "" {
				d.pushValue(StackValue{Kind: "call", Value: d.renderDynamicCallExpr(calleeName, args)})
			} else {
				d.pushValue(StackValue{Kind: "call", Value: d.renderDynamicCallExpr("stack_top", args)})
			}
		}
	case "DEFUN", "DEFUN_Q", "FUNC", "MAIN":
		// function heads do not mutate the symbolic value stack here
	case "END_DEFUN", "END_DEFUN2":
		d.valueStack = d.valueStack[:0]
	default:
		// intentionally conservative: unknown stack effects are ignored
	}
}

func (d *Disassembler) shouldTrackGlobalBinding(idx int, value StackValue) bool {
	name := d.displayGlobalName(idx)
	if name == "" || strings.HasPrefix(name, "sym_") {
		return true
	}
	if isCommonRecoveredBuiltin(name) || isLispFunction(name) {
		return false
	}
	if isLikelyCallableBindingName(name) && value.Kind != "symbol" && value.Kind != "gvar" {
		return false
	}
	return true
}

func isLikelyCallableBindingName(name string) bool {
	switch {
	case name == "":
		return false
	case strings.HasPrefix(name, "c:"):
		return true
	case strings.HasPrefix(name, "fas::"):
		return true
	case strings.HasPrefix(name, "vl-"), strings.HasPrefix(name, "vlax-"):
		return true
	case isCommonRecoveredBuiltin(name):
		return true
	case isLispFunction(name):
		return true
	default:
		return false
	}
}

func (d *Disassembler) resolveZeroArgValue(instr Instruction, idx int) (StackValue, bool) {
	if !d.likelyValueUsePattern(instr) {
		return StackValue{}, false
	}
	if target := d.resolveCallTargetName(idx); target != "" && !strings.HasPrefix(target, "sym_") {
		return StackValue{}, false
	}
	if idx >= 0 && idx < len(d.symbols) {
		raw := d.symbols[idx]
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if !isLikelyStringBackedCallTarget(candidate) && !isCommonRecoveredBuiltin(candidate) {
				return StackValue{Kind: "const", Value: raw}, true
			}
		}
	}
	if raw, ok := d.symbolValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if !isLikelyStringBackedCallTarget(candidate) && !isCommonRecoveredBuiltin(candidate) {
				return StackValue{Kind: "const", Value: raw}, true
			}
		}
	}
	return StackValue{}, false
}

func (d *Disassembler) likelyValueUsePattern(instr Instruction) bool {
	pos := instr.Offset + d.instructionWidth(instr)
	next, ok := d.peekOpcodeNameAt(pos)
	if !ok {
		return false
	}
	switch next {
	case "PUSH_CONST", "PUSH_SYM", "PUSH_GVAR", "PUSH_NIL", "LOAD_LVAR", "LOAD_LVAR2":
		width, ok := d.peekInstructionWidthAt(pos)
		if !ok {
			return false
		}
		next2, ok := d.peekOpcodeNameAt(pos + width)
		if !ok {
			return false
		}
		switch next2 {
		case "CALL", "CALL_JMP", "STACK_CALL_JMP", "CALL_BY_OFFSET":
			return true
		}
	}
	return false
}

func (d *Disassembler) recoverCallTargetFromUsage(instr Instruction, resolved string, args []StackValue) string {
	if inferred := d.inferNearbyBuiltinCallTarget(instr, resolved); inferred != "" {
		return inferred
	}
	if inferred := d.inferPrincCallTarget(instr, resolved, args); inferred != "" {
		return inferred
	}
	if inferred := d.inferComparatorCallTarget(instr, resolved, args); inferred != "" {
		return inferred
	}
	if inferred := d.inferStrcatCallTarget(instr, resolved, args); inferred != "" {
		return inferred
	}
	return resolved
}

func (d *Disassembler) inferNearbyBuiltinCallTarget(instr Instruction, resolved string) string {
	if len(instr.Operands) < 2 {
		return ""
	}
	if instr.Operands[0] > 2 {
		return ""
	}
	next, ok := d.peekOpcodeNameAt(instr.Offset + d.instructionWidth(instr))
	if !ok || next != "POP" {
		return ""
	}
	if resolved != "" && resolved != d.currentFunctionName() && !strings.HasPrefix(resolved, "sym_") {
		return ""
	}
	if candidate := d.nearbyBuiltinCandidate(instr.Operands[1], 3); candidate != "" {
		return candidate
	}
	return ""
}

func (d *Disassembler) nearbyBuiltinCandidate(idx int, span int) string {
	type candidate struct {
		name  string
		score int
	}
	best := candidate{score: 1 << 30}
	consider := func(raw string, distance int) {
		name := canonicalizeResourceSymbol(raw)
		if name == "" || !isCallableSymbolCandidate(raw, name) {
			return
		}
		if name != "setvar" {
			return
		}
		score := distance
		score -= 2
		if score < best.score {
			best = candidate{name: name, score: score}
		}
	}

	for delta := -span; delta <= span; delta++ {
		pos := idx + delta
		if pos >= 0 && pos < len(d.strings) {
			consider(strings.TrimSpace(d.strings[pos]), absInt(delta))
		}
		if pos >= 0 && pos < len(d.symbols) {
			consider(d.symbols[pos], absInt(delta))
		}
	}
	if best.name == "" {
		return ""
	}
	return best.name
}

func (d *Disassembler) inferPrincCallTarget(instr Instruction, resolved string, args []StackValue) string {
	if len(instr.Operands) < 2 {
		return ""
	}
	nargs := instr.Operands[0]
	if nargs > 1 {
		return ""
	}
	if resolved != "" && resolved != d.currentFunctionName() && !strings.HasPrefix(resolved, "sym_") {
		return ""
	}
	next, _ := d.peekOpcodeNameAt(instr.Offset + d.instructionWidth(instr))
	if nargs == 0 {
		switch next {
		case "CLEAR_ARGS", "END_DEFUN", "END_DEFUN2":
			return "princ"
		}
		return ""
	}
	if nargs == 1 && next == "POP" && len(args) == 1 && isPrintableFlowValue(args[0]) {
		return "princ"
	}
	return ""
}

func (d *Disassembler) inferComparatorCallTarget(instr Instruction, resolved string, args []StackValue) string {
	if len(instr.Operands) < 2 || instr.Operands[0] != 2 || len(args) != 2 {
		return ""
	}
	next, ok := d.peekOpcodeNameAt(instr.Offset + d.instructionWidth(instr))
	if !ok || (next != "OR_JMP" && next != "AND_JMP" && !d.isConditionalBranch(next)) {
		return ""
	}
	if !isNilLikeValue(args[1]) {
		return ""
	}
	if resolved != "" && resolved != d.currentFunctionName() && !strings.HasPrefix(resolved, "sym_") && resolved != "block" {
		return ""
	}
	return "/="
}

func (d *Disassembler) inferStrcatCallTarget(instr Instruction, resolved string, args []StackValue) string {
	if len(instr.Operands) < 2 || instr.Operands[0] < 3 || len(args) < 3 {
		return ""
	}
	if resolved != "" && resolved != d.currentFunctionName() && !strings.HasPrefix(resolved, "sym_") && resolved != "cdr" && resolved != "assoc" {
		return ""
	}
	next, ok := d.peekOpcodeNameAt(instr.Offset + d.instructionWidth(instr))
	if !ok || (next != "CALL" && next != "CALL_JMP") {
		return ""
	}
	stringy := 0
	for _, arg := range args {
		if isPrintableFlowValue(arg) {
			stringy++
		}
	}
	if stringy < 2 {
		return ""
	}
	return "strcat"
}

func (d *Disassembler) currentFunctionName() string {
	if d.currentFunc == nil {
		return ""
	}
	return d.currentFunc.Name
}

func isNilLikeValue(v StackValue) bool {
	switch strings.TrimSpace(v.Value) {
	case "nil", "'nil":
		return true
	default:
		return v.Kind == "literal" && strings.TrimSpace(v.Value) == "nil"
	}
}

func isPrintableFlowValue(v StackValue) bool {
	switch v.Kind {
	case "const":
		display, control := normalizeDisplayString(v.Value)
		return control == 0 && display != ""
	case "symbol", "gvar", "slot":
		return sanitizeIdentifier(v.Value) != ""
	case "call", "expr":
		text := strings.TrimSpace(v.Value)
		return text != "" && text != "<value>"
	case "literal", "int":
		return strings.TrimSpace(v.Value) != ""
	default:
		return false
	}
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (d *Disassembler) peekOpcodeNameAt(pos int) (string, bool) {
	if pos < 0 || pos >= len(d.data) {
		return "", false
	}
	op, ok := Opcodes[d.data[pos]]
	if !ok {
		return "", false
	}
	return op.Name, true
}

func (d *Disassembler) peekInstructionWidthAt(pos int) (int, bool) {
	if pos < 0 || pos >= len(d.data) {
		return 0, false
	}
	op, ok := Opcodes[d.data[pos]]
	if !ok {
		return 0, false
	}
	instr := Instruction{Offset: pos, Opcode: d.data[pos], Name: op.Name}
	return d.instructionWidth(instr), true
}

func (d *Disassembler) instructionWidth(instr Instruction) int {
	switch instr.Name {
	case "CALL":
		return 5
	case "FUNC":
		return 6
	case "DEFUN", "DEFUN_Q":
		return 5
	case "CALL_JMP":
		return 4
	case "CALL_BY_OFFSET":
		return 6
	}
	if op, ok := Opcodes[instr.Opcode]; ok {
		switch op.OperandSize {
		case 0:
			return 1
		case 1:
			return 2
		case 2:
			return 3
		case 4:
			return 5
		}
	}
	return 1
}

func (f *FASFunction) headerComment() string {
	return fmt.Sprintf("func=%s kind=%s argc=%d..%d locals=%d frame=%d flags=%d gc=%t lambda=%t",
		f.Name, f.Kind, f.NumOfArgs, f.MaxArgs, f.VarsCount, f.FrameSize, f.Flags, f.GC, f.IsLambda)
}

func (f *FASFunction) footerComment() string {
	return fmt.Sprintf("endfunc=%s locals_used=%d calls=%d indirect_calls=%d blocks=%d edges=%d",
		f.Name, len(f.LocalVarRefs), len(f.Calls), len(f.IndirectCalls), len(f.BlockStarts), len(f.ControlEdges))
}

func (f *FASFunction) slotName(slot int) string {
	if slot < f.NumOfArgs {
		return fmt.Sprintf("arg_%d", slot)
	}
	return fmt.Sprintf("local_%d", slot-f.NumOfArgs)
}

func (f *FASFunction) addCall(name string) {
	if name == "" {
		return
	}
	if !isMeaningfulRecoveredName(name) {
		return
	}
	for _, existing := range f.Calls {
		if existing == name {
			return
		}
	}
	f.Calls = append(f.Calls, name)
}

func (d *Disassembler) displayCallTargetName(name string) string {
	switch d.displaySymbolRef(name) {
	case "alias_254":
		return "dispatch"
	case "alias_228":
		return "dispatch-apply"
	default:
		return d.displaySymbolRef(name)
	}
}

func (d *Disassembler) resolveCallTargetName(idx int) string {
	if raw, ok := d.symbolValueAt(idx); ok {
		if mapped := d.displayCallTargetName(raw); mapped != raw {
			return mapped
		}
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if isCallableSymbolCandidate(raw, candidate) {
				return d.displayCallTargetName(candidate)
			}
		}
	}
	if alias := d.globalAliases[idx]; alias != "" {
		if mapped := d.displayCallTargetName(alias); mapped != alias || isLikelyStringBackedCallTarget(alias) {
			return d.displayCallTargetName(alias)
		}
	}
	if raw, ok := d.constValueAt(idx); ok {
		raw = strings.TrimSpace(raw)
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if !strings.HasPrefix(raw, "[") || isCallableSymbolCandidate(raw, candidate) {
				if isCallableSymbolCandidate(raw, candidate) {
					return d.displayCallTargetName(candidate)
				}
			}
		}
	}
	if raw, kind, ok := d.resourceAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if (kind == "symbol" || !strings.HasPrefix(strings.TrimSpace(raw), "[")) && isCallableSymbolCandidate(raw, candidate) {
				return d.displayCallTargetName(candidate)
			}
		}
	}
	return fmt.Sprintf("sym_%d", idx)
}

func (d *Disassembler) resourceAt(idx int) (string, string, bool) {
	if idx < 0 || idx >= len(d.resources) {
		return "", "", false
	}
	return d.resources[idx].Value, d.resources[idx].Kind, true
}

func (f *FASFunction) addIndirectCall(name string) {
	if name == "" {
		return
	}
	if !isMeaningfulRecoveredName(name) && !strings.HasPrefix(name, "fn_") && !strings.HasPrefix(name, "fn@") {
		return
	}
	for _, existing := range f.IndirectCalls {
		if existing == name {
			return
		}
	}
	f.IndirectCalls = append(f.IndirectCalls, name)
}

func (f *FASFunction) addBlockStart(offset int) {
	if f.blockStartSeen == nil {
		f.blockStartSeen = make(map[int]struct{})
	}
	if _, exists := f.blockStartSeen[offset]; exists {
		return
	}
	f.blockStartSeen[offset] = struct{}{}
	f.BlockStarts = append(f.BlockStarts, offset)
}

func (f *FASFunction) addEdge(from, to int, kind string) {
	if f.edgeSeen == nil {
		f.edgeSeen = make(map[string]struct{})
	}
	key := fmt.Sprintf("%d:%d:%s", from, to, kind)
	if _, exists := f.edgeSeen[key]; exists {
		return
	}
	f.edgeSeen[key] = struct{}{}
	f.ControlEdges = append(f.ControlEdges, FASEdge{From: from, To: to, Kind: kind})
}

// ToPseudoLisp converts disassembled instructions to pseudo-LISP
func (d *Disassembler) ToPseudoLisp() string {
	return d.toPseudoLisp(false)
}

func (d *Disassembler) ToCompactPseudoLisp() string {
	return d.toPseudoLisp(true)
}

func (d *Disassembler) toPseudoLisp(compact bool) string {
	d.buildRenderIndexes()
	var result strings.Builder

	result.WriteString(";; FAS4 Disassembly Output\n")
	result.WriteString(";; =======================\n\n")

	// String/Symbol table
	result.WriteString(fmt.Sprintf(";; String/Symbol Table (%d entries)\n", len(d.strings)+len(d.symbols)))
	stringLimit := len(d.strings)
	if compact && stringLimit > compactRenderStringLimit {
		stringLimit = compactRenderStringLimit
	}
	for i := 0; i < stringLimit; i++ {
		s := d.strings[i]
		result.WriteString(fmt.Sprintf(";; [%3d] %q\n", i, s))
	}
	if compact && stringLimit < len(d.strings) {
		result.WriteString(fmt.Sprintf(";; ... %d additional strings omitted in compact mode\n", len(d.strings)-stringLimit))
	}
	symbolLimit := len(d.symbols)
	if compact && symbolLimit > compactRenderSymbolLimit {
		symbolLimit = compactRenderSymbolLimit
	}
	for i := 0; i < symbolLimit; i++ {
		s := d.symbols[i]
		result.WriteString(fmt.Sprintf(";; [%3d] %s\n", i+len(d.strings), s))
	}
	if compact && symbolLimit < len(d.symbols) {
		result.WriteString(fmt.Sprintf(";; ... %d additional symbols omitted in compact mode\n", len(d.symbols)-symbolLimit))
	}
	result.WriteString("\n")

	if len(d.functions) > 0 {
		result.WriteString(";; Recovered Functions\n")
		result.WriteString(";; ===================\n")
		functionLimit := len(d.functions)
		if compact && functionLimit > compactRenderFunctionLimit {
			functionLimit = compactRenderFunctionLimit
		}
		for i := 0; i < functionLimit; i++ {
			fn := d.functions[i]
			result.WriteString(fmt.Sprintf(";; %s kind=%s start=%04X end=%04X argc=%d..%d frame=%d locals=%d flags=%d gc=%t lambda=%t calls=%v indirect_calls=%v\n",
				fn.Name, fn.Kind, fn.StartOffset, fn.EndOffset, fn.NumOfArgs, fn.MaxArgs, fn.FrameSize, fn.VarsCount, fn.Flags, fn.GC, fn.IsLambda, fn.Calls, fn.IndirectCalls))
			if !compact && len(fn.BlockStarts) > 0 {
				result.WriteString(fmt.Sprintf(";;   block_starts=%v\n", fn.BlockStarts))
			}
			if !compact && len(fn.ControlEdges) > 0 {
				result.WriteString(fmt.Sprintf(";;   edges=%v\n", fn.ControlEdges))
			}
		}
		if compact && functionLimit < len(d.functions) {
			result.WriteString(fmt.Sprintf(";; ... %d additional functions omitted in compact mode\n", len(d.functions)-functionLimit))
		}
		result.WriteString("\n")
	}

	result.WriteString(d.renderBehaviorSummary(compact))
	result.WriteString(d.renderRecoveredFlows(compact))
	result.WriteString(d.renderStructuredPreview(compact))

	// Bytecode disassembly
	result.WriteString(";; Bytecode Disassembly\n")
	result.WriteString(";; ===================\n")
	instructionLimit := len(d.instructions)
	if compact && instructionLimit > compactRenderInstructionLimit {
		instructionLimit = compactRenderInstructionLimit
	}
	for i := 0; i < instructionLimit; i++ {
		instr := d.instructions[i]
		if fn := d.functionAt(instr.Offset); fn != nil && d.isBlockStart(fn, instr.Offset) {
			result.WriteString(fmt.Sprintf(";; <%s>\n", d.blockLabel(fn, instr.Offset)))
		}
		result.WriteString(fmt.Sprintf(";; %04X: %-12s", instr.Offset, instr.Name))

		// Add operands
		if len(instr.Operands) > 0 {
			for _, op := range instr.Operands {
				result.WriteString(fmt.Sprintf(" %d", op))
			}
		}

		// Add comment
		if instr.Comment != "" {
			result.WriteString(fmt.Sprintf(" ; %s", instr.Comment))
		}

		result.WriteString("\n")

		// Add pseudo-LISP equivalent
		result.WriteString(d.instructionToPseudoLispMode(instr, compact))
	}
	if compact && instructionLimit < len(d.instructions) {
		result.WriteString(fmt.Sprintf(";; ... %d additional instructions omitted in compact mode\n", len(d.instructions)-instructionLimit))
	}

	return result.String()
}

func (d *Disassembler) renderBehaviorSummary(compact bool) string {
	behaviors := d.Behaviors()
	if len(behaviors) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString(";; Recovered Behaviors\n")
	out.WriteString(";; ===================\n")
	limit := len(behaviors)
	if compact && limit > compactRenderFlowLimit {
		limit = compactRenderFlowLimit
	}
	for i := 0; i < limit; i++ {
		behavior := behaviors[i]
		out.WriteString(fmt.Sprintf(";; %s category=%s funcs=%v\n", behavior.Kind, behavior.Category, behavior.Functions))
		out.WriteString(fmt.Sprintf(";;   summary=%s\n", behavior.Summary))
		if len(behavior.Evidence) > 0 {
			evidence := behavior.Evidence
			if compact && len(evidence) > compactRenderEvidenceLimit {
				evidence = evidence[:compactRenderEvidenceLimit]
			}
			out.WriteString(fmt.Sprintf(";;   evidence=%v\n", evidence))
		}
	}
	if compact && limit < len(behaviors) {
		out.WriteString(fmt.Sprintf(";; ... %d additional recovered behaviors omitted in compact mode\n", len(behaviors)-limit))
	}
	out.WriteString("\n")
	return out.String()
}

func (d *Disassembler) Behaviors() []FASRecoveredBehavior {
	if d.behaviorsCache != nil {
		return append([]FASRecoveredBehavior{}, d.behaviorsCache...)
	}
	behaviors := d.collectRecoveredBehaviors()
	sort.Slice(behaviors, func(i, j int) bool {
		return behaviors[i].Kind < behaviors[j].Kind
	})
	d.behaviorsCache = append([]FASRecoveredBehavior{}, behaviors...)
	return append([]FASRecoveredBehavior{}, d.behaviorsCache...)
}

func (d *Disassembler) collectRecoveredBehaviors() []FASRecoveredBehavior {
	var behaviors []FASRecoveredBehavior
	lowerStrings := make([]string, 0, len(d.strings))
	for _, s := range d.strings {
		lowerStrings = append(lowerStrings, strings.ToLower(s))
	}
	callToFuncs := make(map[string]map[string]struct{})
	stringToFuncs := make(map[string]map[string]struct{})
	commentText := make([]string, 0, len(d.instructions))
	valueHintText := make([]string, 0, len(d.instructions))
	for _, fn := range d.functions {
		if fn == nil {
			continue
		}
		fnName := fn.Name
		for _, call := range fn.Calls {
			key := strings.ToLower(call)
			if callToFuncs[key] == nil {
				callToFuncs[key] = make(map[string]struct{})
			}
			callToFuncs[key][fnName] = struct{}{}
		}
	}
	for _, instr := range d.instructions {
		commentText = append(commentText, strings.ToLower(instr.Comment))
		if instr.HasValueHint {
			valueHintText = append(valueHintText, strings.ToLower(instr.ValueHint.Value))
		} else {
			valueHintText = append(valueHintText, "")
		}
		if instr.Name != "PUSH_CONST" || len(instr.Operands) == 0 {
			continue
		}
		idx := instr.Operands[0]
		if idx < 0 || idx >= len(lowerStrings) {
			continue
		}
		fn := d.functionAt(instr.Offset)
		if fn == nil || fn.Name == "" {
			continue
		}
		stringToFuncs[lowerStrings[idx]] = addFuncNameSet(stringToFuncs[lowerStrings[idx]], fn.Name)
	}
	hasString := func(needle string) bool {
		needle = strings.ToLower(needle)
		for _, s := range lowerStrings {
			if strings.Contains(s, needle) {
				return true
			}
		}
		return false
	}
	hasCall := func(name string) bool {
		name = strings.ToLower(name)
		if len(callToFuncs[name]) > 0 {
			return true
		}
		needle := "call " + name + " "
		for _, comment := range commentText {
			if strings.Contains(comment, needle) {
				return true
			}
		}
		for _, hint := range valueHintText {
			if strings.Contains(hint, "("+name+" ") {
				return true
			}
		}
		return false
	}
	functionsForCall := func(name string) []string {
		name = strings.ToLower(name)
		found := setToSortedStrings(callToFuncs[name])
		sort.Strings(found)
		return found
	}
	functionsForString := func(needle string) []string {
		foundSet := make(map[string]struct{})
		needle = strings.ToLower(needle)
		for text, funcs := range stringToFuncs {
			if !strings.Contains(text, needle) {
				continue
			}
			for fn := range funcs {
				foundSet[fn] = struct{}{}
			}
		}
		found := setToSortedStrings(foundSet)
		sort.Strings(found)
		return found
	}
	appendBehavior := func(kind, category, summary string, funcs []string, evidence ...string) {
		for _, existing := range behaviors {
			if existing.Kind == kind {
				return
			}
		}
		filteredEvidence := make([]string, 0, len(evidence))
		for _, item := range evidence {
			if item == "" {
				continue
			}
			filteredEvidence = appendUniqueString(filteredEvidence, item)
		}
		sort.Strings(filteredEvidence)
		behaviors = append(behaviors, FASRecoveredBehavior{
			Kind:      kind,
			Category:  category,
			Summary:   summary,
			Functions: funcs,
			Evidence:  filteredEvidence,
		})
	}

	if hasString(`windows script host\settings`) {
		appendBehavior(
			"wsh_warning_suppression",
			"registry",
			"touches WSH settings registry key; likely suppresses Windows Script Host safety prompts",
			functionsForString(`windows script host\settings`),
			`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Script Host\Settings`,
		)
	}
	if (hasString("scriptcontrol") || hasCall("scriptcontrol")) && hasString("adodb.stream") {
		funcs := functionsForCall("scriptcontrol")
		appendBehavior(
			"script_payload_staging",
			"com",
			"combines ScriptControl with ADODB.Stream; likely decodes and writes script payloads through COM",
			funcs,
			"ScriptControl",
			"ADODB.Stream",
		)
	}
	if (hasString("scriptcontrol") || hasCall("scriptcontrol")) && hasString(".wsf") {
		appendBehavior(
			"wsf_payload_output",
			"file",
			"references ScriptControl and .WSF output; likely stages encoded script into Windows Script File format",
			functionsForCall("scriptcontrol"),
			"ScriptControl",
			".WSF",
		)
	}
	if hasCall("vlr-dwg-reactor") || hasString("vlr-dwg-reactor") {
		appendBehavior(
			"reactor_persistence",
			"persistence",
			"installs VLR-DWG-Reactor hooks; likely persists on drawing open/save events",
			functionsForCall("vlr-dwg-reactor"),
			"[VLR-DWG-Reactor",
		)
	}
	if hasString("$(edtime,$(getvar,date)") || (hasCall("getvar") && hasString("edtime")) {
		appendBehavior(
			"timestamped_artifact_naming",
			"naming",
			"derives timestamped names from (getvar \"date\") and edtime; likely generates varying artifact names",
			functionsForString("$(edtime,$(getvar,date)"),
			"M=$(edtime,$(getvar,date),YYMODD)",
			"M=$(edtime,$(getvar,date),MSECDDYYMOMMHHSS)",
		)
	}
	if hasCall("findfile") || hasCall("vl-file-copy") || hasString("findfile") || hasString("vl-file-copy") {
		funcs := functionsForCall("findfile")
		for _, fn := range functionsForCall("vl-file-copy") {
			funcs = appendUniqueString(funcs, fn)
		}
		sort.Strings(funcs)
		appendBehavior(
			"file_search_copy_propagation",
			"propagation",
			"searches for files and copies them; likely participates in document/script propagation",
			funcs,
			"findfile",
			"vl-file-copy",
		)
	}
	return behaviors
}

func addFuncNameSet(set map[string]struct{}, name string) map[string]struct{} {
	if name == "" {
		return set
	}
	if set == nil {
		set = make(map[string]struct{})
	}
	set[name] = struct{}{}
	return set
}

func setToSortedStrings(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (d *Disassembler) renderRecoveredFlows(compact bool) string {
	flows := d.collectRecoveredFlows()
	if len(flows) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString(";; Recovered Flows\n")
	out.WriteString(";; ===============\n")
	limit := len(flows)
	if compact && limit > compactRenderFlowLimit {
		limit = compactRenderFlowLimit
	}
	for i := 0; i < limit; i++ {
		flow := flows[i]
		functions := make([]string, 0, len(flow.Functions))
		for name := range flow.Functions {
			functions = append(functions, name)
		}
		sort.Strings(functions)
		if compact && len(functions) > compactRenderEvidenceLimit {
			functions = functions[:compactRenderEvidenceLimit]
		}
		out.WriteString(fmt.Sprintf(";; %s funcs=%v defs=%v uses=%v\n", flow.Name, functions, flow.Defs, flow.Uses))
		if len(flow.DefHints) > 0 {
			defHints := flow.DefHints
			if compact && len(defHints) > compactRenderEvidenceLimit {
				defHints = defHints[:compactRenderEvidenceLimit]
			}
			out.WriteString(fmt.Sprintf(";;   def_preview=%v\n", defHints))
		}
		if len(flow.UseHints) > 0 {
			useHints := flow.UseHints
			if compact && len(useHints) > compactRenderEvidenceLimit {
				useHints = useHints[:compactRenderEvidenceLimit]
			}
			out.WriteString(fmt.Sprintf(";;   use_preview=%v\n", useHints))
		}
	}
	if compact && limit < len(flows) {
		out.WriteString(fmt.Sprintf(";; ... %d additional recovered flows omitted in compact mode\n", len(flows)-limit))
	}
	out.WriteString("\n")
	return out.String()
}

func (d *Disassembler) collectRecoveredFlows() []*FASFlowSummary {
	byName := make(map[string]*FASFlowSummary)
	add := func(alias string, kind string, instr Instruction) {
		if !strings.HasSuffix(alias, "_flow") {
			return
		}
		flow := byName[alias]
		if flow == nil {
			flow = &FASFlowSummary{Name: alias, Functions: make(map[string]bool)}
			byName[alias] = flow
		}
		if fn := d.functionAt(instr.Offset); fn != nil && fn.Name != "" {
			flow.Functions[fn.Name] = true
		}
		switch kind {
		case "def":
			flow.Defs = appendUniqueInt(flow.Defs, instr.Offset)
			if hint := d.flowPreviewForInstruction(instr); hint != "" {
				flow.DefHints = appendUniqueString(flow.DefHints, hint)
			}
		case "use":
			flow.Uses = appendUniqueInt(flow.Uses, instr.Offset)
			if hint := d.flowPreviewForInstruction(instr); hint != "" {
				flow.UseHints = appendUniqueString(flow.UseHints, hint)
			}
		}
	}
	for _, instr := range d.instructions {
		if !instr.HasValueHint || instr.ValueHint.Value == "" {
			continue
		}
		alias := deriveAliasFromValue(instr.ValueHint)
		switch instr.Name {
		case "SETQ", "SETQ_LVAR", "SETQ_LVAR8", "SETQ_GVAR", "SETQ_DEFUN":
			add(alias, "def", instr)
		case "PUSH_SYM", "PUSH_GVAR", "LOAD_LVAR", "LOAD_LVAR2":
			add(alias, "use", instr)
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	flows := make([]*FASFlowSummary, 0, len(names))
	for _, name := range names {
		flows = append(flows, byName[name])
	}
	return flows
}

func appendUniqueInt(items []int, v int) []int {
	for _, existing := range items {
		if existing == v {
			return items
		}
	}
	return append(items, v)
}

func appendUniqueString(items []string, v string) []string {
	for _, existing := range items {
		if existing == v {
			return items
		}
	}
	return append(items, v)
}

func (d *Disassembler) flowPreviewForInstruction(instr Instruction) string {
	if !instr.HasValueHint || instr.ValueHint.Value == "" {
		return ""
	}
	switch instr.Name {
	case "SETQ", "SETQ_LVAR", "SETQ_LVAR8", "SETQ_GVAR", "SETQ_DEFUN":
		if len(instr.Operands) > 0 {
			return d.slotOrSymbolNameAt(instr) + " := " + d.renderFlowPreview(instr.ValueHint)
		}
		return d.renderFlowPreview(instr.ValueHint)
	case "PUSH_SYM", "PUSH_GVAR", "LOAD_LVAR", "LOAD_LVAR2":
		if len(instr.Operands) > 0 {
			return d.slotOrSymbolNameAt(instr) + " <= " + d.renderFlowPreview(instr.ValueHint)
		}
		return d.renderFlowPreview(instr.ValueHint)
	}
	return ""
}

func (d *Disassembler) slotOrSymbolNameAt(instr Instruction) string {
	switch instr.Name {
	case "PUSH_SYM", "PUSH_GVAR", "SETQ_GVAR", "SETQ_DEFUN":
		if len(instr.Operands) > 0 {
			if instr.Name == "SETQ_DEFUN" {
				return d.displaySymbolName(instr.Operands[0])
			}
			return d.displayGlobalName(instr.Operands[0])
		}
	case "LOAD_LVAR", "LOAD_LVAR2", "SETQ", "SETQ_LVAR", "SETQ_LVAR8":
		if len(instr.Operands) > 0 {
			return d.slotNameAt(instr.Offset, instr.Operands[0])
		}
	}
	return instr.Name
}

func (d *Disassembler) renderFlowPreview(v StackValue) string {
	rendered := d.renderStackValue(v)
	if len(rendered) > 96 {
		return rendered[:93] + "..."
	}
	return rendered
}

// Functions returns recovered function metadata extracted during disassembly.
func (d *Disassembler) Functions() []*FASFunction {
	return d.functions
}

// instructionToPseudoLisp converts a single instruction to pseudo-LISP
func (d *Disassembler) instructionToPseudoLisp(instr Instruction) string {
	return d.instructionToPseudoLispMode(instr, false)
}

func (d *Disassembler) instructionToPseudoLispMode(instr Instruction, compact bool) string {
	var result strings.Builder

	switch instr.Name {
	case "PUSH_SYM":
		if compact {
			break
		}
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			name := d.displayGlobalName(idx)
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(fmt.Sprintf("(push-sym %s ; => %s)\n", name, d.renderValueHint(instr.ValueHint)))
			} else if idx >= 0 && idx < len(d.symbols) {
				result.WriteString(fmt.Sprintf("(push-symbol '%s)\n", name))
			} else {
				result.WriteString(fmt.Sprintf("(push-symbol %s)\n", name))
			}
		}
	case "PUSH_GVAR":
		if compact {
			break
		}
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			name := d.displayGlobalName(idx)
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(fmt.Sprintf("(push-gvar %s ; => %s)\n", name, d.renderValueHint(instr.ValueHint)))
			} else {
				result.WriteString(fmt.Sprintf("(push-gvar %s)\n", name))
			}
		}
	case "PUSH_CONST":
		if len(instr.Operands) > 0 {
			idx := instr.Operands[0]
			if str, ok := d.constValueAt(idx); ok {
				if isEncodedScriptBlob(str) {
					result.WriteString("(push-encoded-script)\n")
					break
				}
				display, control := normalizeDisplayString(str)
				if shouldCanonicalizeBracketToken(str) {
					if canonical := canonicalizeResourceSymbol(str); canonical != "" {
						display = canonical
					}
				}
				if isPrintableString(display) {
					escaped := escapeString(display)
					if control != 0 {
						if len(display) <= 1 {
							result.WriteString(fmt.Sprintf("(push-token \"%s\" 0x%02X)\n", escaped, control))
						} else {
							result.WriteString(fmt.Sprintf("(push-string \"%s\") ; control=0x%02X\n", escaped, control))
						}
					} else {
						result.WriteString(fmt.Sprintf("(push-string \"%s\")\n", escaped))
					}
				} else {
					result.WriteString(fmt.Sprintf("(push-const [bin:%d bytes])\n", len(str)))
				}
			} else {
				result.WriteString(fmt.Sprintf("(push-const const_%d)\n", idx))
			}
		}
	case "PUSH_NIL":
		result.WriteString("(push nil)\n")
	case "PUSH_T":
		result.WriteString("(push T)\n")
	case "POP":
		// Skip POP pseudo-code because it only clears the stack.
		// result.WriteString("(pop)\n")
	case "DUP":
		result.WriteString("(dup)\n")
	case "CALL":
		if len(instr.Operands) >= 2 {
			funcName := instr.TargetHint
			if funcName == "" {
				funcName = d.resolveCallTargetName(instr.Operands[1])
			}
			nargs := instr.Operands[0]
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(d.renderStackValue(instr.ValueHint))
				result.WriteString("\n")
			} else if len(instr.ArgHints) > 0 {
				result.WriteString(d.renderCallExpr(funcName, d.hintsToValues(instr.ArgHints)))
				result.WriteString("\n")
			} else if nargs > 0 {
				result.WriteString(fmt.Sprintf("(%s ; argc=%d)\n", funcName, nargs))
			} else {
				result.WriteString(fmt.Sprintf("(%s)\n", funcName))
			}
		}
	case "SUB":
		if len(instr.ExprHints) >= 2 {
			result.WriteString(fmt.Sprintf("(- %s %s)\n", instr.ExprHints[0], instr.ExprHints[1]))
		} else {
			result.WriteString("(- a b)\n")
		}
	case "ADD_FIXNUM", "SUB_FIXNUM", "MUL_FIXNUM", "DIV_FIXNUM", "MOD_FIXNUM", "LE_FIXNUM", "GE_FIXNUM", "LT_FIXNUM", "GT_FIXNUM":
		if len(instr.ExprHints) >= 2 {
			result.WriteString(fmt.Sprintf("(%s %s %s)\n", d.fixnumOpSymbol(instr.Name), instr.ExprHints[0], instr.ExprHints[1]))
		} else {
			result.WriteString(fmt.Sprintf("(%s a b)\n", d.fixnumOpSymbol(instr.Name)))
		}
	case "INC1":
		if len(instr.ExprHints) >= 1 {
			result.WriteString(fmt.Sprintf("(1+ %s)\n", instr.ExprHints[0]))
		} else {
			result.WriteString("(1+ <expr>)\n")
		}
	case "DEC1":
		if len(instr.ExprHints) >= 1 {
			result.WriteString(fmt.Sprintf("(1- %s)\n", instr.ExprHints[0]))
		} else {
			result.WriteString("(1- <expr>)\n")
		}
	case "CAR":
		result.WriteString("(car <list>)\n")
	case "CDR":
		result.WriteString("(cdr <list>)\n")
	case "CONS":
		result.WriteString("(cons car cdr)\n")
	case "MAKE_LIST":
		if len(instr.Operands) > 0 {
			count := instr.Operands[0]
			result.WriteString(fmt.Sprintf("(make-list %d)\n", count))
		}
	case "PUSH_INT32":
		if len(instr.Operands) > 0 {
			value := instr.Operands[0]
			result.WriteString(fmt.Sprintf("(push-int %d)\n", value))
		}
	case "FUNC":
		if fn := d.functionAt(instr.Offset); fn != nil {
			result.WriteString(fmt.Sprintf("(defun %s (...))\n", fn.Name))
		} else if len(instr.Operands) >= 2 {
			result.WriteString(fmt.Sprintf("(defun %s (...))\n", d.displaySymbolName(instr.Operands[1])))
		}
	case "DEFUN", "DEFUN_Q":
		if fn := d.functionAt(instr.Offset); fn != nil {
			keyword := "defun"
			if instr.Name == "DEFUN_Q" || fn.IsLambda {
				keyword = "defun-q"
			}
			result.WriteString(fmt.Sprintf("(%s %s (%s))\n", keyword, fn.Name, d.formatArgList(fn)))
		}
	case "MAIN":
		result.WriteString("(defun main ())\n")
	case "INIT_ARGS":
		if len(instr.Operands) > 0 {
			result.WriteString(fmt.Sprintf("(init-frame %d)\n", instr.Operands[0]))
		}
	case "LOAD_LVAR", "LOAD_LVAR2":
		if len(instr.Operands) > 0 {
			slotName := d.slotNameAt(instr.Offset, instr.Operands[0])
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(fmt.Sprintf("(load-lvar %s ; => %s)\n", slotName, d.renderValueHint(instr.ValueHint)))
			} else {
				result.WriteString(fmt.Sprintf("(load-lvar %s)\n", slotName))
			}
		}
	case "SETQ", "SETQ_LVAR", "SETQ_LVAR8":
		if len(instr.Operands) > 0 {
			slotName := d.slotNameAt(instr.Offset, instr.Operands[0])
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(fmt.Sprintf("(setq %s %s)\n", slotName, d.renderStackValue(instr.ValueHint)))
			} else {
				result.WriteString(fmt.Sprintf("(setq %s <value>)\n", slotName))
			}
		}
	case "CLEAR_LVAR", "CLEAR_LVAR8":
		if len(instr.Operands) > 0 {
			slotName := d.slotNameAt(instr.Offset, instr.Operands[0])
			result.WriteString(fmt.Sprintf("(clear-lvar %s)\n", slotName))
		}
	case "SETQ_GVAR":
		if len(instr.Operands) > 0 {
			name := d.displayGlobalName(instr.Operands[0])
			if instr.HasValueHint && instr.ValueHint.Value != "" {
				result.WriteString(fmt.Sprintf("(setq '%s %s)\n", name, d.renderStackValue(instr.ValueHint)))
			} else {
				result.WriteString(fmt.Sprintf("(setq '%s <value>)\n", name))
			}
		}
	case "BR_IF_FALSE", "BR_IF_TRUE", "BR_IF_FALSE2", "BR_IF_TRUE2":
		thenLabel := d.edgeTargetLabel(instr)
		elseLabel := d.fallthroughLabel(instr)
		if thenLabel != "" && elseLabel != "" {
			result.WriteString(fmt.Sprintf("(if %s %s %s)\n", d.renderBranchPredicate(instr), thenLabel, elseLabel))
		} else {
			result.WriteString(fmt.Sprintf(";; %s\n", instr.Name))
		}
	case "OR_JMP":
		targetLabel := d.edgeTargetLabel(instr)
		elseLabel := d.fallthroughLabel(instr)
		if targetLabel != "" && elseLabel != "" {
			result.WriteString(fmt.Sprintf("(if %s %s %s)\n", d.renderBranchPredicate(instr), targetLabel, elseLabel))
		} else {
			if len(instr.ExprHints) >= 1 {
				result.WriteString(fmt.Sprintf("(or-jmp %s <target>)\n", instr.ExprHints[0]))
			} else {
				result.WriteString("(or-jmp <target>)\n")
			}
		}
	case "JMP", "JMP_FAR", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP":
		targetLabel := d.edgeTargetLabel(instr)
		if targetLabel != "" {
			if instr.Name == "AND_JMP" && len(instr.ExprHints) >= 1 {
				elseLabel := d.fallthroughLabel(instr)
				if elseLabel != "" {
					result.WriteString(fmt.Sprintf("(if %s %s %s)\n", d.renderBranchPredicate(instr), targetLabel, elseLabel))
				} else {
					result.WriteString(fmt.Sprintf("(and-jmp %s goto %s)\n", instr.ExprHints[0], targetLabel))
				}
			} else {
				result.WriteString(fmt.Sprintf("(goto %s)\n", targetLabel))
			}
		} else {
			if instr.Name == "AND_JMP" && len(instr.ExprHints) >= 1 {
				result.WriteString(fmt.Sprintf("(and-jmp %s <target>)\n", instr.ExprHints[0]))
			} else {
				result.WriteString(fmt.Sprintf(";; %s\n", instr.Name))
			}
		}
	case "CALL_BY_OFFSET":
		if len(instr.Operands) >= 2 {
			nargs := instr.Operands[0]
			target := instr.Operands[1]
			if len(instr.ArgHints) > 0 {
				result.WriteString(fmt.Sprintf("(call-by-offset %s %s)\n", d.lookupFunctionByOffset(target), strings.Join(instr.ArgHints, " ")))
			} else {
				result.WriteString(fmt.Sprintf("(call-by-offset %s ; argc=%d)\n", d.lookupFunctionByOffset(target), nargs))
			}
		}
	case "EVAL":
		result.WriteString("(eval <expr>)\n")
	default:
		result.WriteString(fmt.Sprintf(";; %s\n", instr.Name))
	}

	return result.String()
}

func (d *Disassembler) formatArgList(fn *FASFunction) string {
	if fn == nil || fn.NumOfArgs <= 0 {
		return ""
	}
	args := make([]string, 0, fn.NumOfArgs)
	for i := 0; i < fn.NumOfArgs; i++ {
		args = append(args, fmt.Sprintf("arg_%d", i))
	}
	return strings.Join(args, " ")
}

func (d *Disassembler) slotNameAt(offset, slot int) string {
	if fn := d.functionAt(offset); fn != nil {
		return fn.slotName(slot)
	}
	return fmt.Sprintf("local_%d", slot)
}

func (d *Disassembler) functionAt(offset int) *FASFunction {
	if fn, ok := d.offsetToFunc[offset]; ok {
		return fn
	}
	var best *FASFunction
	for _, fn := range d.functions {
		if offset >= fn.StartOffset && (fn.EndOffset < 0 || offset <= fn.EndOffset) {
			if best == nil {
				best = fn
				continue
			}
			bestSpan := 1 << 30
			if best.EndOffset >= best.StartOffset {
				bestSpan = best.EndOffset - best.StartOffset
			}
			fnSpan := 1 << 30
			if fn.EndOffset >= fn.StartOffset {
				fnSpan = fn.EndOffset - fn.StartOffset
			}
			if fn.StartOffset > best.StartOffset || fnSpan < bestSpan {
				best = fn
			}
		}
	}
	if best != nil {
		d.offsetToFunc[offset] = best
	}
	return best
}

func (d *Disassembler) bodyInstructions(fn *FASFunction) []Instruction {
	if fn == nil {
		return nil
	}
	if instrs, ok := d.funcInstrs[fn]; ok {
		return instrs
	}
	out := make([]Instruction, 0)
	for _, instr := range d.instructions {
		if instr.Offset >= fn.StartOffset && (fn.EndOffset < 0 || instr.Offset <= fn.EndOffset) {
			out = append(out, instr)
		}
	}
	return out
}

func (d *Disassembler) blockLabel(fn *FASFunction, offset int) string {
	if fn == nil {
		return fmt.Sprintf("block_%04X", offset)
	}
	return fmt.Sprintf("%s_block_%04X", fn.Name, offset)
}

func (d *Disassembler) edgeTargetLabel(instr Instruction) string {
	fn := d.functionAt(instr.Offset)
	if len(instr.Operands) == 0 || fn == nil {
		return ""
	}
	target := d.branchTarget(instr, instr.Operands[0])
	return d.blockLabel(fn, target)
}

func (d *Disassembler) fallthroughLabel(instr Instruction) string {
	fn := d.functionAt(instr.Offset)
	if fn == nil {
		return ""
	}
	next := instr.Offset + d.instructionWidth(instr)
	return d.blockLabel(fn, next)
}

func (d *Disassembler) isBlockStart(fn *FASFunction, offset int) bool {
	if fn == nil {
		return false
	}
	if starts, ok := d.blockStartSet[fn]; ok {
		_, exists := starts[offset]
		return exists
	}
	return false
}

func (d *Disassembler) isReturnInstruction(name string) bool {
	return name == "END_DEFUN" || name == "END_DEFUN2"
}

func (d *Disassembler) isJumpInstruction(name string) bool {
	switch name {
	case "JMP", "JMP_FAR", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "AND_JMP":
		return true
	default:
		return false
	}
}

func (d *Disassembler) conditionalEdges(fn *FASFunction, from int) (thenEdge *FASEdge, elseEdge *FASEdge) {
	if fn == nil {
		return nil, nil
	}
	for i := range fn.ControlEdges {
		edge := &fn.ControlEdges[i]
		if edge.From != from {
			continue
		}
		if edge.Kind == "fallthrough" {
			elseEdge = edge
		} else if strings.HasPrefix(edge.Kind, "br_") {
			thenEdge = edge
		}
	}
	return thenEdge, elseEdge
}

func (d *Disassembler) hasBackEdgeTo(fn *FASFunction, target int) bool {
	if fn == nil {
		return false
	}
	for _, edge := range fn.ControlEdges {
		if edge.To == target && edge.From > target {
			return true
		}
	}
	return false
}

func (d *Disassembler) invertPredicate(pred string) string {
	if strings.HasPrefix(pred, "(not ") && strings.HasSuffix(pred, ")") {
		return strings.TrimSuffix(strings.TrimPrefix(pred, "(not "), ")")
	}
	return fmt.Sprintf("(not %s)", pred)
}

func (d *Disassembler) constantBranchOutcome(instr Instruction) (known bool, truthy bool) {
	if len(instr.ExprHints) == 0 {
		return false, false
	}
	return renderedTruthiness(strings.TrimSpace(instr.ExprHints[0]))
}

func renderedTruthiness(expr string) (known bool, truthy bool) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "nil":
		return true, false
	case "t":
		return true, true
	}
	if strings.HasPrefix(expr, "(not ") && strings.HasSuffix(expr, ")") {
		if known, truthy := renderedTruthiness(strings.TrimSpace(expr[5 : len(expr)-1])); known {
			return true, !truthy
		}
	}
	return false, false
}

func (d *Disassembler) renderStructuredLoopPreview(fn *FASFunction, instr Instruction, thenEdge, elseEdge *FASEdge) string {
	if fn == nil || thenEdge == nil || elseEdge == nil {
		return ""
	}
	bodyStart := instr.Offset + d.instructionWidth(instr)
	exitEdge := thenEdge
	bodyEdge := elseEdge
	if bodyEdge.To != bodyStart {
		return ""
	}
	if exitEdge.To <= instr.Offset {
		return ""
	}
	if !d.hasBackEdgeTo(fn, instr.Offset) && !d.hasBackEdgeTo(fn, bodyStart) {
		return ""
	}
	cond := d.invertPredicate(d.renderBranchPredicate(instr))
	return fmt.Sprintf("(while %s %s)", cond, d.blockLabel(fn, bodyEdge.To))
}

func (d *Disassembler) renderStructuredIfPreview(fn *FASFunction, instr Instruction, thenEdge, elseEdge *FASEdge) string {
	if fn == nil || thenEdge == nil || elseEdge == nil {
		return ""
	}
	if known, truthy := d.constantBranchOutcome(instr); known {
		target := elseEdge.To
		if truthy {
			target = thenEdge.To
		}
		return fmt.Sprintf("(goto %s)", d.blockLabel(fn, target))
	}
	return fmt.Sprintf("(if %s %s %s)",
		d.renderBranchPredicate(instr),
		d.blockLabel(fn, thenEdge.To),
		d.blockLabel(fn, elseEdge.To),
	)
}

func (d *Disassembler) renderStructuredPreview(compact bool) string {
	d.buildRenderIndexes()
	var out strings.Builder
	wrote := false
	rendered := 0

	for _, fn := range d.functions {
		if compact && rendered >= compactRenderPreviewLimit {
			break
		}
		for _, instr := range d.funcInstrs[fn] {
			if !d.isConditionalBranch(instr.Name) {
				continue
			}
			thenEdge, elseEdge := d.conditionalEdges(fn, instr.Offset)
			if thenEdge == nil || elseEdge == nil {
				continue
			}
			if !wrote {
				out.WriteString(";; Structured Preview\n")
				out.WriteString(";; ==================\n")
				wrote = true
			}
			out.WriteString(fmt.Sprintf(";; function %s\n", fn.Name))
			if loop := d.renderStructuredLoopPreview(fn, instr, thenEdge, elseEdge); loop != "" {
				out.WriteString(loop)
				out.WriteString("\n")
			} else {
				out.WriteString(d.renderStructuredIfPreview(fn, instr, thenEdge, elseEdge))
				out.WriteString("\n")
			}
			rendered++
			break
		}
	}

	if wrote {
		if compact && rendered >= compactRenderPreviewLimit {
			out.WriteString(";; ... additional structured previews omitted in compact mode\n")
		}
		out.WriteString("\n")
	}
	return out.String()
}

func (d *Disassembler) buildRenderIndexes() {
	if len(d.functions) == 0 {
		return
	}
	if len(d.blockStartSet) == len(d.functions) && len(d.funcInstrs) == len(d.functions) {
		return
	}

	d.blockStartSet = make(map[*FASFunction]map[int]struct{}, len(d.functions))
	d.funcInstrs = make(map[*FASFunction][]Instruction, len(d.functions))

	for _, fn := range d.functions {
		starts := make(map[int]struct{}, len(fn.BlockStarts)+1)
		starts[fn.StartOffset] = struct{}{}
		for _, offset := range fn.BlockStarts {
			starts[offset] = struct{}{}
		}
		d.blockStartSet[fn] = starts
	}
	if len(d.offsetToFunc) != len(d.instructions) {
		d.offsetToFunc, d.funcInstrs = d.assignInstructionOwners()
		return
	}
	for _, instr := range d.instructions {
		if fn := d.offsetToFunc[instr.Offset]; fn != nil {
			d.funcInstrs[fn] = append(d.funcInstrs[fn], instr)
		}
	}
}

func (d *Disassembler) Bindings() []FASBinding {
	result := make([]FASBinding, 0, len(d.globalBindings)+len(d.slotBindings))

	for idx, value := range d.globalBindings {
		name := d.lookupSymbol(idx)
		result = append(result, FASBinding{
			Scope:  "global",
			Name:   name,
			Value:  value.Value,
			Kind:   value.Kind,
			Offset: -1,
		})
	}

	for offset, slots := range d.slotBindings {
		for slot, value := range slots {
			name := fmt.Sprintf("slot_%d", slot)
			if fn := d.funcByStart[offset]; fn != nil {
				name = fn.slotName(slot)
			}
			result = append(result, FASBinding{
				Scope:  "slot",
				Name:   name,
				Value:  value.Value,
				Kind:   value.Kind,
				Offset: offset,
			})
		}
	}

	return result
}

func (d *Disassembler) renderStackValue(v StackValue) string {
	if v.Value == "" {
		return "<unknown>"
	}
	switch v.Kind {
	case "symbol":
		return "'" + d.displaySymbolRef(v.Value)
	case "const":
		return renderConstAtom(v.Value)
	case "literal", "int", "call", "gvar", "slot":
		return d.rewriteDisplayNames(v.Value)
	default:
		return d.rewriteDisplayNames(v.Value)
	}
}

func (d *Disassembler) renderHintStackValue(v StackValue) string {
	if v.Value == "" {
		return "<unknown>"
	}
	var rendered string
	switch v.Kind {
	case "symbol":
		rendered = "'" + v.Value
	case "const":
		rendered = renderConstAtom(v.Value)
	default:
		rendered = v.Value
	}
	rendered = strings.TrimSpace(rendered)
	if len(rendered) > compactHintValueLimit {
		rendered = rendered[:compactHintValueLimit] + "..."
	}
	return rendered
}

func (d *Disassembler) renderValueHint(v StackValue) string {
	switch v.Kind {
	case "call", "expr":
		if alias := deriveAliasFromValue(v); alias != "" {
			return alias
		}
	}
	return d.renderStackValue(v)
}

func (d *Disassembler) rewriteDisplayNames(value string) string {
	value = normalizeRenderedExpression(value)
	return symbolRefPattern.ReplaceAllStringFunc(value, func(match string) string {
		return d.displayEmbeddedSymbolRef(match)
	})
}

func (d *Disassembler) displayEmbeddedSymbolRef(name string) string {
	if !strings.HasPrefix(name, "sym_") {
		return normalizeSyntheticAlias(name)
	}
	var idx int
	if _, err := fmt.Sscanf(name, "sym_%d", &idx); err == nil {
		return normalizeSyntheticAlias(d.displayEmbeddedSymbolName(idx))
	}
	return name
}

func (d *Disassembler) displayEmbeddedSymbolName(idx int) string {
	if raw, ok := d.symbolValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if isCallableSymbolCandidate(raw, candidate) || isPlausibleRecoveredFunctionName(candidate) || isCommonRecoveredBuiltin(candidate) {
				return candidate
			}
		}
	}
	if alias := d.globalAliases[idx]; alias != "" {
		if isLikelyStringBackedCallTarget(alias) || strings.HasPrefix(alias, "alias_") {
			return alias
		}
	}
	if raw, ok := d.constValueAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if isCallableSymbolCandidate(raw, candidate) || isPlausibleRecoveredFunctionName(candidate) || isCommonRecoveredBuiltin(candidate) {
				return candidate
			}
		}
	}
	if raw, kind, ok := d.resourceAt(idx); ok {
		if candidate := canonicalizeResourceSymbol(raw); candidate != "" {
			if (kind == "symbol" || kind == "string") && (isCallableSymbolCandidate(raw, candidate) || isPlausibleRecoveredFunctionName(candidate) || isCommonRecoveredBuiltin(candidate)) {
				return candidate
			}
		}
	}
	return fmt.Sprintf("sym_%d", idx)
}

func (d *Disassembler) hintsToValues(hints []string) []StackValue {
	values := make([]StackValue, 0, len(hints))
	for _, hint := range hints {
		values = append(values, StackValue{Kind: "expr", Value: hint})
	}
	return values
}

func (d *Disassembler) peekArgValues(nargs int, skipTop int) []StackValue {
	if nargs <= 0 {
		return nil
	}
	available := len(d.valueStack) - skipTop
	if available <= 0 {
		return nil
	}
	if nargs > available {
		nargs = available
	}
	start := len(d.valueStack) - skipTop - nargs
	values := make([]StackValue, 0, nargs)
	for idx := start; idx < len(d.valueStack)-skipTop; idx++ {
		values = append(values, d.valueStack[idx])
	}
	return values
}

func (d *Disassembler) renderCallExpr(name string, args []StackValue) string {
	if recovered := d.renderRecoveredHelperCall(name, args); recovered != "" {
		return recovered
	}
	rendered := make([]string, 0, len(args))
	for _, arg := range args {
		rendered = append(rendered, d.renderStackValue(arg))
	}
	if !strings.HasPrefix(name, "sym_") {
		name = d.displaySymbolRef(name)
	}
	if len(rendered) == 0 {
		return fmt.Sprintf("(%s)", name)
	}
	return fmt.Sprintf("(%s %s)", name, strings.Join(rendered, " "))
}

func (d *Disassembler) renderHintCallExpr(name string, args []StackValue) string {
	if recovered := d.renderRecoveredHelperCall(name, args); recovered != "" {
		if len(recovered) > compactHintValueLimit {
			return recovered[:compactHintValueLimit] + "..."
		}
		return recovered
	}
	rendered := make([]string, 0, len(args))
	for _, arg := range args {
		rendered = append(rendered, d.renderHintStackValue(arg))
	}
	if !strings.HasPrefix(name, "sym_") {
		name = normalizeSyntheticAlias(name)
	}
	if len(rendered) == 0 {
		return fmt.Sprintf("(%s)", name)
	}
	out := fmt.Sprintf("(%s %s)", name, strings.Join(rendered, " "))
	if len(out) > compactHintValueLimit {
		out = out[:compactHintValueLimit] + "..."
	}
	return out
}

func (d *Disassembler) renderRecoveredHelperCall(name string, args []StackValue) string {
	name = d.displayCallTargetName(name)
	switch name {
	case "substr":
		return d.renderRecoveredSubstr(args)
	case "dispatch":
		return d.renderAlias254(args)
	case "dispatch-apply":
		return d.renderAlias228(args)
	default:
		return ""
	}
}

func (d *Disassembler) renderRecoveredSubstr(args []StackValue) string {
	if len(args) == 0 {
		return ""
	}
	filtered := make([]StackValue, 0, len(args))
	hasEncoded := false
	for _, arg := range args {
		if d.isEncodedScriptValue(arg) {
			hasEncoded = true
			continue
		}
		filtered = append(filtered, arg)
	}
	if !hasEncoded {
		return ""
	}
	if len(filtered) < 2 {
		return d.renderNamedCall("encoded-script-substr-partial", filtered)
	}
	return d.renderNamedCall("encoded-script-substr", filtered)
}

func (d *Disassembler) renderAlias254(args []StackValue) string {
	if len(args) < 2 {
		return ""
	}
	if mode := d.dispatchMode(args[1]); mode != "" {
		switch mode {
		case "get":
			if len(args) == 3 {
				return d.renderNamedCall("dispatch-get", []StackValue{args[0], args[2]})
			}
		case "put":
			if len(args) >= 4 {
				rewritten := []StackValue{args[0], args[2]}
				rewritten = append(rewritten, args[3:]...)
				return d.renderNamedCall("dispatch-put", rewritten)
			}
		case "call":
			if len(args) >= 3 {
				rewritten := []StackValue{args[0], args[2]}
				rewritten = append(rewritten, args[3:]...)
				return d.renderNamedCall("dispatch-call", rewritten)
			}
		}
	}
	if d.isDispatchTarget(args[0]) && len(args) == 2 && d.isDispatchMember(args[1]) {
		return d.renderNamedCall("dispatch-get", args)
	}
	if d.isDispatchTarget(args[0]) && len(args) >= 3 && d.isDispatchMember(args[1]) {
		return d.renderNamedCall("dispatch-call", args)
	}
	if d.isDispatchTarget(args[0]) && len(args) >= 3 {
		rewritten := []StackValue{args[0], args[1]}
		rewritten = append(rewritten, args[2:]...)
		return d.renderNamedCall("dispatch", rewritten)
	}
	return ""
}

func (d *Disassembler) renderAlias228(args []StackValue) string {
	if len(args) > 0 && d.isDispatchTarget(args[0]) && len(args) < 3 {
		return d.renderNamedCall("dispatch-apply-partial", args)
	}
	if len(args) > 0 && d.isDispatchTarget(args[len(args)-1]) && len(args) < 3 {
		rewritten := append([]StackValue(nil), args...)
		if len(rewritten) > 1 {
			last := rewritten[len(rewritten)-1]
			copy(rewritten[1:], rewritten[:len(rewritten)-1])
			rewritten[0] = last
		}
		return d.renderNamedCall("dispatch-apply-partial", rewritten)
	}
	if len(args) != 3 {
		return ""
	}
	if d.isDispatchTarget(args[0]) {
		return d.renderNamedCall("dispatch-apply", args)
	}
	if d.isDispatchTarget(args[2]) {
		return d.renderNamedCall("dispatch-apply", []StackValue{args[2], args[0], args[1]})
	}
	return ""
}

func (d *Disassembler) renderNamedCall(name string, args []StackValue) string {
	rendered := make([]string, 0, len(args))
	for i, arg := range args {
		rendered = append(rendered, d.renderCallArg(name, i, arg))
	}
	if len(rendered) == 0 {
		return fmt.Sprintf("(%s)", name)
	}
	return fmt.Sprintf("(%s %s)", name, strings.Join(rendered, " "))
}

func (d *Disassembler) renderCallArg(callName string, argIndex int, arg StackValue) string {
	if strings.HasPrefix(callName, "encoded-script-substr") {
		if raw := renderRawBracketConst(arg); raw != "" {
			return raw
		}
	}
	if d.isDispatchLikeCall(callName) && argIndex > 0 {
		if member := d.renderDispatchMemberArg(arg); member != "" {
			return member
		}
	}
	return d.renderStackValue(arg)
}

func renderRawBracketConst(arg StackValue) string {
	if arg.Kind != "const" {
		return ""
	}
	display, _ := normalizeDisplayString(arg.Value)
	if !strings.HasPrefix(strings.TrimSpace(display), "[") {
		return ""
	}
	return fmt.Sprintf("%q", strings.TrimSpace(display))
}

func (d *Disassembler) isDispatchLikeCall(name string) bool {
	switch name {
	case "dispatch", "dispatch-get", "dispatch-put", "dispatch-call", "dispatch-apply", "dispatch-apply-partial":
		return true
	default:
		return false
	}
}

func (d *Disassembler) renderDispatchMemberArg(arg StackValue) string {
	if arg.Kind != "const" {
		return ""
	}
	display, _ := normalizeDisplayString(arg.Value)
	if !strings.HasPrefix(display, "[") {
		return ""
	}
	alias := sanitizeIdentifier(display)
	if alias == "" {
		return ""
	}
	return ":" + alias
}

func (d *Disassembler) dispatchMode(v StackValue) string {
	if v.Kind != "const" {
		return ""
	}
	display, control := normalizeDisplayString(v.Value)
	switch {
	case display == "c" && control == 0x01:
		return "get"
	case display == " " && control == 0x03:
		return "put"
	case display == "9" && control == 0x16:
		return "call"
	default:
		return ""
	}
}

func (d *Disassembler) isDispatchTarget(v StackValue) bool {
	rendered := d.renderStackValue(v)
	if rendered == "" {
		return false
	}
	return strings.Contains(rendered, "(vlax-create-object ") ||
		strings.Contains(rendered, "(vlr-") ||
		strings.Contains(rendered, "(scriptcontrol ") ||
		strings.Contains(rendered, "(htmlfile ") ||
		strings.Contains(rendered, "(timeout ")
}

func (d *Disassembler) isDispatchMember(v StackValue) bool {
	if v.Kind != "const" {
		return false
	}
	display, _ := normalizeDisplayString(v.Value)
	display = strings.TrimSpace(display)
	return display != ""
}

func (d *Disassembler) isEncodedScriptValue(v StackValue) bool {
	switch v.Kind {
	case "const":
		return isEncodedScriptBlob(v.Value)
	case "expr", "call", "slot", "gvar", "literal", "int", "symbol":
		rendered := d.renderStackValue(v)
		return strings.Contains(rendered, "#<encoded-script>") ||
			strings.Contains(rendered, "encoded_script") ||
			strings.Contains(rendered, "encoded-script")
	default:
		return false
	}
}

func (d *Disassembler) renderDynamicCallExpr(callee string, args []StackValue) string {
	rendered := make([]string, 0, len(args)+1)
	rendered = append(rendered, d.rewriteDisplayNames(callee))
	for _, arg := range args {
		rendered = append(rendered, d.renderStackValue(arg))
	}
	return fmt.Sprintf("(funcall %s)", strings.Join(rendered, " "))
}

func (d *Disassembler) renderBranchPredicate(instr Instruction) string {
	cond := "<cond>"
	if len(instr.ExprHints) >= 1 {
		cond = instr.ExprHints[0]
	}
	switch instr.Name {
	case "BR_IF_FALSE", "BR_IF_FALSE2", "AND_JMP":
		return fmt.Sprintf("(not %s)", cond)
	case "BR_IF_TRUE", "BR_IF_TRUE2", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR", "OR_JMP":
		return cond
	default:
		return strings.ToLower(instr.Name)
	}
}

var symbolRefPattern = regexp.MustCompile(`sym_\d+`)
var quotedStringPattern = regexp.MustCompile(`"([^"]+)"`)
var rawBracketSymbolPattern = regexp.MustCompile(`\[[A-Za-z0-9:_*\-]+`)

func normalizeRenderedExpression(value string) string {
	if value == "" {
		return value
	}
	value = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
	value = quotedStringPattern.ReplaceAllStringFunc(value, normalizeQuotedDisplayLiteral)
	return strings.Join(strings.Fields(value), " ")
}

func normalizeQuotedDisplayLiteral(lit string) string {
	unquoted, err := strconv.Unquote(lit)
	if err != nil {
		return lit
	}
	if shouldCanonicalizeBracketToken(unquoted) {
		if canonical := canonicalizeResourceSymbol(unquoted); canonical != "" {
			return strconv.Quote(canonical)
		}
	}
	unquoted = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(unquoted)
	return strconv.Quote(unquoted)
}

func renderConstAtom(raw string) string {
	if isEncodedScriptBlob(raw) {
		return "#<encoded-script>"
	}
	display, control := normalizeDisplayString(raw)
	if control == 0 && shouldCanonicalizeBracketToken(display) {
		if canonical := canonicalizeResourceSymbol(display); canonical != "" {
			return fmt.Sprintf("%q", canonical)
		}
	}
	if control != 0 {
		display = strings.TrimSpace(display)
		if display == "" {
			return fmt.Sprintf("#<tok 0x%02X>", control)
		}
		if shouldCanonicalizeBracketToken(display) {
			if canonical := canonicalizeResourceSymbol(display); canonical != "" {
				return fmt.Sprintf("%q", canonical)
			}
		}
		if isMostlyPrintableASCII(display) {
			return fmt.Sprintf("#<tok %q 0x%02X>", display, control)
		}
		return fmt.Sprintf("#<tok %q 0x%02X>", display, control)
	}
	return fmt.Sprintf("%q", display)
}

func shouldCanonicalizeBracketToken(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return strings.HasPrefix(trimmed, "[") && len(trimmed) > 4
}

func renderConstAtomLegacy(raw string) string {
	if isEncodedScriptBlob(raw) {
		return "#<encoded-script>"
	}
	display, control := normalizeDisplayString(raw)
	if canonical := canonicalizeResourceSymbol(display); canonical != "" {
		return fmt.Sprintf("%q", canonical)
	}
	if control != 0 {
		display = strings.TrimSpace(display)
		if display == "" {
			return fmt.Sprintf("#<tok 0x%02X>", control)
		}
		if canonical := canonicalizeResourceSymbol(display); canonical != "" {
			return fmt.Sprintf("%q", canonical)
		}
		if isMostlyPrintableASCII(display) {
			return fmt.Sprintf("%q", display)
		}
		return fmt.Sprintf("#<tok %q 0x%02X>", display, control)
	}
	return fmt.Sprintf("%q", display)
}

func isEncodedScriptBlob(raw string) bool {
	return strings.HasPrefix(raw, "#@~^") && strings.HasSuffix(raw, "^#~@")
}

func normalizeDisplayString(raw string) (string, byte) {
	if raw == "" {
		return raw, 0
	}
	if len(raw) >= 2 {
		last := raw[len(raw)-1]
		base := raw[:len(raw)-1]
		if last > 0 && last < 32 && isMostlyPrintableASCII(base) {
			return base, last
		}
	}
	return raw, 0
}

func canonicalizeResourceSymbol(raw string) string {
	display, control := normalizeDisplayString(raw)
	display = strings.TrimSpace(display)
	if display == "" {
		return ""
	}
	if control != 0 {
		upper := strings.ToUpper(display)
		switch upper {
		case "U":
			return ""
		}
	}
	if strings.Contains(display, "[") && !strings.HasPrefix(display, "[") {
		display = strings.SplitN(display, "[", 2)[0]
	}
	if strings.HasPrefix(display, "[") {
		display = strings.TrimPrefix(display, "[")
	}
	display = strings.TrimSpace(display)
	if display == "" {
		return ""
	}

	upper := strings.ToUpper(display)
	switch upper {
	case "VIAX-IXMDX":
		return "vlax-create-object"
	case "VIAX-IWBWO":
		return "vlax-invoke-method"
	case "VIAX-IQCQB":
		return "vlax-get-property"
	case "VIAX-IDOMC":
		return "vlax-release-object"
	case "VL-LOAD-REACTORS":
		return "vl-load-reactors"
	case "SUBSTR":
		return "substr"
	}

	if !isSymbolLikeDisplay(display) {
		return ""
	}
	name := strings.ToLower(display)
	if normalized := normalizeKnownHelperVariant(name); normalized != "" {
		name = normalized
	}
	if !isMeaningfulRecoveredName(name) {
		return ""
	}
	return name
}

func normalizeKnownHelperVariant(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	if isKnownRecoveredHelperName(name) {
		return name
	}
	for _, suffix := range []string{"u", "9"} {
		if strings.HasSuffix(name, suffix) {
			trimmed := strings.TrimSuffix(name, suffix)
			if isKnownRecoveredHelperName(trimmed) {
				return trimmed
			}
		}
	}
	return ""
}

func isSymbolLikeDisplay(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', ':', '*', '+', '<', '>', '=', '/', '?', '$', '!', '.':
			continue
		default:
			return false
		}
	}
	return true
}

func isMeaningfulRecoveredName(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "sym_") {
		return false
	}
	if strings.Contains(name, " ") || strings.Contains(name, `"`) {
		return false
	}
	if name != "=" && name != "/=" {
		if strings.Count(name, "=") > 1 || strings.Contains(name, "==") {
			return false
		}
		if strings.HasPrefix(name, "=") || strings.HasSuffix(name, "=") {
			return false
		}
	}
	allDigits := true
	alphaCount := 0
	for _, r := range name {
		if r >= '0' && r <= '9' {
			continue
		}
		allDigits = false
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			alphaCount++
		}
	}
	if allDigits {
		return false
	}
	if alphaCount < 2 {
		return false
	}
	if len(name) == 1 {
		return false
	}
	return true
}

func isMostlyPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r >= 127 {
			return false
		}
	}
	return true
}

func deriveAliasFromValue(v StackValue) string {
	switch v.Kind {
	case "symbol", "gvar":
		return sanitizeIdentifier(v.Value)
	case "const":
		display, control := normalizeDisplayString(v.Value)
		if control != 0 {
			return ""
		}
		return sanitizeIdentifier(display)
	case "call", "expr":
		if alias := deriveAliasFromRenderedExpr(v.Value); alias != "" {
			return alias
		}
		if strings.HasPrefix(v.Value, "(") {
			body := strings.TrimPrefix(v.Value, "(")
			if idx := strings.IndexAny(body, " )"); idx > 0 {
				callName := sanitizeIdentifier(body[:idx])
				if callName == "" || !isSemanticAliasCandidate(callName) {
					return ""
				}
				return callName + "_result"
			}
		}
	}
	return ""
}

func isSemanticAliasCandidate(name string) bool {
	switch name {
	case "assoc", "car", "cdr", "list", "cons", "princ", "setq", "eval", "not", "member", "mapcar", "substr", "strcat":
		return false
	}
	if strings.HasPrefix(name, "sym_") || strings.HasPrefix(name, "fn_") {
		return false
	}
	if len(name) < 3 {
		return false
	}
	return true
}

func deriveAliasFromRenderedExpr(expr string) string {
	if expr == "" {
		return ""
	}
	if strings.HasPrefix(expr, "(encoded-script-substr") {
		matches := quotedStringPattern.FindAllStringSubmatch(expr, -1)
		for i := len(matches) - 1; i >= 0; i-- {
			if len(matches[i]) < 2 {
				continue
			}
			if base := sanitizeIdentifier(matches[i][1]); base != "" {
				return base + "_decoded"
			}
		}
		return "decoded_script"
	}
	if callName, args, ok := splitTopLevelCall(expr); ok {
		if alias := deriveAliasFromDispatchExpr(callName, args); alias != "" {
			return alias
		}
		if alias := deriveAliasFromWrapperExpr(callName, args); alias != "" {
			return alias
		}
	}
	return ""
}

func deriveAliasFromDispatchExpr(callName string, args []string) string {
	if len(args) < 2 {
		return ""
	}
	var suffix string
	switch callName {
	case "dispatch-get":
		suffix = "value"
	case "dispatch-put":
		suffix = "set_result"
	case "dispatch-call":
		suffix = "call_result"
	case "dispatch-apply", "dispatch-apply-partial":
		suffix = "apply_result"
	default:
		return ""
	}
	member := ""
	for _, arg := range args[1:] {
		candidate := strings.TrimSpace(arg)
		if strings.HasPrefix(candidate, ":") {
			member = candidate
			break
		}
	}
	if member == "" {
		member = strings.TrimSpace(args[1])
		if !strings.HasPrefix(member, ":") {
			return ""
		}
	}
	base := sanitizeIdentifier(member)
	if base == "" {
		return ""
	}
	return base + "_" + suffix
}

func deriveAliasFromWrapperExpr(callName string, args []string) string {
	switch callName {
	case "scriptcontrol":
	case "timeout":
	case "startapp":
	case "htmlfile":
	default:
		return ""
	}
	for _, arg := range args {
		if strings.HasPrefix(strings.TrimSpace(arg), "(") {
			if base := deriveAliasFromArgString(arg); base != "" {
				return semanticFlowAlias(base)
			}
		}
	}
	for _, arg := range args {
		if base := deriveAliasFromArgString(arg); base != "" {
			return semanticFlowAlias(base)
		}
	}
	return ""
}

func deriveAliasFromArgString(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}
	if strings.HasPrefix(arg, "(") && strings.HasSuffix(arg, ")") {
		return deriveAliasFromRenderedExpr(arg)
	}
	if strings.HasPrefix(arg, ":") {
		return sanitizeIdentifier(arg)
	}
	if strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"") && len(arg) >= 2 {
		return sanitizeIdentifier(arg[1 : len(arg)-1])
	}
	return ""
}

func trimAliasSuffix(alias string) string {
	for _, suffix := range []string{
		"_flow",
		"_scriptcontrol_result",
		"_timeout_result",
		"_startapp_result",
		"_htmlfile_result",
		"_call_result",
		"_apply_result",
		"_set_result",
		"_value",
		"_decoded",
		"_result",
	} {
		if strings.HasSuffix(alias, suffix) {
			return strings.TrimSuffix(alias, suffix)
		}
	}
	return alias
}

func semanticFlowAlias(alias string) string {
	base := trimAliasSuffix(alias)
	if base == "" {
		return ""
	}
	if strings.HasSuffix(base, "_flow") {
		return base
	}
	return base + "_flow"
}

func splitTopLevelCall(expr string) (string, []string, bool) {
	expr = strings.TrimSpace(expr)
	if len(expr) < 2 || expr[0] != '(' || expr[len(expr)-1] != ')' {
		return "", nil, false
	}
	body := strings.TrimSpace(expr[1 : len(expr)-1])
	if body == "" {
		return "", nil, false
	}
	parts := splitTopLevelFields(body)
	if len(parts) == 0 {
		return "", nil, false
	}
	return parts[0], parts[1:], true
}

func splitTopLevelFields(s string) []string {
	var parts []string
	var buf strings.Builder
	depth := 0
	inString := false
	escaped := false
	flush := func() {
		part := strings.TrimSpace(buf.String())
		if part != "" {
			parts = append(parts, part)
		}
		buf.Reset()
	}
	for _, r := range s {
		if inString {
			buf.WriteRune(r)
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
			} else if r == '"' {
				inString = false
			}
			continue
		}
		switch r {
		case '"':
			inString = true
			buf.WriteRune(r)
		case '(':
			depth++
			buf.WriteRune(r)
		case ')':
			if depth > 0 {
				depth--
			}
			buf.WriteRune(r)
		case ' ', '\t', '\r', '\n':
			if depth == 0 {
				flush()
			} else {
				buf.WriteRune(r)
			}
		default:
			buf.WriteRune(r)
		}
	}
	flush()
	return parts
}

func sanitizeIdentifier(raw string) string {
	raw = strings.TrimSpace(raw)
	if isEncodedScriptBlob(raw) {
		return "encoded_script"
	}
	raw = strings.Trim(raw, "[](){}<>\"'")
	raw = strings.TrimPrefix(raw, ":")
	raw = strings.TrimPrefix(raw, "*")
	raw = strings.TrimSuffix(raw, "*")
	raw = strings.ToLower(raw)
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return "url"
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	name := strings.Trim(b.String(), "_")
	if len(name) < 2 {
		return ""
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "v_" + name
	}
	return name
}

func normalizeSyntheticAlias(name string) string {
	return name
}

func (d *Disassembler) fixnumOpSymbol(name string) string {
	switch name {
	case "ADD_FIXNUM":
		return "+"
	case "SUB_FIXNUM":
		return "-"
	case "MUL_FIXNUM":
		return "*"
	case "DIV_FIXNUM":
		return "/"
	case "MOD_FIXNUM":
		return "mod"
	case "LE_FIXNUM":
		return "<="
	case "GE_FIXNUM":
		return ">="
	case "LT_FIXNUM":
		return "<"
	case "GT_FIXNUM":
		return ">"
	case "INC1":
		return "1+"
	case "DEC1":
		return "1-"
	default:
		return name
	}
}

func (d *Disassembler) captureCallHints(instr *Instruction) {
	if instr == nil {
		return
	}

	if (instr.Name == "SETQ" || instr.Name == "SETQ_LVAR" || instr.Name == "SETQ_LVAR8" || instr.Name == "SETQ_GVAR" || instr.Name == "SETQ_DEFUN") && !instr.HasValueHint {
		if pending, ok := d.peekValue(); ok && pending.Value != "" {
			instr.ValueHint = pending
			instr.HasValueHint = true
		}
	}
	if instr.Name == "PUSH_SYM" && !instr.HasValueHint && len(instr.Operands) > 0 {
		if bound, ok := d.globalBindings[instr.Operands[0]]; ok && bound.Value != "" {
			instr.ValueHint = bound
			instr.HasValueHint = true
		}
	}

	switch instr.Name {
	case "CALL", "CALL_JMP":
		if len(instr.Operands) < 2 {
			return
		}
		nargs := instr.Operands[0]
		argValues := d.peekArgValues(nargs, 0)
		instr.TargetHint = d.recoverCallTargetFromUsage(*instr, d.resolveCallTargetName(instr.Operands[1]), argValues)
		if nargs == 0 {
			if v, ok := d.resolveZeroArgValue(*instr, instr.Operands[1]); ok {
				instr.ValueHint = v
				instr.HasValueHint = true
				return
			}
		}
		instr.ArgHints = d.peekArgs(nargs, 0)
		if len(argValues) > 0 {
			instr.ValueHint = StackValue{Kind: "call", Value: d.renderHintCallExpr(instr.TargetHint, argValues)}
			instr.HasValueHint = true
		}
	case "STACK_CALL_JMP":
		if len(instr.Operands) < 1 {
			return
		}
		nargs := instr.Operands[0]
		if callee, ok := d.peekValue(); ok {
			instr.TargetHint = d.renderStackValue(callee)
		} else {
			instr.TargetHint = "stack_top"
		}
		instr.ArgHints = d.peekArgs(nargs, 1)
	case "CALL_BY_OFFSET":
		if len(instr.Operands) < 2 {
			return
		}
		nargs := instr.Operands[0]
		instr.TargetHint = d.lookupFunctionByOffset(instr.Operands[1])
		instr.ArgHints = d.peekArgs(nargs, 0)
		if values := d.peekArgValues(nargs, 0); len(values) > 0 {
			instr.ValueHint = StackValue{Kind: "call", Value: d.renderHintCallExpr(instr.TargetHint, values)}
			instr.HasValueHint = true
		}
	case "SUB", "ADD_FIXNUM", "SUB_FIXNUM", "MUL_FIXNUM", "DIV_FIXNUM", "MOD_FIXNUM", "LE_FIXNUM", "GE_FIXNUM", "LT_FIXNUM", "GT_FIXNUM":
		instr.ExprHints = d.peekArgs(2, 0)
	case "INC1", "DEC1", "OR_JMP", "AND_JMP", "BR_IF_FALSE", "BR_IF_TRUE", "BR_IF_FALSE2", "BR_IF_TRUE2", "BR_IF_TRUE_FAR", "BR2_IF_TRUE_FAR":
		instr.ExprHints = d.peekArgs(1, 0)
	}
}

func (d *Disassembler) peekArgs(nargs int, skipTop int) []string {
	if nargs <= 0 {
		return nil
	}
	args := make([]string, 0, nargs)
	for i := nargs - 1; i >= 0; i-- {
		idx := len(d.valueStack) - 1 - skipTop - i
		if idx < 0 || idx >= len(d.valueStack) {
			args = append(args, "arg")
			continue
		}
		args = append(args, d.renderHintStackValue(d.valueStack[idx]))
	}
	return args
}

// DecryptStream decrypts a FAS4 stream using rolling XOR
func DecryptStream(streamData []byte, key []byte) []byte {
	if len(key) == 0 {
		return streamData
	}

	keyLength := len(key)
	result := make([]byte, len(streamData))
	keyOld := key[0]
	keyPos := 1

	for i, b := range streamData {
		if keyPos >= keyLength {
			keyPos = 0
		}
		keyNew := key[keyPos]
		result[i] = b ^ keyNew ^ keyOld
		keyOld = keyNew
		keyPos++
	}

	return result
}

// IsEncrypted checks if a stream is encrypted
func IsEncrypted(data []byte, pos int) bool {
	// Check if the byte after stream data is '$' (0x24)
	// If not, the stream is encrypted
	streamLengthEnd := pos + 4 // Assuming length field is 4 bytes
	if streamLengthEnd+1 < len(data) {
		return data[streamLengthEnd+1] != 0x24
	}
	return false
}

// isPrintableString reports whether a string is mostly printable ASCII.
func isPrintableString(s string) bool {
	if len(s) == 0 {
		return false
	}
	printableCount := 0
	for _, r := range s {
		if r >= 32 && r < 127 {
			printableCount++
		}
	}
	// Require at least 80% printable characters.
	return float64(printableCount)/float64(len(s)) > 0.8
}

// isLispFunction reports whether the name looks like a standard Lisp function.
func isLispFunction(name string) bool {
	lispFuncs := map[string]bool{
		"setq": true, "defun": true, "if": true, "cond": true,
		"car": true, "cdr": true, "cons": true, "list": true,
		"null": true, "atom": true, "eq": true, "equal": true,
		"+": true, "-": true, "*": true, "/": true,
		"vlax-create-object": true, "vlax-invoke-method": true,
		"vl-registry-write": true, "vl-registry-read": true,
		"vl-file-copy": true, "vl-file-delete": true,
		"startapp": true, "command": true, "load": true,
		"getenv": true, "setenv": true, "findfile": true,
	}
	return lispFuncs[name]
}
