package ir

// EffectType represents side effect types - security-focused
type EffectType string

const (
	FILE_READ   EffectType = "file_read"
	FILE_WRITE  EffectType = "file_write"
	FILE_DELETE EffectType = "file_delete"
	FILE_HIDDEN EffectType = "file_hidden"

	REGISTRY_READ   EffectType = "registry_read"
	REGISTRY_MODIFY EffectType = "registry_modify"
	REGISTRY_DELETE EffectType = "registry_delete"

	COM_CREATE EffectType = "com_create"
	COM_INVOKE EffectType = "com_invoke"

	COMMAND_HIJACK   EffectType = "command_hijack"
	COMMAND_UNDEFINE EffectType = "command_undefine"

	NETWORK_CONNECT EffectType = "network_connect"
	PROCESS_CREATE  EffectType = "process_create"

	ENV_CHECK       EffectType = "env_check"
	DATA_EXFILTRATE EffectType = "data_exfiltrate"
	DATA_DESTROY    EffectType = "data_destroy"
)

// IROpcode represents IR instruction opcodes
type IROpcode string

const (
	ASSIGN IROpcode = "ASSIGN" // Variable assignment
	CALL   IROpcode = "CALL"   // Function call
	BRANCH IROpcode = "BRANCH" // Conditional branch
	LOOP   IROpcode = "LOOP"   // Loop construct
	EFFECT IROpcode = "EFFECT" // Side effect
	RETURN IROpcode = "RETURN" // Return value
	PHI    IROpcode = "PHI"    // SSA phi node
)

// IRInstruction represents an IR instruction
type IRInstruction struct {
	Opcode   IROpcode
	Result   string        // Result variable (SSA)
	Operands []interface{} // Operands
	Metadata map[string]interface{}
	Line     int
}

// String returns string representation of the instruction
func (i *IRInstruction) String() string {
	if i.Result != "" {
		return i.Result + " = " + string(i.Opcode) + " " + toString(i.Operands)
	}
	return string(i.Opcode) + " " + toString(i.Operands)
}

// IREffect represents a side effect instruction
type IREffect struct {
	EffectType EffectType
	Target     string
	Source     string
	Metadata   map[string]interface{}
	Line       int
}

// String returns string representation of the effect
func (e *IREffect) String() string {
	if e.Source != "" {
		return "EFFECT " + string(e.EffectType) + "(" + e.Target + ") from " + e.Source
	}
	return "EFFECT " + string(e.EffectType) + "(" + e.Target + ")"
}

// IRBasicBlock represents a basic block in IR
type IRBasicBlock struct {
	ID           string
	Instructions []IRInstruction
	Effects      []IREffect
	Successors   []string
	Predecessors []string
}

// AddInstruction adds an instruction to the block
func (b *IRBasicBlock) AddInstruction(instr IRInstruction) {
	b.Instructions = append(b.Instructions, instr)
}

// AddEffect adds an effect to the block
func (b *IRBasicBlock) AddEffect(effect IREffect) {
	b.Effects = append(b.Effects, effect)
}

// IRFunction represents a function in IR
type IRFunction struct {
	Name       string
	Params     []string
	Blocks     map[string]*IRBasicBlock
	EntryBlock string
	LocalVars  map[string]bool
	Metadata   map[string]interface{}
}

// AddBlock adds a block to the function
func (f *IRFunction) AddBlock(block *IRBasicBlock) {
	if f.Blocks == nil {
		f.Blocks = make(map[string]*IRBasicBlock)
	}
	f.Blocks[block.ID] = block
	if f.EntryBlock == "" {
		f.EntryBlock = block.ID
	}
}

// toString converts operands to string representation
func toString(operands []interface{}) string {
	result := "["
	for i, op := range operands {
		if i > 0 {
			result += ", "
		}
		result += formatOperand(op)
	}
	result += "]"
	return result
}

// formatOperand formats a single operand
func formatOperand(op interface{}) string {
	switch v := op.(type) {
	case string:
		return v
	case int:
		return string(rune(v))
	case float64:
		return string(rune(v))
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return "?"
	}
}
