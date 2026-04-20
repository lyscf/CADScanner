package ir

import (
	"fmt"
)

// ConstantFolder performs constant folding and string reconstruction
type ConstantFolder struct {
	constants   map[string]interface{} // var -> constant value
	foldedCount int
}

// NewConstantFolder creates a new constant folder
func NewConstantFolder() *ConstantFolder {
	return &ConstantFolder{
		constants: make(map[string]interface{}),
	}
}

// Fold applies constant folding to all functions
func (cf *ConstantFolder) Fold(functions map[string]*IRFunction) map[string]*IRFunction {
	for _, fn := range functions {
		for _, block := range fn.Blocks {
			cf.foldBlock(block)
		}
	}
	return functions
}

// foldBlock folds constants in a basic block
func (cf *ConstantFolder) foldBlock(block *IRBasicBlock) {
	newInstructions := []IRInstruction{}

	for _, instr := range block.Instructions {
		folded := cf.tryFoldInstruction(instr)
		if folded != nil {
			newInstructions = append(newInstructions, *folded)
			cf.foldedCount++
		} else {
			newInstructions = append(newInstructions, instr)
		}
	}

	block.Instructions = newInstructions
}

// tryFoldInstruction tries to fold an instruction
func (cf *ConstantFolder) tryFoldInstruction(instr IRInstruction) *IRInstruction {
	if instr.Opcode != CALL {
		return nil
	}

	if len(instr.Operands) == 0 {
		return nil
	}

	// Get function name from first operand
	funcName, ok := instr.Operands[0].(string)
	if !ok {
		return nil
	}

	args := instr.Operands[1:]

	// chr(N) → character
	if funcName == "chr" && len(args) == 1 {
		var charCode int
		var ok bool

		// Try to resolve through constants table first
		if arg, ok := args[0].(string); ok {
			if val, exists := cf.constants[arg]; exists {
				if intVal, ok := val.(int); ok {
					charCode = intVal
					ok = true
				}
			}
		}

		if !ok {
			if intVal, ok := args[0].(int); ok {
				charCode = intVal
				ok = true
			} else if floatVal, ok := args[0].(float64); ok {
				charCode = int(floatVal)
				ok = true
			}
		}

		if !ok {
			return nil
		}

		if charCode < 0 || charCode > 0x10FFFF {
			return nil
		}

		charValue := string(rune(charCode))
		if instr.Result != "" {
			cf.constants[instr.Result] = charValue
		}

		return &IRInstruction{
			Opcode:   ASSIGN,
			Result:   instr.Result,
			Operands: []interface{}{charValue},
			Metadata: map[string]interface{}{
				"folded":   true,
				"original": fmt.Sprintf("chr(%d)", charCode),
			},
			Line: instr.Line,
		}
	}

	// strcat(...) → concatenated string
	if funcName == "strcat" && len(args) > 0 {
		resolvedArgs := []string{}
		allResolved := true

		for _, arg := range args {
			if strArg, ok := arg.(string); ok {
				if val, exists := cf.constants[strArg]; exists {
					resolvedArgs = append(resolvedArgs, fmt.Sprintf("%v", val))
				} else {
					resolvedArgs = append(resolvedArgs, strArg)
				}
			} else if intArg, ok := arg.(int); ok {
				resolvedArgs = append(resolvedArgs, fmt.Sprintf("%d", intArg))
			} else {
				allResolved = false
				break
			}
		}

		if allResolved && len(resolvedArgs) > 0 {
			concatenated := ""
			for _, arg := range resolvedArgs {
				concatenated += arg
			}

			if instr.Result != "" {
				cf.constants[instr.Result] = concatenated
			}

			return &IRInstruction{
				Opcode:   ASSIGN,
				Result:   instr.Result,
				Operands: []interface{}{concatenated},
				Metadata: map[string]interface{}{
					"folded":   true,
					"original": fmt.Sprintf("strcat(%d args)", len(args)),
				},
				Line: instr.Line,
			}
		}
	}

	// atoi(s) → integer
	if funcName == "atoi" && len(args) == 1 {
		var strVal string
		ok := false

		if arg, isString := args[0].(string); isString {
			if val, exists := cf.constants[arg]; exists {
				if str, isString := val.(string); isString {
					strVal = str
					ok = true
				}
			} else {
				strVal = arg
				ok = true
			}
		}

		if ok {
			var intVal int
			_, err := fmt.Sscanf(strVal, "%d", &intVal)
			if err == nil && instr.Result != "" {
				cf.constants[instr.Result] = intVal
				return &IRInstruction{
					Opcode:   ASSIGN,
					Result:   instr.Result,
					Operands: []interface{}{intVal},
					Metadata: map[string]interface{}{
						"folded":   true,
						"original": fmt.Sprintf("atoi(%s)", strVal),
					},
					Line: instr.Line,
				}
			}
		}
	}

	// itoa(i) → string
	if funcName == "itoa" && len(args) == 1 {
		var intVal int
		ok := false

		if arg, isInt := args[0].(int); isInt {
			intVal = arg
			ok = true
		} else if arg, isFloat := args[0].(float64); isFloat {
			intVal = int(arg)
			ok = true
		}

		if ok && instr.Result != "" {
			strVal := fmt.Sprintf("%d", intVal)
			cf.constants[instr.Result] = strVal
			return &IRInstruction{
				Opcode:   ASSIGN,
				Result:   instr.Result,
				Operands: []interface{}{strVal},
				Metadata: map[string]interface{}{
					"folded":   true,
					"original": fmt.Sprintf("itoa(%d)", intVal),
				},
				Line: instr.Line,
			}
		}
	}

	return nil
}

// GetFoldedCount returns the number of folded instructions
func (cf *ConstantFolder) GetFoldedCount() int {
	return cf.foldedCount
}
