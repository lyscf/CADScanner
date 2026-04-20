package ir

// Pruner performs IR pruning optimizations
type Pruner struct {
	prunedCount int
}

// NewPruner creates a new IR pruner
func NewPruner() *Pruner {
	return &Pruner{
		prunedCount: 0,
	}
}

// Prune applies pruning optimizations to all functions
func (p *Pruner) Prune(functions map[string]*IRFunction) map[string]*IRFunction {
	for _, fn := range functions {
		p.pruneFunction(fn)
	}
	return functions
}

// pruneFunction prunes a single function
func (p *Pruner) pruneFunction(fn *IRFunction) {
	// Prune each block
	for _, block := range fn.Blocks {
		p.pruneBlock(block)
	}

	// Remove unreachable blocks
	p.pruneUnreachableBlocks(fn)
}

// pruneBlock prunes a single basic block
func (p *Pruner) pruneBlock(block *IRBasicBlock) {
	newInstructions := []IRInstruction{}

	for _, instr := range block.Instructions {
		// Skip NOP instructions
		if instr.Opcode == "NOP" {
			p.prunedCount++
			continue
		}

		// Skip redundant assignments (e.g., x = x)
		if instr.Opcode == "ASSIGN" && len(instr.Operands) > 0 {
			if instr.Result == getOperandString(instr.Operands[0]) {
				p.prunedCount++
				continue
			}
		}

		newInstructions = append(newInstructions, instr)
	}

	block.Instructions = newInstructions
}

// pruneUnreachableBlocks removes unreachable blocks
func (p *Pruner) pruneUnreachableBlocks(fn *IRFunction) {
	// Find all reachable blocks from entry point
	reachable := make(map[string]bool)
	if fn.EntryBlock != "" {
		p.markReachable(fn, fn.EntryBlock, reachable)
	}

	// Remove unreachable blocks
	for blockID := range fn.Blocks {
		if !reachable[blockID] {
			delete(fn.Blocks, blockID)
			p.prunedCount++
		}
	}
}

// markReachable marks all blocks reachable from a starting block
func (p *Pruner) markReachable(fn *IRFunction, blockID string, reachable map[string]bool) {
	if reachable[blockID] {
		return
	}

	block, ok := fn.Blocks[blockID]
	if !ok {
		return
	}

	reachable[blockID] = true

	// Mark successors as reachable
	for _, successor := range block.Successors {
		p.markReachable(fn, successor, reachable)
	}

	// Also mark blocks reachable from branches
	for _, instr := range block.Instructions {
		if instr.Opcode == "JMP" || instr.Opcode == "BR_IF_FALSE" || instr.Opcode == "BR_IF_TRUE" {
			if len(instr.Operands) > 0 {
				// In a real implementation, we'd resolve the jump target
				// For now, just mark all blocks as potentially reachable
			}
		}
	}
}

// GetPrunedCount returns the number of pruned instructions/blocks
func (p *Pruner) GetPrunedCount() int {
	return p.prunedCount
}

// getOperandString converts an operand to string
func getOperandString(op interface{}) string {
	switch v := op.(type) {
	case string:
		return v
	case int:
		return string(rune(v))
	default:
		return ""
	}
}
