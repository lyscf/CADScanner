package ir

// resolveCallTargets resolves a call target through conservative assignment-based
// aliases. It only returns names that are known functions in the IR.
func resolveCallTargets(functions map[string]*IRFunction, callerName, callee string) []string {
	return resolveCallTargetsWithAliasMap(functions, callee, buildAliasMapForCaller(functions, callerName))
}

func resolveCallTargetsWithAliasMap(functions map[string]*IRFunction, callee string, aliasMap map[string][]string) []string {
	if callee == "" {
		return nil
	}
	if _, ok := functions[callee]; ok {
		return []string{callee}
	}
	visited := map[string]bool{callee: true}
	queue := []string{callee}
	resolved := make([]string, 0)
	seenResolved := make(map[string]bool)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if _, ok := functions[current]; ok {
			if !seenResolved[current] {
				resolved = append(resolved, current)
				seenResolved[current] = true
			}
			continue
		}

		for _, next := range aliasMap[current] {
			if next == "" || visited[next] {
				continue
			}
			visited[next] = true
			queue = append(queue, next)
		}
	}

	return resolved
}

func buildAliasMapForCaller(functions map[string]*IRFunction, callerName string) map[string][]string {
	aliasMap := make(map[string][]string)
	if callerName != "" {
		if fn, ok := functions[callerName]; ok {
			collectAliasesFromFunction(aliasMap, fn)
		}
	}
	if top, ok := functions["__toplevel__"]; ok && callerName != "__toplevel__" {
		collectAliasesFromFunction(aliasMap, top)
	}
	return aliasMap
}

func buildAliasMaps(functions map[string]*IRFunction) map[string]map[string][]string {
	aliasMaps := make(map[string]map[string][]string, len(functions))

	var topLevelAliasMap map[string][]string
	if top, ok := functions["__toplevel__"]; ok {
		topLevelAliasMap = make(map[string][]string)
		collectAliasesFromFunction(topLevelAliasMap, top)
	}

	for callerName, fn := range functions {
		aliasMap := make(map[string][]string)
		if fn != nil {
			collectAliasesFromFunction(aliasMap, fn)
		}
		if callerName != "__toplevel__" && topLevelAliasMap != nil {
			mergeAliasMaps(aliasMap, topLevelAliasMap)
		}
		aliasMaps[callerName] = aliasMap
	}

	return aliasMaps
}

func mergeAliasMaps(dst, src map[string][]string) {
	for name, values := range src {
		for _, value := range values {
			dst[name] = appendUniqueString(dst[name], value)
		}
	}
}

func collectAliasesFromFunction(aliasMap map[string][]string, fn *IRFunction) {
	if fn == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instructions {
			if instr.Opcode != ASSIGN {
				continue
			}
			name := aliasAssignedName(instr)
			value := aliasAssignedValue(instr)
			if name == "" || value == "" || name == value {
				continue
			}
			aliasMap[name] = appendUniqueString(aliasMap[name], value)
		}
	}
}

func aliasAssignedName(instr IRInstruction) string {
	if instr.Result != "" {
		return instr.Result
	}
	if instr.Metadata != nil {
		if original, ok := instr.Metadata["original_var"].(string); ok && original != "" {
			return original
		}
	}
	return ""
}

func aliasAssignedValue(instr IRInstruction) string {
	for i := len(instr.Operands) - 1; i >= 0; i-- {
		if s, ok := instr.Operands[i].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func appendUniqueString(dst []string, value string) []string {
	for _, existing := range dst {
		if existing == value {
			return dst
		}
	}
	return append(dst, value)
}
