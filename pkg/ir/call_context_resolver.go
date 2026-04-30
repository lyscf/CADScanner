package ir

import (
	"strings"
)

// CallContextResolver resolves paths using call context
// Resolves paths by analyzing function call chains and parameter bindings
type CallContextResolver struct {
	functions      map[string]*IRFunction
	constantFolder *ConstantFolder
	callSites      []CallSite
	paramBindings  map[string][]string // (func,param) -> [values]
	aliasMaps      map[string]map[string][]string
}

// CallSite represents function call site information
type CallSite struct {
	Caller string
	Callee string
	Args   []string
	Line   int
}

// NewCallContextResolver creates a new call context resolver
func NewCallContextResolver(functions map[string]*IRFunction, constantFolder *ConstantFolder) *CallContextResolver {
	resolver := &CallContextResolver{
		functions:      functions,
		constantFolder: constantFolder,
		callSites:      []CallSite{},
		paramBindings:  make(map[string][]string),
		aliasMaps:      buildAliasMaps(functions),
	}

	resolver.buildCallSites()
	resolver.buildParamBindings()

	return resolver
}

// cleanValue cleans a value by stripping quotes and handling list literals
func (r *CallContextResolver) cleanValue(value string) string {
	s := value
	// Strip quotes
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		s = s[1:]
	}
	if len(s) > 0 && (s[len(s)-1] == '"' || s[len(s)-1] == '\'') {
		s = s[:len(s)-1]
	}
	s = strings.TrimSpace(s)
	return s
}

// buildCallSites extracts all function call sites
func (r *CallContextResolver) buildCallSites() {
	for funcName, fn := range r.functions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Opcode == CALL && len(instr.Operands) > 0 {
					// Get callee function name
					var callee string
					if calleeStr, ok := instr.Operands[0].(string); ok {
						callee = r.cleanValue(calleeStr)
					} else {
						callee = "unknown"
					}

					for _, resolvedCallee := range resolveCallTargetsWithAliasMap(r.functions, callee, r.aliasMaps[funcName]) {
						callSite := CallSite{
							Caller: funcName,
							Callee: resolvedCallee,
							Args:   r.extractArgs(instr.Operands[1:]),
							Line:   instr.Line,
						}
						r.callSites = append(r.callSites, callSite)
					}
				}
			}
		}
	}
}

// extractArgs extracts arguments from operands
func (r *CallContextResolver) extractArgs(operands []interface{}) []string {
	args := []string{}
	for _, op := range operands {
		if s, ok := op.(string); ok {
			args = append(args, r.cleanValue(s))
		}
	}
	return args
}

// buildParamBindings builds parameter bindings from call sites
func (r *CallContextResolver) buildParamBindings() {
	for _, callSite := range r.callSites {
		calleeFunc, ok := r.functions[callSite.Callee]
		if !ok {
			continue
		}

		// Bind each parameter to its argument
		for i, param := range calleeFunc.Params {
			if i < len(callSite.Args) {
				key := callSite.Callee + ":" + param
				if _, exists := r.paramBindings[key]; !exists {
					r.paramBindings[key] = []string{}
				}
				r.paramBindings[key] = append(r.paramBindings[key], callSite.Args[i])
			}
		}
	}
}

// resolveInFunction resolves variable in function context
// Returns list of possible values (may be multiple due to different call sites)
func (r *CallContextResolver) resolveInFunction(varName string, funcName string) []string {
	// Check if it's a parameter
	fn, ok := r.functions[funcName]
	if ok {
		for _, param := range fn.Params {
			key := funcName + ":" + param
			if values, exists := r.paramBindings[key]; exists {
				return values
			}
		}
	}

	// Check if it's a local variable
	if ok {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Opcode == ASSIGN && instr.Result == varName && len(instr.Operands) > 0 {
					if s, ok := instr.Operands[0].(string); ok {
						return []string{r.cleanValue(s)}
					}
				}
			}
		}
	}

	return []string{}
}

// resolvePathInContext resolves path variable in function context
// Returns list of possible resolved paths
func (r *CallContextResolver) resolvePathInContext(pathVar string, funcName string) []string {
	// Try direct resolution
	values := r.resolveInFunction(pathVar, funcName)
	if len(values) == 0 {
		return []string{"unknown"}
	}

	resolvedPaths := []string{}
	for _, value := range values {
		// Try to resolve further
		resolved := r.resolveValue(value)
		if len(resolved) > 0 {
			resolvedPaths = append(resolvedPaths, resolved...)
		}
	}

	if len(resolvedPaths) == 0 {
		return []string{"unknown"}
	}
	return resolvedPaths
}

// resolveValue recursively resolves a value
func (r *CallContextResolver) resolveValue(value string) []string {
	value = r.cleanValue(value)

	// Check constants
	if r.constantFolder != nil {
		if constVal, ok := r.constantFolder.constants[value]; ok {
			if constValStr, ok := constVal.(string); ok {
				return []string{r.cleanValue(constValStr)}
			}
		}
	}

	// Check if it's a strcat result
	if len(value) > 1 && value[0] == 't' && value[1] >= '0' && value[1] <= '9' {
		return r.resolveStrcat(value)
	}

	// Check if it's a literal path
	if contains(value, ".") || contains(value, "/") || contains(value, "\\") {
		return []string{value}
	}

	return []string{}
}

// resolveStrcat resolves strcat operation
func (r *CallContextResolver) resolveStrcat(tempVar string) []string {
	for _, fn := range r.functions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Result == tempVar && instr.Opcode == CALL && len(instr.Operands) > 0 {
					if callee, ok := instr.Operands[0].(string); ok {
						calleeLower := toLower(r.cleanValue(callee))
						if calleeLower == "strcat" || calleeLower == "vl-string-subst" {
							// Resolve each component
							parts := []string{}
							for _, arg := range instr.Operands[1:] {
								if s, ok := arg.(string); ok {
									resolved := r.resolveValue(s)
									if len(resolved) > 0 {
										parts = append(parts, resolved[0])
									} else {
										// Try to identify getvar patterns
										getvarVal := r.findGetvarValue(s)
										if getvarVal != "" {
											parts = append(parts, "<"+getvarVal+">")
										} else {
											parts = append(parts, "<"+r.cleanValue(s)+">")
										}
									}
								}
							}

							// Build path
							path := ""
							for _, part := range parts {
								path += part
							}

							// Infer common patterns
							if contains(path, "<dwgprefix>") && contains(path, "acaddoc") {
								return []string{"dwgprefix/acaddoc.lsp"}
							} else if contains(path, "<menuname>") && contains(path, "doc.lsp") {
								return []string{"menuname/doc.lsp"}
							} else if contains(path, "<menuname>") && contains(path, ".mnl") {
								return []string{"menuname.mnl"}
							}

							return []string{path}
						}
					}
				}
			}
		}
	}
	return []string{}
}

// findGetvarValue finds the value of a getvar call
func (r *CallContextResolver) findGetvarValue(arg string) string {
	// This is a simplified version - in the full implementation,
	// this would track getvar calls and their resolved values
	argLower := toLower(r.cleanValue(arg))

	// Common AutoCAD environment variables
	envVars := map[string]string{
		"dwgprefix": "DWGPREFIX",
		"dwgname":   "DWGNAME",
		"menuname":  "MENUNAME",
		"acadver":   "ACADVER",
	}

	for key, val := range envVars {
		if contains(argLower, key) {
			return val
		}
	}

	return ""
}
