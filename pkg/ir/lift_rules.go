package ir

import (
	"fmt"
	"regexp"
	"strings"
)

// LiftRule represents a declarative effect lifting rule
type LiftRule struct {
	ID      string
	Name    string
	Pattern Pattern
	Extract map[string]string
	Effect  Effect
}

// Pattern represents the matching pattern for a rule
type Pattern struct {
	Type       string
	Func       string
	ObjectType string
	Method     string
	Property   string
	Value      interface{}
	PathRegex  string
	KeyRegex   string
}

// Effect represents the high-level security effect
type Effect struct {
	Type       string
	Severity   string
	Confidence float64
}

// EFFECT_RULES contains all declarative effect lifting rules
var EFFECT_RULES = []LiftRule{
	// Process Execution
	{
		ID:   "EXEC_001",
		Name: "WScript.Shell.Run",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "wscript.shell",
			Method:     "run",
		},
		Extract: map[string]string{
			"target":  "args[0]",
			"command": "args[0]",
		},
		Effect: Effect{
			Type:       "PROCESS_EXEC",
			Severity:   "critical",
			Confidence: 0.95,
		},
	},
	{
		ID:   "EXEC_002",
		Name: "Shell.Application.ShellExecute",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "shell.application",
			Method:     "shellexecute",
		},
		Extract: map[string]string{
			"target": "args[0]",
		},
		Effect: Effect{
			Type:       "PROCESS_EXEC",
			Severity:   "critical",
			Confidence: 0.95,
		},
	},

	// Persistence
	{
		ID:   "PERSIST_001",
		Name: "Startup file write",
		Pattern: Pattern{
			Type:      "file_write",
			PathRegex: ".*(acad|acaddoc)\\.lsp$",
		},
		Effect: Effect{
			Type:       "PERSISTENCE",
			Severity:   "high",
			Confidence: 0.9,
		},
	},
	{
		ID:   "PERSIST_002",
		Name: "Registry Run key",
		Pattern: Pattern{
			Type:     "registry_write",
			KeyRegex: ".*\\\\Run.*",
		},
		Effect: Effect{
			Type:       "PERSISTENCE",
			Severity:   "high",
			Confidence: 0.9,
		},
	},

	// Stealth
	{
		ID:   "STEALTH_001",
		Name: "File attribute hidden",
		Pattern: Pattern{
			Type:       "com_put",
			ObjectType: "scripting.filesystemobject",
			Property:   "attributes",
			Value:      2,
		},
		Effect: Effect{
			Type:       "STEALTH",
			Severity:   "high",
			Confidence: 0.85,
		},
	},
	{
		ID:   "STEALTH_002",
		Name: "Registry hide files",
		Pattern: Pattern{
			Type:     "registry_write",
			KeyRegex: ".*(Hidden|ShowAll).*",
		},
		Effect: Effect{
			Type:       "STEALTH",
			Severity:   "high",
			Confidence: 0.85,
		},
	},

	// Code Execution
	{
		ID:   "CODE_001",
		Name: "Dynamic load",
		Pattern: Pattern{
			Type: "call",
			Func: "load",
		},
		Extract: map[string]string{
			"target": "args[0]",
		},
		Effect: Effect{
			Type:       "CODE_LOAD",
			Severity:   "medium",
			Confidence: 0.8,
		},
	},
	{
		ID:   "CODE_002",
		Name: "Dynamic eval",
		Pattern: Pattern{
			Type: "call",
			Func: "eval",
		},
		Effect: Effect{
			Type:       "CODE_EVAL",
			Severity:   "high",
			Confidence: 0.85,
		},
	},

	// File Operations
	{
		ID:   "FILE_001",
		Name: "File deletion",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "scripting.filesystemobject",
			Method:     "deletefile",
		},
		Extract: map[string]string{
			"target": "args[0]",
		},
		Effect: Effect{
			Type:       "FILE_DELETE",
			Severity:   "medium",
			Confidence: 0.8,
		},
	},
	{
		ID:   "FILE_002",
		Name: "File copy",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "scripting.filesystemobject",
			Method:     "copyfile",
		},
		Extract: map[string]string{
			"source": "args[0]",
			"dest":   "args[1]",
		},
		Effect: Effect{
			Type:       "FILE_COPY",
			Severity:   "low",
			Confidence: 0.7,
		},
	},

	// Network
	{
		ID:   "NET_001",
		Name: "HTTP request",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "msxml2.xmlhttp",
			Method:     "open",
		},
		Extract: map[string]string{
			"url": "args[1]",
		},
		Effect: Effect{
			Type:       "NETWORK_HTTP",
			Severity:   "medium",
			Confidence: 0.8,
		},
	},

	// WMI Query
	{
		ID:   "WMI_001",
		Name: "WMI query",
		Pattern: Pattern{
			Type:       "com_invoke",
			ObjectType: "wbemscripting.swbemlocator",
			Method:     "connectserver",
		},
		Effect: Effect{
			Type:       "WMI_QUERY",
			Severity:   "medium",
			Confidence: 0.75,
		},
	},

	// Specific rule for benign COM initialization (vl-load-com is NOT dangerous)
	{
		ID:   "BENIGN_COM_INIT",
		Name: "Benign COM initialization",
		Pattern: Pattern{
			Type: "com_create",
			Func: "vl-load-com",
		},
		Effect: Effect{
			Type:       "COM_INIT",
			Severity:   "low",
			Confidence: 0.15,
		},
	},

	// Benign temporary file operations
	{
		ID:   "TEMP_FILE_WRITE",
		Name: "Temporary file write",
		Pattern: Pattern{
			Type:      "file_write",
			PathRegex: `.*fn.*`, // Variables named fn often come from vl-filename-mktemp
		},
		Effect: Effect{
			Type:       "TEMP_FILE_WRITE",
			Severity:   "low",
			Confidence: 0.3,
		},
	},

	// Basic fallback rules for common effect types
	{
		ID:   "BASIC_FILE_WRITE",
		Name: "Basic file write",
		Pattern: Pattern{
			Type: "file_write",
		},
		Effect: Effect{
			Type:       "FILE_WRITE",
			Severity:   "medium",
			Confidence: 0.7,
		},
	},
	{
		ID:   "BASIC_REGISTRY_WRITE",
		Name: "Basic registry write",
		Pattern: Pattern{
			Type: "registry_write",
		},
		Effect: Effect{
			Type:       "REGISTRY_MOD",
			Severity:   "high",
			Confidence: 0.8,
		},
	},
	{
		ID:   "BASIC_PROCESS_CREATE",
		Name: "Basic process create",
		Pattern: Pattern{
			Type: "process_create",
		},
		Effect: Effect{
			Type:       "PROCESS_EXEC",
			Severity:   "high",
			Confidence: 0.85,
		},
	},
	{
		ID:   "BASIC_COM_CREATE",
		Name: "Basic COM create",
		Pattern: Pattern{
			Type: "com_create",
		},
		Effect: Effect{
			Type:       "COM_CREATE",
			Severity:   "medium",
			Confidence: 0.7,
		},
	},
	{
		ID:   "BASIC_COM_INVOKE",
		Name: "Basic COM invoke",
		Pattern: Pattern{
			Type: "com_invoke",
		},
		Effect: Effect{
			Type:       "COM_INVOKE",
			Severity:   "medium",
			Confidence: 0.7,
		},
	},
	{
		ID:   "BASIC_ENV_CHECK",
		Name: "Basic environment check",
		Pattern: Pattern{
			Type: "env_check",
		},
		Effect: Effect{
			Type:       "ENV_CHECK",
			Severity:   "low",
			Confidence: 0.6,
		},
	},
	{
		ID:   "BASIC_NETWORK_CONNECT",
		Name: "Basic network connect",
		Pattern: Pattern{
			Type: "network_connect",
		},
		Effect: Effect{
			Type:       "NETWORK_HTTP",
			Severity:   "high",
			Confidence: 0.8,
		},
	},
}

// RuleMatcher matches IR nodes against lifting rules
type RuleMatcher struct {
	rules []LiftRule
}

// NewRuleMatcher creates a new rule matcher
func NewRuleMatcher(rules []LiftRule) *RuleMatcher {
	if rules == nil {
		rules = EFFECT_RULES
	}
	return &RuleMatcher{
		rules: rules,
	}
}

// Match matches node against all rules, returns matched rules
func (rm *RuleMatcher) Match(irNode map[string]interface{}, context map[string]interface{}) []LiftRule {
	matched := []LiftRule{}

	for _, rule := range rm.rules {
		if rm.matchRule(irNode, rule, context) {
			matched = append(matched, rule)
		}
	}

	return matched
}

// matchRule checks if node matches rule pattern
func (rm *RuleMatcher) matchRule(irNode map[string]interface{}, rule LiftRule, context map[string]interface{}) bool {
	pattern := rule.Pattern

	// Type match
	if pattern.Type != "" {
		if irNode["type"] != pattern.Type {
			return false
		}
	}

	// Function match
	if pattern.Func != "" {
		if strings.ToLower(irNodeGet(irNode, "func")) != strings.ToLower(pattern.Func) {
			return false
		}
	}

	// COM object type match
	if pattern.ObjectType != "" {
		objVar := irNodeGet(irNode, "object")
		if objVar != "" {
			symbolTable, _ := context["symbol_table"].(map[string]string)
			objType := symbolTable[objVar]
			if objType != "" {
				objTypeStr := strings.ToLower(objType)
				if objTypeStr != strings.ToLower(pattern.ObjectType) {
					return false
				}
			} else {
				return false
			}
		} else {
			return false
		}
	}

	// Method match
	if pattern.Method != "" {
		if strings.ToLower(irNodeGet(irNode, "method")) != strings.ToLower(pattern.Method) {
			return false
		}
	}

	// Property match
	if pattern.Property != "" {
		if strings.ToLower(irNodeGet(irNode, "property")) != strings.ToLower(pattern.Property) {
			return false
		}
	}

	// Value match
	if pattern.Value != nil {
		if irNode["value"] != pattern.Value {
			return false
		}
	}

	// Path regex match
	if pattern.PathRegex != "" {
		target := irNodeGet(irNode, "target")
		matched, _ := regexp.MatchString(pattern.PathRegex, target)
		if !matched {
			return false
		}
	}

	// Key regex match
	if pattern.KeyRegex != "" {
		key := irNodeGet(irNode, "target")
		matched, _ := regexp.MatchString(pattern.KeyRegex, key)
		if !matched {
			return false
		}
	}

	return true
}

// ExtractEffect extracts effect from matched rule
func (rm *RuleMatcher) ExtractEffect(irNode map[string]interface{}, rule LiftRule, context map[string]interface{}) map[string]interface{} {
	effect := map[string]interface{}{
		"type":       rule.Effect.Type,
		"severity":   rule.Effect.Severity,
		"confidence": rule.Effect.Confidence,
		"rule_id":    rule.ID,
		"rule_name":  rule.Name,
	}

	// Extract fields
	if rule.Extract != nil {
		for field, expr := range rule.Extract {
			value := rm.evaluateExtract(expr, irNode, context)
			if value != nil {
				effect[field] = value
			}
		}
	}

	// Add source info
	effect["source_line"] = irNodeGet(irNode, "line")
	effect["source_node"] = irNodeGet(irNode, "id")

	return effect
}

// evaluateExtract evaluates extraction expression
func (rm *RuleMatcher) evaluateExtract(expr string, irNode map[string]interface{}, context map[string]interface{}) interface{} {
	// args[N] - extract argument
	if strings.HasPrefix(expr, "args[") {
		idxStr := strings.TrimPrefix(expr, "args[")
		idxStr = strings.TrimSuffix(idxStr, "]")
		var idx int
		if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil {
			args, _ := irNode["args"].([]interface{})
			if idx >= 0 && idx < len(args) {
				arg := args[idx]
				constants, _ := context["constants"].(map[string]interface{})
				if val, ok := constants[arg.(string)]; ok {
					return val
				}
				return arg
			}
		}
		return nil
	}

	// Direct field access
	return irNode[expr]
}

// irNodeGet safely gets a value from irNode as string
func irNodeGet(irNode map[string]interface{}, key string) string {
	if val, ok := irNode[key]; ok {
		switch v := val.(type) {
		case string:
			return v
		case int:
			return fmt.Sprintf("%d", v)
		case float64:
			return fmt.Sprintf("%f", v)
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}
