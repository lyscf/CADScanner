package ir

import (
	"fmt"
	"strings"
)

// LiftedEffect represents a high-level security effect
type LiftedEffect struct {
	EffectType string                 // PERSISTENCE, PROCESS_EXEC, STEALTH, etc.
	Target     string                 // Target of the effect
	Method     string                 // Method used (optional)
	Severity   string                 // Severity level
	Confidence float64                // Confidence score
	RuleID     string                 // Rule ID that matched
	RuleName   string                 // Rule name
	SourceLine int                    // Source line number
	Metadata   map[string]interface{} // Additional metadata
}

// ToDict converts LiftedEffect to dictionary representation
func (le *LiftedEffect) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"type":       le.EffectType,
		"target":     le.Target,
		"method":     le.Method,
		"severity":   le.Severity,
		"confidence": le.Confidence,
		"rule":       le.RuleID,
		"line":       le.SourceLine,
	}
}

// EffectLifter lifts IR effects to high-level behaviors
type EffectLifter struct {
	constantFolder *ConstantFolder
	symbolTable    map[string]string
	matcher        *RuleMatcher
	constants      map[string]interface{}
}

// NewEffectLifter creates a new effect lifter
func NewEffectLifter(constantFolder *ConstantFolder, symbolTable map[string]string) *EffectLifter {
	lifter := &EffectLifter{
		constantFolder: constantFolder,
		symbolTable:    symbolTable,
		matcher:        NewRuleMatcher(nil),
		constants:      make(map[string]interface{}),
	}

	// Build constants map from folder
	if constantFolder != nil {
		lifter.constants = constantFolder.constants
	}

	return lifter
}

// Lift lifts IR effects to high-level behaviors
func (el *EffectLifter) Lift(irEffects []IREffect) []LiftedEffect {
	lifted := []LiftedEffect{}

	for _, effect := range irEffects {
		// Convert IR effect to dict for matching
		irNode := el.effectToDict(effect)

		// Build context
		context := map[string]interface{}{
			"symbol_table": el.symbolTable,
			"constants":    el.constants,
		}

		// Try to match against rules
		matchedRules := el.matcher.Match(irNode, context)

		if len(matchedRules) > 0 {
			// Use first matched rule
			rule := matchedRules[0]
			liftedEffect := el.createLiftedEffect(effect, rule, context)
			lifted = append(lifted, liftedEffect)
		} else {
			// No rule matched, create basic lifted effect
			basicEffect := el.createBasicLiftedEffect(effect)
			if basicEffect != nil {
				lifted = append(lifted, *basicEffect)
			}
		}
	}

	return lifted
}

// effectToDict converts IR effect to dict for rule matching
func (el *EffectLifter) effectToDict(effect IREffect) map[string]interface{} {
	effectDict := map[string]interface{}{
		"type":     el.mapEffectType(effect.EffectType),
		"target":   effect.Target,
		"source":   effect.Source,
		"func":     effect.Source, // Allow rules to match on function name
		"line":     effect.Line,
		"metadata": effect.Metadata,
	}

	// Add specific fields based on effect type
	if effect.EffectType == COM_INVOKE {
		effectDict["object"] = effect.Source
		if method, ok := effect.Metadata["method"].(string); ok {
			effectDict["method"] = method
		}
	}

	return effectDict
}

// mapEffectType maps IR effect type to rule pattern type
func (el *EffectLifter) mapEffectType(effectType EffectType) string {
	mapping := map[EffectType]string{
		FILE_WRITE:       "file_write",
		FILE_READ:        "file_read",
		FILE_DELETE:      "file_delete",
		REGISTRY_MODIFY:  "registry_write",
		REGISTRY_READ:    "registry_read",
		COM_CREATE:       "com_create",
		COM_INVOKE:       "com_invoke",
		COMMAND_UNDEFINE: "command_undefine",
		ENV_CHECK:        "env_check",
		PROCESS_CREATE:   "process_create",
		NETWORK_CONNECT:  "network_connect",
	}
	if mapped, ok := mapping[effectType]; ok {
		return mapped
	}
	return "unknown"
}

// createLiftedEffect creates lifted effect from matched rule
func (el *EffectLifter) createLiftedEffect(irEffect IREffect, rule LiftRule, context map[string]interface{}) LiftedEffect {
	// Extract effect details from rule
	effectData := el.matcher.ExtractEffect(el.effectToDict(irEffect), rule, context)

	method, _ := effectData["method"].(string)
	target, _ := effectData["target"].(string)
	if target == "" {
		target = irEffect.Target
	}

	// Handle source_line type conversion
	sourceLine := irEffect.Line
	if sl, ok := effectData["source_line"]; ok {
		switch v := sl.(type) {
		case float64:
			sourceLine = int(v)
		case int:
			sourceLine = v
		case string:
			// Try to parse string to int
			var parsed int
			if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil {
				sourceLine = parsed
			}
		}
	}

	return LiftedEffect{
		EffectType: effectData["type"].(string),
		Target:     target,
		Method:     method,
		Severity:   effectData["severity"].(string),
		Confidence: effectData["confidence"].(float64),
		RuleID:     effectData["rule_id"].(string),
		RuleName:   effectData["rule_name"].(string),
		SourceLine: sourceLine,
		Metadata:   irEffect.Metadata,
	}
}

// createBasicLiftedEffect creates basic lifted effect when no rule matches
func (el *EffectLifter) createBasicLiftedEffect(irEffect IREffect) *LiftedEffect {
	// Map common IR effects to basic lifted effects
	typeMapping := map[EffectType]string{
		FILE_WRITE:       "FILE_WRITE",
		FILE_READ:        "FILE_READ",
		FILE_DELETE:      "FILE_DELETE",
		REGISTRY_MODIFY:  "REGISTRY_MOD",
		REGISTRY_READ:    "REGISTRY_READ",
		COM_CREATE:       "COM_CREATE",
		COM_INVOKE:       "COM_INVOKE",
		COMMAND_UNDEFINE: "COMMAND_UNDEFINE",
		ENV_CHECK:        "ENV_CHECK",
		DATA_DESTROY:     "DATA_DESTROY",
		PROCESS_CREATE:   "PROCESS_EXEC",
		NETWORK_CONNECT:  "NETWORK_HTTP",
		FILE_HIDDEN:      "STEALTH",
	}

	liftedType, ok := typeMapping[irEffect.EffectType]
	if !ok {
		// Default to the effect type string itself
		liftedType = string(irEffect.EffectType)
	}

	// Default severity and confidence
	severity := "medium"
	confidence := 0.6

	// Handle benign COM initialization (vl-load-com is just enabling COM, not creating dangerous objects)
	if irEffect.EffectType == COM_CREATE {
		sourceLower := strings.ToLower(irEffect.Source)
		// Trim whitespace and check for vl-load-com (benign AutoCAD COM initialization)
		sourceLower = strings.TrimSpace(sourceLower)
		if sourceLower == "vl-load-com" || strings.Contains(sourceLower, "vl-load-com") {
			severity = "low"
			confidence = 0.2 // Very low confidence for benign COM init
		}
	}

	return &LiftedEffect{
		EffectType: liftedType,
		Target:     irEffect.Target,
		Severity:   severity,
		Confidence: confidence,
		SourceLine: irEffect.Line,
		Metadata:   irEffect.Metadata,
	}
}
