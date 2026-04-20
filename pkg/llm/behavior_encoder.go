package llm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/evilcad/cadscanner/pkg/ir"
)

// BehaviorEncoder encodes behavior patterns for LLM analysis
type BehaviorEncoder struct {
	encodingTemplate string
}

// NewBehaviorEncoder creates a new behavior encoder
func NewBehaviorEncoder() *BehaviorEncoder {
	return &BehaviorEncoder{
		encodingTemplate: `# Malware Behavior Analysis

## IR Effects
%s

## Lifted Effects
%s

## Function Summaries
%s

## Propagation Evidence
- Entry Points: %v
- Targets: %v
- Lateral Movement: %v
- Autoload: %v

## Analysis Task
Based on the above IR effects, lifted effects, and propagation evidence, analyze the malware behavior:
1. Identify the primary malware type (worm, trojan, backdoor, etc.)
2. Describe the propagation mechanism
3. Identify persistence mechanisms
4. Assess the stealth techniques used
5. Determine the destructive capabilities

Provide a structured analysis with confidence scores for each assessment.`,
	}
}

// EncodingResult represents the result of behavior encoding
type EncodingResult struct {
	Encoding      string
	Metadata      map[string]interface{}
	Effects       []ir.IREffect
	LiftedEffects []ir.LiftedEffect
}

// Encode encodes the analysis results for LLM processing
func (be *BehaviorEncoder) Encode(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, functionSummaries map[string]*ir.FunctionSummary, propEvidence *ir.PropagationEvidence) *EncodingResult {
	// Encode IR effects
	effectsEncoding := be.encodeEffects(effects)

	// Encode lifted effects
	liftedEncoding := be.encodeLiftedEffects(liftedEffects)

	// Encode function summaries
	summariesEncoding := be.encodeFunctionSummaries(functionSummaries)

	// Encode propagation evidence
	propEvidenceEncoding := be.encodePropagationEvidence(propEvidence)

	// Build final encoding
	encoding := fmt.Sprintf(be.encodingTemplate,
		effectsEncoding,
		liftedEncoding,
		summariesEncoding,
		propEvidence.EntryPoints,
		propEvidenceEncoding,
		propEvidence.LateralMovement,
		propEvidence.LocalAutoload,
	)

	return &EncodingResult{
		Encoding: encoding,
		Metadata: map[string]interface{}{
			"effects_count":        len(effects),
			"lifted_effects_count": len(liftedEffects),
			"functions_count":      len(functionSummaries),
			"template_version":     "1.0",
		},
		Effects:       effects,
		LiftedEffects: liftedEffects,
	}
}

// encodeEffects encodes IR effects to text
func (be *BehaviorEncoder) encodeEffects(effects []ir.IREffect) string {
	if len(effects) == 0 {
		return "No effects detected."
	}

	var sb strings.Builder
	for i, effect := range effects {
		sb.WriteString(fmt.Sprintf("%d. %s on %s (line %d)\n",
			i+1,
			effect.EffectType,
			effect.Target,
			effect.Line,
		))
		if effect.Source != "" {
			sb.WriteString(fmt.Sprintf("   Source: %s\n", effect.Source))
		}
		if len(effect.Metadata) > 0 {
			sb.WriteString(fmt.Sprintf("   Metadata: %v\n", effect.Metadata))
		}
	}
	return sb.String()
}

// encodeLiftedEffects encodes lifted effects to text
func (be *BehaviorEncoder) encodeLiftedEffects(liftedEffects []ir.LiftedEffect) string {
	if len(liftedEffects) == 0 {
		return "No lifted effects detected."
	}

	var sb strings.Builder
	for i, effect := range liftedEffects {
		sb.WriteString(fmt.Sprintf("%d. %s: %s (confidence: %.2f)\n",
			i+1,
			effect.EffectType,
			effect.Target,
			effect.Confidence,
		))
		if effect.Method != "" {
			sb.WriteString(fmt.Sprintf("   Method: %s\n", effect.Method))
		}
		if effect.RuleID != "" {
			sb.WriteString(fmt.Sprintf("   Rule: %s (%s)\n", effect.RuleID, effect.RuleName))
		}
	}
	return sb.String()
}

// encodeFunctionSummaries encodes function summaries to text
func (be *BehaviorEncoder) encodeFunctionSummaries(summaries map[string]*ir.FunctionSummary) string {
	if len(summaries) == 0 {
		return "No function summaries available."
	}

	var sb strings.Builder
	names := make([]string, 0, len(summaries))
	for funcName := range summaries {
		names = append(names, funcName)
	}
	sort.Strings(names)
	for _, funcName := range names {
		summary := summaries[funcName]
		sb.WriteString(fmt.Sprintf("Function: %s\n", funcName))
		sb.WriteString(fmt.Sprintf("  Direct Effects: %v\n", summary.DirectEffects))
		sb.WriteString(fmt.Sprintf("  Inherited Effects: %v\n", summary.InheritedEffects))
		sb.WriteString(fmt.Sprintf("  Calls: %v\n", summary.Calls))
		if len(summary.InferredBehaviors) > 0 {
			behaviors := []string{}
			for behavior := range summary.InferredBehaviors {
				behaviors = append(behaviors, behavior)
			}
			sort.Strings(behaviors)
			sb.WriteString(fmt.Sprintf("  Inferred Behaviors: %v\n", behaviors))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// encodePropagationEvidence encodes propagation evidence to text
func (be *BehaviorEncoder) encodePropagationEvidence(propEvidence *ir.PropagationEvidence) string {
	if propEvidence == nil {
		return "No propagation evidence available."
	}

	targets := []string{}
	for _, target := range propEvidence.Targets {
		targets = append(targets, target.Path)
	}

	return fmt.Sprintf("%v", targets)
}

// EncodeJSON encodes the analysis results to JSON format
func (be *BehaviorEncoder) EncodeJSON(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, functionSummaries map[string]*ir.FunctionSummary, propEvidence *ir.PropagationEvidence) (string, error) {
	data := map[string]interface{}{
		"effects":              effects,
		"lifted_effects":       liftedEffects,
		"function_summaries":   functionSummaries,
		"propagation_evidence": propEvidence,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
