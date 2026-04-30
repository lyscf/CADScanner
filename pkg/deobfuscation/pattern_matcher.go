package deobfuscation

import (
	"fmt"
	"strings"

	"github.com/evilcad/cadscanner/pkg/normalizer"
)

// ObfuscationPattern represents a detected obfuscation pattern
type ObfuscationPattern struct {
	PatternType  string
	Description  string
	Nodes        []string
	Deobfuscated string
	Confidence   float64
}

// PatternMatcher matches and deobfuscates common patterns
type PatternMatcher struct {
	patterns []ObfuscationPattern
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		patterns: make([]ObfuscationPattern, 0),
	}
}

// Analyze analyzes nodes for obfuscation patterns
func (pm *PatternMatcher) Analyze(normalized []*normalizer.NormalizedNode) []ObfuscationPattern {
	pm.patterns = make([]ObfuscationPattern, 0)

	// Detect patterns
	pm.detectChREncoding(normalized)
	pm.detectNumericTransform(normalized)
	pm.detectListObfuscation(normalized)
	pm.detectConditionalEnvCheck(normalized)

	return pm.patterns
}

// detectChREncoding detects chr-based string encoding
func (pm *PatternMatcher) detectChREncoding(nodes []*normalizer.NormalizedNode) {
	chrSequences := [][]struct {
		node     *normalizer.NormalizedNode
		charCode int
	}{}
	currentSequence := []struct {
		node     *normalizer.NormalizedNode
		charCode int
	}{}

	for _, node := range nodes {
		if node == nil {
			continue
		}
		if pm.isChrCall(node) {
			// Extract chr value
			if len(node.Arguments) > 0 {
				if num, ok := node.Arguments[0].(int); ok {
					currentSequence = append(currentSequence, struct {
						node     *normalizer.NormalizedNode
						charCode int
					}{node: node, charCode: num})
				} else if str, ok := node.Arguments[0].(string); ok {
					// Try to parse string as number
					var code int
					_, err := fmt.Sscanf(str, "%d", &code)
					if err == nil {
						currentSequence = append(currentSequence, struct {
							node     *normalizer.NormalizedNode
							charCode int
						}{node: node, charCode: code})
					}
				}
			}
		} else if len(currentSequence) > 0 {
			// End of sequence
			if len(currentSequence) >= 3 {
				chrSequences = append(chrSequences, currentSequence)
			}
			currentSequence = []struct {
				node     *normalizer.NormalizedNode
				charCode int
			}{}
		}
	}

	// Check last sequence
	if len(currentSequence) >= 3 {
		chrSequences = append(chrSequences, currentSequence)
	}

	// Process sequences
	for _, sequence := range chrSequences {
		// Decode string
		var decoded strings.Builder
		for _, item := range sequence {
			if item.charCode >= 32 && item.charCode <= 126 {
				decoded.WriteRune(rune(item.charCode))
			}
		}

		nodes := make([]string, 0)
		for _, item := range sequence {
			nodes = append(nodes, fmt.Sprintf("line_%d", item.node.Line))
		}

		pattern := ObfuscationPattern{
			PatternType:  "CHR_ENCODING",
			Description:  fmt.Sprintf("String encoded with %d chr() calls", len(sequence)),
			Nodes:        nodes,
			Deobfuscated: decoded.String(),
			Confidence:   1.0,
		}
		pm.patterns = append(pm.patterns, pattern)
	}
}

// detectNumericTransform detects numeric transformation patterns
func (pm *PatternMatcher) detectNumericTransform(nodes []*normalizer.NormalizedNode) {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Operation == normalizer.DEFUN {
			funcName := node.FunctionName

			// Check for transformation functions
			if pm.isTransformFunction(node) {
				pattern := ObfuscationPattern{
					PatternType:  "NUMERIC_TRANSFORM",
					Description:  fmt.Sprintf("Numeric transformation function: %s", funcName),
					Nodes:        []string{fmt.Sprintf("line_%d", node.Line)},
					Deobfuscated: fmt.Sprintf("TRANSFORM_FUNC(%s)", funcName),
					Confidence:   0.9,
				}
				pm.patterns = append(pm.patterns, pattern)
			}
		}
	}
}

// detectListObfuscation detects obfuscated list patterns
func (pm *PatternMatcher) detectListObfuscation(nodes []*normalizer.NormalizedNode) {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Operation == normalizer.SETQ && len(node.Arguments) > 0 {
			varName, _ := node.Arguments[0].(string)
			value := interface{}(nil)
			if len(node.Arguments) > 1 {
				value = node.Arguments[1]
			}

			// Check for large numeric lists
			if valNode, ok := value.(*normalizer.NormalizedNode); ok && valNode != nil && valNode.Operation == normalizer.LIST {
				if pm.isNumericList(valNode) {
					pattern := ObfuscationPattern{
						PatternType:  "LIST_OBFUSCATION",
						Description:  fmt.Sprintf("Large numeric list assignment: %s", varName),
						Nodes:        []string{fmt.Sprintf("line_%d", node.Line)},
						Deobfuscated: fmt.Sprintf("NUMERIC_LIST(%s)", varName),
						Confidence:   0.8,
					}
					pm.patterns = append(pm.patterns, pattern)
				}
			}
		}
	}
}

// detectConditionalEnvCheck detects conditional environment checks
func (pm *PatternMatcher) detectConditionalEnvCheck(nodes []*normalizer.NormalizedNode) {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.Operation == normalizer.IF {
			// Check if condition involves environment variables
			if pm.isEnvCheck(node) {
				pattern := ObfuscationPattern{
					PatternType:  "ENV_CHECK",
					Description:  "Conditional environment variable check",
					Nodes:        []string{fmt.Sprintf("line_%d", node.Line)},
					Deobfuscated: "ENV_CHECK",
					Confidence:   0.7,
				}
				pm.patterns = append(pm.patterns, pattern)
			}
		}
	}
}

// isChrCall checks if node is a chr() call
func (pm *PatternMatcher) isChrCall(node *normalizer.NormalizedNode) bool {
	if node == nil {
		return false
	}
	if node.Operation == normalizer.STRING_DECODE {
		return true
	}
	return strings.EqualFold(node.FunctionName, "chr")
}

// isTransformFunction checks if function is a transformation function
func (pm *PatternMatcher) isTransformFunction(node *normalizer.NormalizedNode) bool {
	if node == nil {
		return false
	}
	// Check for common transformation function patterns
	transformKeywords := []string{"mkgroup", "decode", "encode", "transform", "obfuscate"}
	funcName := strings.ToLower(node.FunctionName)
	for _, keyword := range transformKeywords {
		if strings.Contains(funcName, keyword) {
			return true
		}
	}
	return false
}

// isNumericList checks if node is a numeric list
func (pm *PatternMatcher) isNumericList(node *normalizer.NormalizedNode) bool {
	if node == nil {
		return false
	}
	if len(node.Arguments) == 0 {
		return false
	}

	numericCount := 0
	for _, arg := range node.Arguments {
		switch arg.(type) {
		case int, float64:
			numericCount++
		case string:
			numericCount++
		}
	}

	// Consider it numeric if > 80% are numbers
	return float64(numericCount)/float64(len(node.Arguments)) > 0.8
}

// isEnvCheck checks if node is an environment variable check
func (pm *PatternMatcher) isEnvCheck(node *normalizer.NormalizedNode) bool {
	if node == nil {
		return false
	}
	if len(node.Arguments) == 0 {
		return false
	}

	envKeywords := []string{"getenv", "getenv", "sysvar", "getvar", "findfile"}

	// Check condition for env functions
	for _, arg := range node.Arguments {
		if child, ok := arg.(*normalizer.NormalizedNode); ok && child != nil {
			for _, keyword := range envKeywords {
				if strings.EqualFold(child.FunctionName, keyword) {
					return true
				}
			}
		}
	}

	return false
}
