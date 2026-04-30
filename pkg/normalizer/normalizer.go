package normalizer

import (
	"github.com/evilcad/cadscanner/pkg/parser"
)

// NormalizedNode represents a normalized AST node with semantic information
type NormalizedNode struct {
	Operation    OperationType
	FunctionName string
	Arguments    []interface{}
	Line         int
	Column       int
	Metadata     map[string]interface{}
}

// ToDict converts the node to a dictionary-like structure
func (n *NormalizedNode) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"operation": string(n.Operation),
		"function":  n.FunctionName,
		"arguments": serializeArgs(n.Arguments),
		"line":      n.Line,
		"column":    n.Column,
		"metadata":  n.Metadata,
	}
	return result
}

// serializeArgs serializes arguments for JSON
func serializeArgs(args []interface{}) []interface{} {
	result := make([]interface{}, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case *NormalizedNode:
			result[i] = v.ToDict()
		case *parser.ASTNode:
			result[i] = map[string]interface{}{
				"type":  v.Type,
				"value": v.Value,
			}
		default:
			result[i] = arg
		}
	}
	return result
}

// Normalizer normalizes AST into semantic representation
type Normalizer struct {
	Functions        map[string]*NormalizedNode
	Variables        map[string]interface{}
	FunctionAliases  map[string]string
}

// NewNormalizer creates a new normalizer
func NewNormalizer() *Normalizer {
	return &Normalizer{
		Functions:       make(map[string]*NormalizedNode),
		Variables:       make(map[string]interface{}),
		FunctionAliases: make(map[string]string),
	}
}

// Normalize normalizes a list of AST nodes
func (n *Normalizer) Normalize(astNodes []*parser.ASTNode) []*NormalizedNode {
	normalized := make([]*NormalizedNode, 0)

	for _, node := range astNodes {
		result := n.normalizeNode(node)
		if result != nil {
			normalized = append(normalized, result)

			// Track function definitions
			if result.Operation == DEFUN {
				funcName := ""
				if len(result.Arguments) > 0 {
					if name, ok := result.Arguments[0].(string); ok {
						funcName = name
					}
				}
				if funcName != "" {
					n.Functions[funcName] = result
				}
			}
		}
	}

	return normalized
}

// normalizeNode normalizes a single AST node
func (n *Normalizer) normalizeNode(node *parser.ASTNode) *NormalizedNode {
	if node == nil {
		return nil
	}

	if node.Type == "call" {
		return n.normalizeCall(node)
	} else if node.Type == "list" {
		// Handle quoted lists
		return nil
	}

	return nil
}

// normalizeCall normalizes a function call
func (n *Normalizer) normalizeCall(node *parser.ASTNode) *NormalizedNode {
	originalFunctionName := ""
	if v, ok := node.Value.(string); ok {
		originalFunctionName = v
	}
	
	functionName := n.resolveFunctionAlias(originalFunctionName)
	operation := GetOperationType(functionName)

	// Normalize arguments
	arguments := make([]interface{}, 0)
	for _, child := range node.Children {
		arg := n.extractArgument(child)
		arguments = append(arguments, arg)
	}

	// Extract metadata based on operation type
	metadata := n.extractMetadata(operation, functionName, arguments)
	if functionName != originalFunctionName {
		metadata["alias_of"] = originalFunctionName
	}

	return &NormalizedNode{
		Operation:    operation,
		FunctionName: functionName,
		Arguments:    arguments,
		Line:         node.Line,
		Column:       node.Column,
		Metadata:     metadata,
	}
}

// resolveFunctionAlias resolves function aliases
func (n *Normalizer) resolveFunctionAlias(name string) string {
	if alias, ok := n.FunctionAliases[name]; ok {
		return alias
	}
	return name
}

// extractArgument extracts an argument from an AST node
func (n *Normalizer) extractArgument(node *parser.ASTNode) interface{} {
	if node == nil {
		return nil
	}

	switch node.Type {
	case "symbol", "string", "number":
		return node.Value
	case "call", "list":
		return n.normalizeNode(node)
	case "quote":
		if len(node.Children) > 0 {
			return node.Children[0]
		}
		return nil
	default:
		return node.Value
	}
}

// extractMetadata extracts metadata based on operation type
func (n *Normalizer) extractMetadata(operation OperationType, functionName string, arguments []interface{}) map[string]interface{} {
	metadata := make(map[string]interface{})
	
	// Add operation-specific metadata
	switch operation {
	case FILE_WRITE:
		if len(arguments) > 0 {
			metadata["target"] = arguments[0]
		}
	case REG_WRITE:
		if len(arguments) > 0 {
			metadata["registry_key"] = arguments[0]
		}
	case COM_CREATE:
		if len(arguments) > 0 {
			metadata["com_object"] = arguments[0]
		}
	case OS_EXEC:
		if len(arguments) > 0 {
			metadata["command"] = arguments[0]
		}
	}
	
	return metadata
}
