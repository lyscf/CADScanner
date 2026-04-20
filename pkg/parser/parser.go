package parser

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	maxDepth                     = 4096
	maxUnclosedDefunExtractCalls = 8192
)

// ParseError represents a parsing error
type ParseError struct {
	Message string
	Line    int
	Column  int
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("Parse error at line %d, column %d: %s", e.Line, e.Column, e.Message)
}

// ASTNode represents an AST node
type ASTNode struct {
	Type     string
	Value    interface{}
	Line     int
	Column   int
	Children []*ASTNode
}

// ToDict converts the node to a dictionary-like structure
func (n *ASTNode) ToDict() map[string]interface{} {
	result := map[string]interface{}{
		"type":   n.Type,
		"value":  n.Value,
		"line":   n.Line,
		"column": n.Column,
	}
	if len(n.Children) > 0 {
		children := make([]map[string]interface{}, len(n.Children))
		for i, child := range n.Children {
			children[i] = child.ToDict()
		}
		result["children"] = children
	}
	return result
}

// Parser parses AutoLISP source code
type Parser struct {
	tokens   []Token
	pos      int
	maxDepth int
}

// New creates a new parser from source code
func New() (*Parser, error) {
	return &Parser{
		maxDepth: maxDepth,
	}, nil
}

// NewFromTokens creates a new parser from tokens
func NewFromTokens(tokens []Token) *Parser {
	// Filter out comments
	filtered := make([]Token, 0, len(tokens))
	for _, t := range tokens {
		if t.Type != TokenComment {
			filtered = append(filtered, t)
		}
	}
	return &Parser{
		tokens:   filtered,
		pos:      0,
		maxDepth: maxDepth,
	}
}

// ParseSource parses source code into an AST
func (p *Parser) ParseSource(source string) ([]*ASTNode, error) {
	tokenizer := NewTokenizer(source)
	tokens, err := tokenizer.Tokenize()
	if err != nil {
		return nil, err
	}

	parser := NewFromTokens(tokens)
	return parser.Parse()
}

// Parse parses tokens into an AST
func (p *Parser) Parse() ([]*ASTNode, error) {
	var expressions []*ASTNode

	for !p.isAtEnd() {
		if p.peek().Type == TokenEOF {
			break
		}
		expr, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		if expr != nil {
			// Check for unclosed defun pattern - when a defun has deeply nested content,
			// it's likely an unclosed parentheses attack (e.g., acad2006.lsp virus)
			if expr.Type == "call" {
				if funcName, ok := expr.Value.(string); ok {
					funcNameLower := strings.ToLower(funcName)
					if funcNameLower == "defun" {
						// Extract nested expressions from unclosed defun
						bodyExprs := p.extractBodyFromUnclosedDefun(expr)
						// Always add defun, and add body expressions if found
						expressions = append(expressions, expr)
						if len(bodyExprs) > 0 {
							expressions = append(expressions, bodyExprs...)
						}
						continue
					}
				}
			}
			expressions = append(expressions, expr)
		}
	}

	return expressions, nil
}

// countTotalChildren recursively counts all children in a node
func (p *Parser) countTotalChildren(node *ASTNode) int {
	if node == nil {
		return 0
	}
	count := len(node.Children)
	for _, child := range node.Children {
		count += p.countTotalChildren(child)
	}
	return count
}

// extractBodyFromUnclosedDefun extracts body expressions from an unclosed defun
// This handles the acad2006.lsp virus pattern where (defun s::startup (/ ...
// is intentionally left unclosed to execute code on AutoCAD startup
func (p *Parser) extractBodyFromUnclosedDefun(defunNode *ASTNode) []*ASTNode {
	var bodyExprs []*ASTNode
	if len(defunNode.Children) < 2 {
		return bodyExprs
	}

	// For unclosed defun (e.g., (defun s::startup (/ ... )),
	// the entire file body may be contained in Children[1] (the parameter list)
	// because the (/ was never closed with )
	bodyExprs = p.extractCallsFromNode(defunNode.Children[1])
	return bodyExprs
}

// extractCallsFromNode recursively extracts all call-type nodes from a node
func (p *Parser) extractCallsFromNode(node *ASTNode) []*ASTNode {
	if node == nil {
		return nil
	}

	results := make([]*ASTNode, 0)
	stack := []*ASTNode{node}

	for len(stack) > 0 && len(results) < maxUnclosedDefunExtractCalls {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == nil {
			continue
		}

		if current.Type == "call" {
			results = append(results, current)
			if len(results) >= maxUnclosedDefunExtractCalls {
				break
			}
		}

		for i := len(current.Children) - 1; i >= 0; i-- {
			child := current.Children[i]
			if child == nil || len(child.Children) == 0 && child.Type != "call" {
				continue
			}
			stack = append(stack, child)
		}
	}

	return results
}

// parseExpression parses a single expression
func (p *Parser) parseExpression(depth int) (*ASTNode, error) {
	if depth > p.maxDepth {
		token := p.peek()
		return nil, &ParseError{
			Message: fmt.Sprintf("Maximum parse depth exceeded (%d)", p.maxDepth),
			Line:    token.Line,
			Column:  token.Column,
		}
	}

	token := p.peek()

	switch token.Type {
	case TokenLPAREN:
		return p.parseList(depth)
	case TokenQuote:
		return p.parseQuoted(depth)
	case TokenSymbol:
		return p.parseSymbol()
	case TokenString:
		return p.parseString()
	case TokenNumber:
		return p.parseNumber()
	default:
		p.advance()
		return nil, nil
	}
}

// parseList parses a list (function call or data structure)
func (p *Parser) parseList(depth int) (*ASTNode, error) {
	lparen := p.advance() // Consume (

	var children []*ASTNode
	for !p.isAtEnd() && p.peek().Type != TokenRPAREN {
		expr, err := p.parseExpression(depth + 1)
		if err != nil {
			return nil, err
		}
		if expr != nil {
			children = append(children, expr)
		}
	}

	if p.peek().Type == TokenRPAREN {
		p.advance() // Consume )
	} else {
		// EOF reached - unclosed parentheses
		// Log warning but continue
	}

	// Determine if this is a function call
	if len(children) > 0 && children[0].Type == "symbol" {
		return &ASTNode{
			Type:     "call",
			Value:    children[0].Value,
			Line:     lparen.Line,
			Column:   lparen.Column,
			Children: children[1:], // Arguments
		}, nil
	}

	return &ASTNode{
		Type:     "list",
		Value:    nil,
		Line:     lparen.Line,
		Column:   lparen.Column,
		Children: children,
	}, nil
}

// parseQuoted parses a quoted expression
func (p *Parser) parseQuoted(depth int) (*ASTNode, error) {
	quoteToken := p.advance() // Consume '

	expr, err := p.parseExpression(depth + 1)
	if err != nil {
		return nil, err
	}

	var children []*ASTNode
	if expr != nil {
		children = append(children, expr)
	}

	return &ASTNode{
		Type:     "quote",
		Value:    nil,
		Line:     quoteToken.Line,
		Column:   quoteToken.Column,
		Children: children,
	}, nil
}

// parseSymbol parses a symbol
func (p *Parser) parseSymbol() (*ASTNode, error) {
	token := p.advance()
	return &ASTNode{
		Type:   "symbol",
		Value:  token.Value,
		Line:   token.Line,
		Column: token.Column,
	}, nil
}

// parseString parses a string literal
func (p *Parser) parseString() (*ASTNode, error) {
	token := p.advance()
	return &ASTNode{
		Type:   "string",
		Value:  token.Value,
		Line:   token.Line,
		Column: token.Column,
	}, nil
}

// parseNumber parses a number
func (p *Parser) parseNumber() (*ASTNode, error) {
	token := p.advance()

	// Try to parse as int or float
	var value interface{}
	tokenStr := token.Value
	if len(tokenStr) > 0 {
		// Check if it's a float
		for _, c := range tokenStr {
			if c == '.' {
				f, err := strconv.ParseFloat(tokenStr, 64)
				if err == nil {
					value = f
				} else {
					value = tokenStr
				}
				break
			}
		}
		if value == nil {
			i, err := strconv.Atoi(tokenStr)
			if err == nil {
				value = i
			} else {
				value = tokenStr
			}
		}
	} else {
		value = tokenStr
	}

	return &ASTNode{
		Type:   "number",
		Value:  value,
		Line:   token.Line,
		Column: token.Column,
	}, nil
}

// peek returns the current token
func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		if len(p.tokens) > 0 {
			return p.tokens[len(p.tokens)-1] // Return EOF
		}
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

// advance advances and returns current token
func (p *Parser) advance() Token {
	token := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return token
}

// isAtEnd checks if at end of tokens
func (p *Parser) isAtEnd() bool {
	return p.pos >= len(p.tokens) || p.peek().Type == TokenEOF
}
