package parser

import (
	"strings"
	"unicode"
)

// TokenType represents the type of token
type TokenType int

const (
	TokenLPAREN TokenType = iota
	TokenRPAREN
	TokenSymbol
	TokenString
	TokenNumber
	TokenQuote
	TokenComment
	TokenEOF
)

// String returns the string representation of the token type
func (t TokenType) String() string {
	switch t {
	case TokenLPAREN:
		return "LPAREN"
	case TokenRPAREN:
		return "RPAREN"
	case TokenSymbol:
		return "SYMBOL"
	case TokenString:
		return "STRING"
	case TokenNumber:
		return "NUMBER"
	case TokenQuote:
		return "QUOTE"
	case TokenComment:
		return "COMMENT"
	case TokenEOF:
		return "EOF"
	default:
		return "UNKNOWN"
	}
}

// Token represents a lexical token
type Token struct {
	Type   TokenType
	Value  string
	Line   int
	Column int
}

// Tokenizer tokenizes AutoLISP source code
type Tokenizer struct {
	source string
	pos    int
	line   int
	column int
	tokens []Token
}

// NewTokenizer creates a new tokenizer
func NewTokenizer(source string) *Tokenizer {
	return &Tokenizer{
		source: source,
		pos:    0,
		line:   1,
		column: 1,
		tokens: make([]Token, 0),
	}
}

// Tokenize tokenizes the entire source
func (t *Tokenizer) Tokenize() ([]Token, error) {
	for t.pos < len(t.source) {
		t.skipWhitespace()

		if t.pos >= len(t.source) {
			break
		}

		currentChar := t.peek()

		// Comments
		if currentChar == ';' {
			t.readComment()
			continue
		}

		// Parentheses
		if currentChar == '(' {
			t.addToken(TokenLPAREN, "(")
			t.advance()
			continue
		}

		if currentChar == ')' {
			t.addToken(TokenRPAREN, ")")
			t.advance()
			continue
		}

		// Quote
		if currentChar == '\'' {
			t.addToken(TokenQuote, "'")
			t.advance()
			continue
		}

		// String literals
		if currentChar == '"' {
			t.readString()
			continue
		}

		// Numbers or symbols
		if unicode.IsDigit(rune(currentChar)) || (currentChar == '-' && t.peekNextIsDigit()) {
			t.readNumber()
		} else {
			t.readSymbol()
		}
	}

	t.addToken(TokenEOF, "")
	return t.tokens, nil
}

// peek returns the current character
func (t *Tokenizer) peek() byte {
	if t.pos >= len(t.source) {
		return 0
	}
	return t.source[t.pos]
}

// peekNext returns the next character
func (t *Tokenizer) peekNext() byte {
	if t.pos+1 >= len(t.source) {
		return 0
	}
	return t.source[t.pos+1]
}

// peekNextIsDigit checks if the next character is a digit
func (t *Tokenizer) peekNextIsDigit() bool {
	next := t.peekNext()
	return unicode.IsDigit(rune(next))
}

// advance advances position and returns current character
func (t *Tokenizer) advance() byte {
	if t.pos >= len(t.source) {
		return 0
	}

	char := t.source[t.pos]
	t.pos++

	if char == '\n' {
		t.line++
		t.column = 1
	} else {
		t.column++
	}

	return char
}

// skipWhitespace skips whitespace characters
func (t *Tokenizer) skipWhitespace() {
	for t.pos < len(t.source) {
		c := t.source[t.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if c == '\n' {
				t.line++
				t.column = 1
			} else {
				t.column++
			}
			t.pos++
		} else {
			break
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readComment reads a comment (from ; to end of line)
func (t *Tokenizer) readComment() {
	startCol := t.column
	start := t.pos
	for t.peek() != '\n' && t.peek() != 0 {
		t.advance()
	}
	t.addToken(TokenComment, t.source[start:t.pos], startCol)
}

// readString reads a string literal
func (t *Tokenizer) readString() {
	startCol := t.column
	t.advance() // Skip opening "

	var parts []string
	start := t.pos

	for t.pos < len(t.source) {
		c := t.source[t.pos]
		if c == '"' {
			parts = append(parts, t.source[start:t.pos])
			t.advance() // consume closing "
			t.addToken(TokenString, strings.Join(parts, ""), startCol)
			return
		} else if c == '\\' {
			parts = append(parts, t.source[start:t.pos])
			t.advance() // consume backslash
			escapeChar := t.advance()
			switch escapeChar {
			case 'n':
				parts = append(parts, "\n")
			case 't':
				parts = append(parts, "\t")
			case '\\':
				parts = append(parts, "\\")
			case '"':
				parts = append(parts, "\"")
			default:
				parts = append(parts, string(escapeChar))
			}
			start = t.pos
		} else if c == '\n' {
			t.pos++
			t.line++
			t.column = 1
		} else {
			t.pos++
			t.column++
		}
	}

	// Unterminated string
	parts = append(parts, t.source[start:t.pos])
	t.addToken(TokenString, strings.Join(parts, ""), startCol)
}

// readNumber reads a number (integer or float)
func (t *Tokenizer) readNumber() {
	startCol := t.column
	start := t.pos
	if t.peek() == '-' {
		t.advance()
	}

	for unicode.IsDigit(rune(t.peek())) || t.peek() == '.' {
		t.advance()
	}

	t.addToken(TokenNumber, t.source[start:t.pos], startCol)
}

// readSymbol reads a symbol (function name, variable, etc.)
func (t *Tokenizer) readSymbol() {
	startCol := t.column
	start := t.pos
	for t.pos < len(t.source) {
		c := t.source[t.pos]
		if isSymbolDelimiter(c) {
			break
		}
		t.pos++
		t.column++
	}
	if t.pos > start {
		t.addToken(TokenSymbol, t.source[start:t.pos], startCol)
		return
	}
	// Shouldn't happen, but advance one char to avoid infinite loop
	t.advance()
}

func isSymbolDelimiter(c byte) bool {
	switch c {
	case '(', ')', ' ', '\t', '\n', '\r', '"', ';', 0:
		return true
	default:
		return false
	}
}

// addToken adds a token to the list
func (t *Tokenizer) addToken(tokenType TokenType, value string, column ...int) {
	col := t.column
	if len(column) > 0 {
		col = column[0]
	}

	token := Token{
		Type:   tokenType,
		Value:  value,
		Line:   t.line,
		Column: col,
	}
	t.tokens = append(t.tokens, token)
}
