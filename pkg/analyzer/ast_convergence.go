package analyzer

import (
	"strconv"
	"strings"

	"github.com/evilcad/cadscanner/pkg/parser"
)

const maxAdjacentDuplicateAST = 4
const maxTotalDuplicateAST = 16

func convergeASTNodes(nodes []*parser.ASTNode) []*parser.ASTNode {
	if len(nodes) <= 1 {
		return nodes
	}

	sigCache := make(map[*parser.ASTNode]string, len(nodes))
	converged := make([]*parser.ASTNode, 0, len(nodes))
	totalBySig := make(map[string]int, len(nodes)/8)

	lastSig := ""
	runCount := 0
	for _, node := range nodes {
		sig := astSignature(node, sigCache)
		if sig == lastSig {
			runCount++
		} else {
			lastSig = sig
			runCount = 1
		}
		if runCount > maxAdjacentDuplicateAST {
			continue
		}
		totalBySig[sig]++
		if totalBySig[sig] <= maxTotalDuplicateAST {
			converged = append(converged, node)
		}
	}

	return converged
}

func astSignature(node *parser.ASTNode, cache map[*parser.ASTNode]string) string {
	if node == nil {
		return "<nil>"
	}
	if sig, ok := cache[node]; ok {
		return sig
	}

	var b strings.Builder
	b.Grow(64)
	b.WriteString(node.Type)
	b.WriteByte('|')
	b.WriteString(astValueString(node.Value))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(len(node.Children)))
	for _, child := range node.Children {
		b.WriteByte('(')
		b.WriteString(child.Type)
		b.WriteByte('|')
		b.WriteString(astValueString(child.Value))
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(child.Children)))
		b.WriteByte(')')
	}

	sig := b.String()
	cache[node] = sig
	return sig
}

func astValueString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return "<nil>"
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return "<opaque>"
	}
}
