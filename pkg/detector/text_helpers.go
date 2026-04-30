package detector

import (
	"fmt"
	"strings"

	"github.com/evilcad/cadscanner/pkg/normalizer"
)

func lowerNodeArgumentsText(args []interface{}) string {
	var b strings.Builder
	appendLowerArgs(&b, args)
	return strings.TrimSpace(b.String())
}

func appendLowerArgs(b *strings.Builder, args []interface{}) {
	for _, arg := range args {
		appendLowerArgValue(b, arg)
	}
}

func appendLowerArgValue(b *strings.Builder, value interface{}) {
	switch v := value.(type) {
	case nil:
		return
	case string:
		if v == "" {
			return
		}
		b.WriteString(strings.ToLower(v))
		b.WriteByte(' ')
	case *normalizer.NormalizedNode:
		if v == nil {
			return
		}
		if v.FunctionName != "" {
			b.WriteString(strings.ToLower(v.FunctionName))
			b.WriteByte(' ')
		}
		appendLowerArgs(b, v.Arguments)
	default:
		text := strings.TrimSpace(fmt.Sprint(v))
		if text == "" {
			return
		}
		b.WriteString(strings.ToLower(text))
		b.WriteByte(' ')
	}
}
