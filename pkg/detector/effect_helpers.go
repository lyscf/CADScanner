package detector

import (
	"strings"

	"github.com/evilcad/cadscanner/pkg/ir"
)

type loweredEffect struct {
	target string
	source string
	text   string
}

func lowerEffect(effect ir.IREffect) loweredEffect {
	target := strings.ToLower(effect.Target)
	source := strings.ToLower(effect.Source)
	return loweredEffect{
		target: target,
		source: source,
		text:   target + " " + source,
	}
}

func cleanLowerEffectText(effect ir.IREffect) string {
	return strings.TrimRight(strings.ToLower(effect.Target+" "+effect.Source), "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")
}
