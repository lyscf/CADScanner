package analyzer

import "strings"

const maxAdjacentDuplicateSourceLines = 4
const maxTotalDuplicateSourceLines = 16

func convergeSource(source string) string {
	if source == "" {
		return source
	}

	var out strings.Builder
	out.Grow(len(source))

	lastNonEmpty := ""
	runCount := 0
	wroteAny := false
	totalByLine := make(map[string]int)

	for lineStart := 0; lineStart < len(source); {
		lineEnd := lineStart
		for lineEnd < len(source) && source[lineEnd] != '\n' {
			lineEnd++
		}

		rawEnd := lineEnd
		if rawEnd > lineStart && source[rawEnd-1] == '\r' {
			rawEnd--
		}

		trimmedStart, trimmedEnd := trimSourceLine(source, lineStart, rawEnd)
		if trimmedStart != trimmedEnd {
			trimmed := source[trimmedStart:trimmedEnd]
			if trimmed == lastNonEmpty {
				runCount++
			} else {
				lastNonEmpty = trimmed
				runCount = 1
			}

			if runCount <= maxAdjacentDuplicateSourceLines {
				totalByLine[trimmed]++
			}
			if runCount <= maxAdjacentDuplicateSourceLines && totalByLine[trimmed] <= maxTotalDuplicateSourceLines {
				if wroteAny {
					out.WriteByte('\n')
				}
				out.WriteString(source[lineStart:rawEnd])
				wroteAny = true
			}
		}

		lineStart = lineEnd + 1
	}

	return out.String()
}

func trimSourceLine(source string, start, end int) (int, int) {
	for start < end && isSourceSpace(source[start]) {
		start++
	}
	for start < end && isSourceSpace(source[end-1]) {
		end--
	}
	return start, end
}

func isSourceSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}
