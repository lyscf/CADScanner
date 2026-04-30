package adapter

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/evilcad/cadscanner/pkg/debugutil"
)

// FASAdaptResult represents the result of FAS adaptation
type FASAdaptResult struct {
	Source       string
	Meta         map[string]interface{}
	UsedFallback bool
	ParseError   error
}

type FASDebugResources struct {
	Stream1Length int
	Stream2Length int
	Strings       []string
	Symbols       []string
	Resources     []FASResourceEntry
}

type FASResourceEntry struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// FASAdapter adapts FAS files to pseudo-LISP source
type FASAdapter struct{}

var adapterStartupPattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx|mnl)\b`)

const (
	streamSeparatorByte   = 0x24 // '$'
	maxFASAdaptSourceSize = 1024 * 1024
)

// NewFASAdapter creates a new FAS adapter
func NewFASAdapter() *FASAdapter {
	return &FASAdapter{}
}

func (a *FASAdapter) DebugResources(data []byte) (*FASDebugResources, error) {
	pos := bytes.Index(data, []byte("FAS4-FILE"))
	if pos == -1 {
		return nil, fmt.Errorf("invalid FAS4 signature")
	}
	data = data[pos:]
	stream1, stream2, _, err := a.parseFAS4Streams(data)
	if err != nil {
		return nil, err
	}
	resources, extractedStrings, symbols := a.extractOrderedResources(stream2)
	return &FASDebugResources{
		Stream1Length: len(stream1),
		Stream2Length: len(stream2),
		Strings:       extractedStrings,
		Symbols:       symbols,
		Resources:     resources,
	}, nil
}

// Adapt adapts FAS bytes to pseudo-LISP source
func (a *FASAdapter) Adapt(data []byte) (*FASAdaptResult, error) {
	totalStart := time.Now()
	// Check FAS4 signature - tolerate header text variants and leading noise.
	pos := bytes.Index(data, []byte("FAS4-FILE"))
	if pos == -1 {
		return nil, fmt.Errorf("invalid FAS4 signature")
	}

	// Find FAS4-FILE position and slice from there
	if pos >= 0 {
		// Slice from FAS4-FILE position
		data = data[pos:]
	}

	start := time.Now()
	stream1, stream2, _, err := a.parseFAS4Streams(data)
	parseTime := time.Since(start)
	if err != nil {
		// Fallback: try to extract resources from raw data
		start = time.Now()
		extractedStrings, symbols := a.extractRawResources(data)
		fallbackExtractTime := time.Since(start)
		start = time.Now()
		source := a.generatePseudoLisp(extractedStrings, symbols)
		pseudoTime := time.Since(start)
		start = time.Now()
		semanticSummary := a.collectSemanticIndicators(extractedStrings, symbols)
		summaryTime := time.Since(start)
		totalTime := time.Since(totalStart)
		if debugutil.TimingEnabled() && totalTime > 200*time.Millisecond {
			fmt.Fprintf(os.Stderr, "  [FAS-TIMING] total=%v parse=%v fallback_extract=%v pseudo=%v summary=%v disasm=0s topseudo=0s strings=%d symbols=%d fallback=true bytes=%d\n",
				totalTime, parseTime, fallbackExtractTime, pseudoTime, summaryTime, len(extractedStrings), len(symbols), len(data))
		}
		meta := map[string]interface{}{
			"resource_summary": semanticSummary,
			"parse_fallback":   true,
		}
		return &FASAdaptResult{
			Source:       source,
			Meta:         meta,
			UsedFallback: true,
			ParseError:   err,
		}, nil
	}

	// Extract strings and symbols from stream2
	start = time.Now()
	resources, extractedStrings, symbols := a.extractOrderedResources(stream2)
	resourceTime := time.Since(start)

	// Try to disassemble stream1 if available
	var disasmSource string
	var recoveredFunctions []map[string]interface{}
	var recoveredBindings []map[string]interface{}
	var recoveredBehaviors []map[string]interface{}
	disasmTime := time.Duration(0)
	toPseudoTime := time.Duration(0)
	if len(stream1) > 0 {
		// Disassemble (stream1 is already decrypted by parseFAS4Streams if needed)
		disassembler := NewDisassembler(stream1, symbols, extractedStrings)
		disassembler.SetResourcePool(resources)
		start = time.Now()
		_, err := disassembler.Disassemble()
		disasmTime = time.Since(start)
		if err == nil {
			start = time.Now()
			disasmSource = disassembler.ToCompactPseudoLisp()
			toPseudoTime = time.Since(start)
			for _, fn := range disassembler.Functions() {
				recoveredFunctions = append(recoveredFunctions, map[string]interface{}{
					"name":           fn.Name,
					"kind":           fn.Kind,
					"symbol_index":   fn.SymbolIndex,
					"start_offset":   fn.StartOffset,
					"end_offset":     fn.EndOffset,
					"num_args":       fn.NumOfArgs,
					"max_args":       fn.MaxArgs,
					"vars_count":     fn.VarsCount,
					"frame_size":     fn.FrameSize,
					"flags":          fn.Flags,
					"gc":             fn.GC,
					"is_lambda":      fn.IsLambda,
					"calls":          fn.Calls,
					"indirect_calls": fn.IndirectCalls,
					"block_starts":   fn.BlockStarts,
					"control_edges":  fn.ControlEdges,
				})
			}
			for _, binding := range disassembler.Bindings() {
				recoveredBindings = append(recoveredBindings, map[string]interface{}{
					"scope":  binding.Scope,
					"name":   binding.Name,
					"value":  binding.Value,
					"kind":   binding.Kind,
					"offset": binding.Offset,
				})
			}
			for _, behavior := range disassembler.Behaviors() {
				recoveredBehaviors = append(recoveredBehaviors, map[string]interface{}{
					"kind":      behavior.Kind,
					"category":  behavior.Category,
					"summary":   behavior.Summary,
					"functions": behavior.Functions,
					"evidence":  behavior.Evidence,
				})
			}
		}
	}

	// Generate pseudo-LISP source from extracted data
	start = time.Now()
	resourceSource := a.generatePseudoLisp(extractedStrings, symbols)
	resourcePseudoTime := time.Since(start)

	// Combine disassembly with resource-driven pseudo-LISP for better decompilation
	var source strings.Builder

	// If we have actual disassembly, use it as primary output
	if disasmSource != "" {
		source.WriteString(";; AutoCAD FAS4 Bytecode Decompilation\n")
		source.WriteString(";; Generated from disassembly + resource extraction\n\n")
		source.WriteString(disasmSource)
		source.WriteString("\n\n")
		// Append resource strings for IOC extraction
		source.WriteString(";; === Extracted Strings for IOC Analysis ===\n")
		source.WriteString(resourceSource)
	} else {
		// Fallback to resource-only output if disassembly failed
		source.WriteString(";; AutoCAD FAS4 Resource Extraction (Disassembly unavailable)\n")
		source.WriteString(resourceSource)
	}

	start = time.Now()
	semanticSummary := a.collectSemanticIndicators(extractedStrings, symbols)
	summaryTime := time.Since(start)
	meta := map[string]interface{}{
		"resource_summary": semanticSummary,
	}
	if len(recoveredFunctions) > 0 {
		meta["recovered_functions"] = recoveredFunctions
	}
	if len(recoveredBindings) > 0 {
		meta["recovered_bindings"] = recoveredBindings
	}
	if len(recoveredBehaviors) > 0 {
		meta["recovered_behaviors"] = recoveredBehaviors
	}
	totalTime := time.Since(totalStart)
	if debugutil.TimingEnabled() && (totalTime > 200*time.Millisecond || disasmTime > 200*time.Millisecond || toPseudoTime > 200*time.Millisecond) {
		fmt.Fprintf(os.Stderr, "  [FAS-TIMING] total=%v parse=%v resources=%v disasm=%v topseudo=%v pseudo=%v summary=%v strings=%d symbols=%d fallback=false bytes=%d\n",
			totalTime, parseTime, resourceTime, disasmTime, toPseudoTime, resourcePseudoTime, summaryTime,
			len(extractedStrings), len(symbols), len(data))
	}

	finalSource := source.String()
	sourceTruncated := false
	if len(finalSource) > maxFASAdaptSourceSize {
		finalSource = finalSource[:maxFASAdaptSourceSize] + "\n;; ... compact output truncated for performance\n"
		sourceTruncated = true
	}
	if sourceTruncated {
		meta["source_truncated"] = true
	}

	return &FASAdaptResult{
		Source:       finalSource,
		Meta:         meta,
		UsedFallback: disasmSource == "",
	}, nil
}

// parseFAS4Streams parses the two streams in a FAS4 file
func (a *FASAdapter) parseFAS4Streams(data []byte) ([]byte, []byte, []byte, error) {
	// Find FAS4-FILE marker
	fas4Pos := bytes.Index(data, []byte("FAS4-FILE"))
	if fas4Pos == -1 {
		return nil, nil, nil, fmt.Errorf("FAS4-FILE marker not found")
	}

	// Find CRLF after FAS4-FILE header
	pos := bytes.Index(data[fas4Pos:], []byte("\r\n"))
	if pos == -1 {
		return nil, nil, nil, fmt.Errorf("no CRLF after FAS4-FILE header")
	}
	pos += fas4Pos + 2 // Skip CRLF after header line

	// Parse Stream 1: FunctionStream
	// Skip whitespace
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}

	// Read stream1_length (text number)
	stream1Length, nextPos, ok := readDecimalAt(data, pos)
	if !ok {
		return nil, nil, nil, fmt.Errorf("could not read stream1 length")
	}
	pos = nextPos

	// Read stream1_vars (text number before '$')
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}
	_, pos, _ = readDecimalAt(data, pos)

	// Skip to '$'
	for pos < len(data) && data[pos] != '$' {
		pos++
	}
	if pos >= len(data) {
		return nil, nil, nil, fmt.Errorf("no $ for stream1")
	}
	pos++ // skip '$'

	// Read stream1 data
	if pos+stream1Length > len(data) {
		return nil, nil, nil, fmt.Errorf("stream1 data exceeds file size")
	}
	stream1DataRaw := data[pos : pos+stream1Length]
	pos += stream1Length

	// Read keylength byte
	if pos >= len(data) {
		return nil, nil, nil, fmt.Errorf("unexpected EOF after stream1")
	}
	keylength1 := data[pos]
	pos++

	// Check if stream1 is encrypted
	var stream1Data []byte
	var key1 []byte
	if keylength1 == streamSeparatorByte {
		// Not encrypted (keylength byte IS '$')
		stream1Data = stream1DataRaw
	} else {
		// Encrypted: read key
		if pos+int(keylength1) > len(data) {
			return nil, nil, nil, fmt.Errorf("stream1 key exceeds file size")
		}
		key1 = data[pos : pos+int(keylength1)]
		pos += int(keylength1)
		// Skip trailing '$'
		if pos < len(data) && data[pos] == streamSeparatorByte {
			pos++
		}
		// Decrypt stream1
		stream1Data = DecryptStream(stream1DataRaw, key1)
	}

	// Check for stream2
	if pos >= len(data) {
		return stream1Data, nil, key1, nil
	}

	// Skip CRLF before stream2
	if data[pos] == '\r' && pos+1 < len(data) && data[pos+1] == '\n' {
		pos += 2
	}

	// Parse Stream 2: ResourceStream
	// Skip CRLF and whitespace
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}

	// Read stream2_length (text number)
	stream2Length, nextPos, ok := readDecimalAt(data, pos)
	if !ok {
		return stream1Data, nil, key1, fmt.Errorf("could not read stream2 length")
	}
	pos = nextPos

	// Read stream2_vars (text number before '$')
	for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r' || data[pos] == '\n') {
		pos++
	}
	_, pos, _ = readDecimalAt(data, pos)

	// Skip to '$'
	for pos < len(data) && data[pos] != '$' {
		pos++
	}
	if pos >= len(data) {
		return stream1Data, nil, key1, fmt.Errorf("no $ for stream2")
	}
	pos++ // skip '$'

	// Read stream2 data
	if pos+stream2Length > len(data) {
		return stream1Data, nil, key1, fmt.Errorf("stream2 data exceeds file size")
	}
	stream2DataRaw := data[pos : pos+stream2Length]
	pos += stream2Length

	// Read keylength byte
	if pos >= len(data) {
		return stream1Data, stream2DataRaw, key1, nil
	}
	keylength2 := data[pos]
	pos++

	// Check if stream2 is encrypted
	var stream2Data []byte
	if keylength2 == streamSeparatorByte {
		// Not encrypted (keylength byte IS '$')
		stream2Data = stream2DataRaw
	} else {
		// Encrypted: read key
		if pos+int(keylength2) > len(data) {
			return stream1Data, stream2DataRaw, key1, fmt.Errorf("stream2 key exceeds file size")
		}
		key2 := data[pos : pos+int(keylength2)]
		pos += int(keylength2)
		// Skip trailing '$'
		if pos < len(data) && data[pos] == streamSeparatorByte {
			pos++
		}
		// Decrypt stream2
		stream2Data = DecryptStream(stream2DataRaw, key2)
	}

	return stream1Data, stream2Data, key1, nil
}

func readDecimalAt(data []byte, pos int) (int, int, bool) {
	start := pos
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	if pos == start {
		return 0, start, false
	}
	value, err := strconv.Atoi(string(data[start:pos]))
	if err != nil {
		return 0, start, false
	}
	return value, pos, true
}

// extractResources extracts strings and symbols from resource stream
func (a *FASAdapter) extractResources(stream2 []byte) ([]string, []string) {
	_, stringList, symbols := a.extractOrderedResources(stream2)
	return stringList, symbols
}

func (a *FASAdapter) extractOrderedResources(stream2 []byte) ([]FASResourceEntry, []string, []string) {
	resources := []FASResourceEntry{}
	stringList := []string{}
	symbols := []string{}

	if len(stream2) < 4 {
		return resources, stringList, symbols
	}

	// Skip header (4 bytes)
	pos := 4

	for pos < len(stream2) {
		// Find null-terminated string
		nullPos := bytes.IndexByte(stream2[pos:], 0)
		if nullPos == -1 {
			break
		}

		chunk := string(stream2[pos : pos+nullPos])
		if chunk != "" {
			parts := a.splitResourceChunk(chunk)
			for _, str := range parts {
				if len(str) >= 2 {
					// Determine if it's a symbol or string literal
					if a.isSymbol(str) {
						resources = append(resources, FASResourceEntry{Index: len(resources), Kind: "symbol", Value: str})
						symbols = append(symbols, str)
					} else {
						resources = append(resources, FASResourceEntry{Index: len(resources), Kind: "string", Value: str})
						stringList = append(stringList, str)
					}
				}
			}
		}

		pos += nullPos + 1
	}

	return resources, stringList, symbols
}

func (a *FASAdapter) splitResourceChunk(chunk string) []string {
	if chunk == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(chunk); i++ {
		if chunk[i] != '[' || i == start {
			continue
		}
		end := len(chunk)
		if next := strings.IndexByte(chunk[i+1:], '['); next >= 0 {
			end = i + 1 + next
		}
		if !looksLikeBracketResourceBoundary(chunk[i:end]) {
			continue
		}
		if part := chunk[start:i]; part != "" {
			parts = append(parts, part)
		}
		start = i
	}
	if tail := chunk[start:]; tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func looksLikeBracketResourceBoundary(token string) bool {
	if !strings.HasPrefix(token, "[") || len(token) < 2 {
		return false
	}
	if strings.ContainsAny(token, " \t\r\n/\\") {
		return false
	}
	inner := strings.TrimPrefix(token, "[")
	inner = strings.TrimSuffix(inner, "]")
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return false
	}
	for _, r := range inner {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '_', ':', '+', '*', '<', '>', '=', '?', '$', '!', '.', '-', '&':
			continue
		default:
			return false
		}
	}
	return true
}

// extractRawResources extracts resources from raw FAS data as fallback
func (a *FASAdapter) extractRawResources(data []byte) ([]string, []string) {
	var strings []string
	var symbols []string

	// Simple string extraction: look for sequences of printable ASCII characters
	// This is a fallback when stream parsing fails
	for i := 0; i < len(data)-4; i++ {
		if data[i] >= 32 && data[i] <= 126 { // Printable ASCII
			start := i
			length := 0
			for i < len(data) && data[i] >= 32 && data[i] <= 126 && length < 256 {
				length++
				i++
			}
			if length >= 4 {
				strings = append(strings, string(data[start:start+length]))
			}
		}
	}

	return strings, symbols
}

// isSymbol checks if a string is a valid LISP symbol
func (a *FASAdapter) isSymbol(s string) bool {
	if s == "" {
		return false
	}

	// Check if all characters are valid for symbols
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '_', ':', '+', '*', '<', '>', '=', '/', '?', '$', '!', '.', '-':
			continue
		default:
			return false
		}
	}

	// Heuristic: ALL_CAPS_WITH_UNDERSCORES are likely string constants, not symbols
	// Examples: END_PLATE, TOP_RAIL, ACAD_MLINESTYLE
	if strings.Contains(s, "_") {
		allUpper := true
		for _, c := range s {
			if c >= 'a' && c <= 'z' {
				allUpper = false
				break
			}
		}
		if allUpper {
			// This looks like a string constant
			return false
		}
	}

	// Known AutoLISP function/symbol patterns
	lower := strings.ToLower(s)

	// VL-*, VLA-*, VLAX-*, VLR-* are definitely symbols
	if strings.HasPrefix(lower, "vl-") || strings.HasPrefix(lower, "vla-") ||
		strings.HasPrefix(lower, "vlax-") || strings.HasPrefix(lower, "vlr-") {
		return true
	}

	// Known AutoLISP functions are symbols
	knownFuncs := map[string]bool{
		"entget": true, "entsel": true, "entmod": true, "entmake": true,
		"ssget": true, "ssname": true, "sslength": true, "ssadd": true,
		"command": true, "getvar": true, "setvar": true, "getenv": true,
		"findfile": true, "load": true, "princ": true, "print": true,
		"strcat": true, "strcase": true, "substr": true, "strlen": true,
		"getpoint": true, "getdist": true, "getangle": true, "getstring": true,
		"polar": true, "distance": true, "angle": true, "inters": true,
		"tblsearch": true, "tblnext": true, "dictsearch": true, "dictadd": true,
		"namedobjdict": true, "acad_strlsort": true, "acad_colordlg": true,
		"car": true, "cdr": true, "cons": true, "list": true, "append": true,
		"assoc": true, "reverse": true, "mapcar": true, "apply": true,
	}
	if knownFuncs[lower] {
		return true
	}

	// Default: if it has lowercase letters or special LISP chars, it's likely a symbol
	// If it's all uppercase without underscores, could be either (default to symbol for compatibility)
	return true
}

// generatePseudoLisp generates executable pseudo-LISP code from extracted data
func (a *FASAdapter) generatePseudoLisp(stringList []string, symbols []string) string {
	var buf strings.Builder

	buf.WriteString(";; Conservative resource extraction from FAS file\n")
	buf.WriteString(";; Resource strings are preserved for IOC/reference only.\n")
	buf.WriteString("(defun fas::entry () (princ))\n")
	buf.WriteString("(fas::entry)\n")

	cleanedStrings := make([]string, 0, len(stringList))
	for _, s := range stringList {
		clean := a.sanitizeExtractedString(s)
		if clean != "" && len(clean) >= 4 {
			cleanedStrings = append(cleanedStrings, clean)
		}
	}

	if len(symbols) > 0 {
		buf.WriteString(";; extracted_symbols_begin\n")
		for i, sym := range symbols {
			if i >= 300 {
				break
			}
			sym = a.sanitizeExtractedString(sym)
			if sym == "" {
				continue
			}
			buf.WriteString(fmt.Sprintf(";; sym: %s\n", a.escapeString(sym)))
		}
		buf.WriteString(";; extracted_symbols_end\n")
	}

	buf.WriteString(";; extracted_strings_begin\n")
	for i, s := range cleanedStrings {
		if i >= 600 {
			break
		}
		buf.WriteString(fmt.Sprintf(";; str: %s\n", a.escapeString(s)))
	}
	buf.WriteString(";; extracted_strings_end\n")

	return buf.String()
}

// collectSemanticIndicators collects conservative resource summaries from extracted data.
func (a *FASAdapter) collectSemanticIndicators(stringList []string, symbols []string) map[string]interface{} {
	urls := []string{}
	comObjects := []string{}
	commands := []string{}
	regKeys := []string{}
	filePaths := []string{}

	for _, s := range stringList {
		s = a.sanitizeExtractedString(s)
		if s == "" {
			continue
		}
		if a.isURL(s) {
			urls = append(urls, s)
		}
		if a.isCOMObject(s) {
			comObjects = append(comObjects, s)
		}
		if a.isCommand(s) {
			commands = append(commands, s)
		}
		if a.isRegistryKey(s) {
			regKeys = append(regKeys, s)
		}
		if a.isFilePath(s) {
			filePaths = append(filePaths, s)
		}
	}
	for _, sym := range symbols {
		sym = a.sanitizeExtractedString(sym)
		if sym == "" {
			continue
		}
		if a.isCOMObject(sym) {
			comObjects = append(comObjects, sym)
		}
		if a.isCommand(sym) {
			commands = append(commands, sym)
		}
		if a.isFilePath(sym) || a.isStartupArtifact(sym) {
			filePaths = append(filePaths, sym)
		}
	}

	summary := a.analyzeBehavior(stringList, symbols)
	summary["urls"] = urls
	summary["com_objects"] = comObjects
	summary["commands"] = commands
	summary["registry_keys"] = regKeys
	summary["file_paths"] = filePaths
	summary["string_count"] = len(stringList)
	summary["symbol_count"] = len(symbols)
	return summary
}

// Helper functions for semantic detection
func (a *FASAdapter) isURL(s string) bool {
	urlRegex := regexp.MustCompile(`(?i)^https?://[^\s"']+`)
	return urlRegex.MatchString(s)
}

func (a *FASAdapter) isRegistryKey(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "hkey_") && strings.Count(s, "\\") >= 1
}

func (a *FASAdapter) isFilePath(s string) bool {
	pathRegex := regexp.MustCompile(`(?i)\.(lsp|fas|vlx|mnl|dcl|scr|dll|ocx|exe)\b`)
	return pathRegex.MatchString(s)
}

func (a *FASAdapter) isStartupArtifact(s string) bool {
	lower := strings.ToLower(a.sanitizeExtractedString(s))
	return strings.Contains(lower, "acaddoc") ||
		strings.Contains(lower, "startup") ||
		adapterStartupPattern.MatchString(lower)
}

func (a *FASAdapter) sanitizeExtractedString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	return s
}

func (a *FASAdapter) isCOMObject(s string) bool {
	comKeywords := []string{"wscript.shell", "shell.application", "xmlhttp", "msxml",
		"adodb.stream", "scripting.filesystemobject", "scriptlet", "wbemscripting", "winhttp"}
	lower := strings.ToLower(s)
	for _, kw := range comKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (a *FASAdapter) isCommand(s string) bool {
	cmdKeywords := []string{"cmd.exe", "rundll32", "regsvr32", "powershell", "wscript.exe", "attrib "}
	lower := strings.ToLower(s)
	for _, kw := range cmdKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (a *FASAdapter) escapeString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// analyzeBehavior returns a conservative IOC-oriented resource summary.
// It intentionally avoids adapter-side behavioral conclusions or ATT&CK/TTP
// assertions so the main pipeline can rely on recovered structure instead.
func (a *FASAdapter) analyzeBehavior(strList []string, symbols []string) map[string]interface{} {
	evidence := make(map[string]interface{})

	// IOC extraction
	filenames := []string{}
	reactors := []string{}
	paths := []string{}
	urls := []string{}
	registryKeys := []string{}
	comObjects := []string{}
	cmdStrings := []string{}

	for _, s := range strList {
		sLower := strings.ToLower(s)
		// Filenames
		if strings.Contains(sLower, ".") && !strings.HasPrefix(s, "[") && len(s) > 3 {
			filenames = append(filenames, s)
		}
		// Reactors
		if strings.HasPrefix(s, "[S::") || strings.HasPrefix(s, "[VLR") {
			reactors = append(reactors, s)
		}
		// Paths
		if strings.Contains(s, "\\") || strings.Contains(s, "/") {
			paths = append(paths, s)
		}
		// URLs
		if strings.HasPrefix(s, "http") {
			urls = append(urls, s)
		}
		// Registry keys
		if strings.Contains(strings.ToUpper(s), "HKEY_") && strings.Count(s, "\\") >= 1 {
			registryKeys = append(registryKeys, s)
		}
		// COM objects
		comKeywords := []string{"wscript", "scripting.", "microsoft.xml", "msxml", "adodb",
			"scriptlet", "wbemscripting", "shell.application"}
		for _, kw := range comKeywords {
			if strings.Contains(sLower, kw) {
				comObjects = append(comObjects, s)
				break
			}
		}
		// Command strings
		cmdKeywords := []string{"cmd.exe", "rundll32", "regsvr32", "wscript.exe", "powershell",
			"mshta", "certutil", "bitsadmin"}
		for _, kw := range cmdKeywords {
			if strings.Contains(sLower, kw) {
				cmdStrings = append(cmdStrings, s)
				break
			}
		}
	}

	evidence["filenames"] = filenames
	evidence["reactors"] = reactors
	evidence["paths"] = paths
	evidence["urls"] = urls
	evidence["registry_keys"] = registryKeys
	evidence["com_objects"] = comObjects
	evidence["cmd_strings"] = cmdStrings
	evidence["summary_mode"] = "conservative_resource_only"

	return evidence
}
