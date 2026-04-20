package detector

import (
	"fmt"
	"strings"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/normalizer"
)

// Detector detects malicious patterns
type Detector struct {
	config        *config.Config
	attackMapper  *AttackMapper
	advancedRules *AdvancedRulesRegistry
}

type EvidenceContext struct {
	Source  string
	FASMeta map[string]interface{}
	VLXMeta map[string]interface{}
}

// DetectResult represents the detection result
type DetectResult struct {
	MatchedRules []MatchedRule
	AttackResult *AttackResult
	AttackRisk   float64
}

// MatchedRule represents a matched detection rule
type MatchedRule struct {
	ID       string
	Name     string
	Severity float64
}

// AttackResult represents ATT&CK mapping result
type AttackResult struct {
	Techniques []AttackTechnique
	Evidence   []map[string]interface{}
}

// AttackTechnique represents an ATT&CK technique
type AttackTechnique struct {
	ID         string
	Name       string
	Confidence float64
}

// New creates a new detector
func New(cfg *config.Config) *Detector {
	return &Detector{
		config:        cfg,
		attackMapper:  NewAttackMapper(),
		advancedRules: NewAdvancedRulesRegistry(),
	}
}

const (
	maxSourceEvidenceBytes = 64 * 1024
	maxMetaEvidenceItems   = 256
)

// Detect detects malicious patterns in the IR.
func (d *Detector) Detect(irResult *ir.IRResult, normalized []*normalizer.NormalizedNode, evidence *EvidenceContext) (*DetectResult, error) {
	result := &DetectResult{
		MatchedRules: make([]MatchedRule, 0),
		AttackResult: &AttackResult{
			Techniques: make([]AttackTechnique, 0),
		},
		AttackRisk: 0.0,
	}

	if !d.config.Detection.EnableRules {
		return result, nil
	}

	// Use AttackMapper for comprehensive ATT&CK mapping (controlled by EnableATTACK)
	if d.config.Detection.EnableATTACK {
		attackResult, attackRisk := d.attackMapper.Analyze(irResult.Effects, normalized)
		result.AttackResult = attackResult
		result.AttackRisk = attackRisk
	}

	// Evaluate advanced rules
	matchedAdvancedRules := d.advancedRules.Evaluate(irResult.Effects)
	for _, rule := range matchedAdvancedRules {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       rule.GetID(),
			Name:     rule.GetName(),
			Severity: rule.GetSeverity(),
		})
	}

	// Startup-hook heuristics need normalized AST context, not just IR effects.
	recoveredText := buildRecoveredEvidenceText(normalized, evidence)

	if hasStartupHook(normalized) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "STARTUP_HOOK_001",
			Name:     "AutoCAD Startup Hook",
			Severity: 0.94,
		})
	}
	if hasEmbeddedStartupCopy(normalized) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "STARTUP_COPY_STR_001",
			Name:     "Embedded Startup Copy String",
			Severity: 0.90,
		})
	}
	if hasBootDatStartupChain(normalized) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "BOOTDAT_CHAIN_001",
			Name:     "Boot.dat Startup Chain",
			Severity: 0.88,
		})
	}
	if hasStartupRewriteInfector(recoveredText) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "STARTUP_REWRITE_001",
			Name:     "Startup Rewrite Infector",
			Severity: 0.96,
		})
	}
	if hasRecoveredExfilStub(recoveredText) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "EXFIL_STUB_001",
			Name:     "Recovered Exfiltration Stub",
			Severity: 0.95,
		})
	}
	if hasRecoveredDestructiveStub(recoveredText) {
		result.MatchedRules = append(result.MatchedRules, MatchedRule{
			ID:       "DESTRUCT_STUB_001",
			Name:     "Recovered Destructive Stub",
			Severity: 0.94,
		})
	}

	// Check for high-confidence malicious patterns only
	// Advanced rules already handle specific patterns (worm-like, dropper, etc.)
	// Only add generic rules for effects with clear malicious indicators
	for _, effect := range irResult.Effects {
		// Registry writes should only score as malicious for persistence /
		// execution-sensitive keys, not ordinary application settings.
		if effect.EffectType == ir.REGISTRY_MODIFY && IsSuspiciousRegistryPath(effect.Target) {
			result.MatchedRules = append(result.MatchedRules, MatchedRule{
				ID:       "REGISTRY_001",
				Name:     "Registry Modification",
				Severity: 0.9,
			})
		}

		// Process creation should match only when the command itself is high risk.
		if effect.EffectType == ir.PROCESS_CREATE {
			if IsSuspiciousProcessCommand(effect.Target) {
				result.MatchedRules = append(result.MatchedRules, MatchedRule{
					ID:       "CMD_EXEC_001",
					Name:     "Command Execution",
					Severity: 0.85,
				})
			}
		}
	}

	return result, nil
}

func hasStartupHook(normalized []*normalizer.NormalizedNode) bool {
	for _, node := range normalized {
		if node == nil {
			continue
		}
		fn := strings.ToLower(node.FunctionName)
		argsText := lowerNodeArgumentsText(node.Arguments)
		if node.Operation == normalizer.DEFUN && len(node.Arguments) > 0 {
			if name, ok := node.Arguments[0].(string); ok {
				nameLower := strings.ToLower(name)
				if strings.Contains(nameLower, "s::startup") || strings.Contains(nameLower, "startup") {
					return true
				}
			}
		}
		if (strings.Contains(fn, "vlr-") || strings.Contains(fn, "reactor")) &&
			(strings.Contains(argsText, "s::startup") ||
				strings.Contains(argsText, "acaddoc") ||
				strings.Contains(argsText, "acad.lsp") ||
				strings.Contains(argsText, "acadlspasdoc")) {
			return true
		}
		if fn == "setvar" && strings.Contains(argsText, "acadlspasdoc") {
			return true
		}
	}
	return false
}

func hasEmbeddedStartupCopy(normalized []*normalizer.NormalizedNode) bool {
	for _, node := range normalized {
		if node == nil {
			continue
		}
		fn := strings.ToLower(node.FunctionName)
		argsText := lowerNodeArgumentsText(node.Arguments)
		text := fn + " " + argsText

		if !strings.Contains(text, "vl-file-copy") || !strings.Contains(text, "findfile") {
			continue
		}
		if strings.Contains(text, "acad.vlx") ||
			strings.Contains(text, "acad.mnl") ||
			strings.Contains(text, "acad.lsp") ||
			strings.Contains(text, "acaddoc") ||
			strings.Contains(text, "ai_utils.lsp") {
			return true
		}
	}
	return false
}

func hasBootDatStartupChain(normalized []*normalizer.NormalizedNode) bool {
	hasBootDat := false
	hasVBARun := false
	hasStartupRef := false

	for _, node := range normalized {
		if node == nil {
			continue
		}
		fn := strings.ToLower(node.FunctionName)
		argsText := lowerNodeArgumentsText(node.Arguments)
		text := fn + " " + argsText

		if strings.Contains(text, "boot.dat") {
			hasBootDat = true
		}
		if strings.Contains(text, "_-vbarun") || strings.Contains(text, "vbarun") {
			hasVBARun = true
		}
		if strings.Contains(text, "acaddoc") ||
			strings.Contains(text, "base.dcl") ||
			strings.Contains(text, "cadhelp.jpg") ||
			strings.Contains(text, "acad.bak") ||
			strings.Contains(text, "beifen.bak") {
			hasStartupRef = true
		}
	}

	return hasBootDat && (hasVBARun || hasStartupRef)
}

func hasStartupRewriteInfector(combined string) bool {
	if combined == "" {
		return false
	}

	hasStartupArtifact := strings.Contains(combined, "acad.lsp") ||
		strings.Contains(combined, "acaddoc.lsp") ||
		strings.Contains(combined, "acadisa.lin")
	if !hasStartupArtifact {
		return false
	}

	hasRewriteFlow := strings.Contains(combined, "open") &&
		strings.Contains(combined, "read-line") &&
		strings.Contains(combined, "write-line")
	if !hasRewriteFlow {
		return false
	}

	return strings.Contains(combined, "writeapp") ||
		(strings.Contains(combined, "findfile") &&
			strings.Contains(combined, "acad.lsp") &&
			strings.Contains(combined, "acadisa.lin"))
}

func hasRecoveredExfilStub(combined string) bool {
	if combined == "" {
		return false
	}
	if strings.Contains(combined, "bashupload.com") {
		return true
	}
	hasWinHTTP := strings.Contains(combined, "winhttp.winhttprequest.5.1")
	hasADODB := strings.Contains(combined, "adodb.stream")
	hasPost := strings.Contains(combined, "post") || strings.Contains(combined, "application/octet-stream")
	return hasWinHTTP && hasADODB && hasPost
}

func hasRecoveredDestructiveStub(combined string) bool {
	if combined == "" {
		return false
	}
	hasDeletePrimitive := strings.Contains(combined, "vl-file-delete") ||
		strings.Contains(combined, "vla-delete")
	if !hasDeletePrimitive {
		return false
	}
	hasSelectionLogic := strings.Contains(combined, "*nuclear*") ||
		strings.Contains(combined, "*reactor*") ||
		strings.Contains(combined, "*power*") ||
		(strings.Contains(combined, "wcmatch") && strings.Contains(combined, "dwgname"))
	hasModelMutation := strings.Contains(combined, "vla-get-modelspace") ||
		strings.Contains(combined, "vla-get-layers") ||
		strings.Contains(combined, "objectname")
	return hasSelectionLogic && hasModelMutation
}

func buildRecoveredEvidenceText(normalized []*normalizer.NormalizedNode, evidence *EvidenceContext) string {
	text := normalizedText(normalized)
	metaText := metadataEvidenceText(evidence)
	switch {
	case text == "" && metaText == "":
		return compactLowerSource(evidence)
	case metaText == "":
		sourceText := compactLowerSource(evidence)
		if sourceText == "" {
			return text
		}
		return text + " " + sourceText
	case text == "":
		return metaText
	default:
		return text + " " + metaText
	}
}

func metadataEvidenceText(evidence *EvidenceContext) string {
	if evidence == nil {
		return ""
	}
	parts := make([]string, 0, 64)
	appendMetaEvidence(&parts, evidence.FASMeta, "")
	appendMetaEvidence(&parts, evidence.VLXMeta, "")
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func appendMetaEvidence(parts *[]string, value interface{}, key string) {
	if value == nil || len(*parts) >= maxMetaEvidenceItems {
		return
	}

	switch v := value.(type) {
	case map[string]interface{}:
		for k, nested := range v {
			appendMetaEvidence(parts, nested, strings.ToLower(k))
			if len(*parts) >= maxMetaEvidenceItems {
				return
			}
		}
	case []string:
		for _, item := range v {
			appendMetaScalar(parts, item, key)
			if len(*parts) >= maxMetaEvidenceItems {
				return
			}
		}
	case []interface{}:
		for _, item := range v {
			appendMetaEvidence(parts, item, key)
			if len(*parts) >= maxMetaEvidenceItems {
				return
			}
		}
	case string:
		appendMetaScalar(parts, v, key)
	case fmt.Stringer:
		appendMetaScalar(parts, v.String(), key)
	}
}

func appendMetaScalar(parts *[]string, raw string, key string) {
	if len(*parts) >= maxMetaEvidenceItems {
		return
	}
	clean := strings.ToLower(strings.TrimSpace(raw))
	if clean == "" {
		return
	}
	if len(clean) > 256 {
		clean = clean[:256]
	}
	if key != "" && isMetadataEvidenceKey(key) {
		*parts = append(*parts, clean)
		return
	}
	if strings.Contains(clean, "acad") ||
		strings.Contains(clean, "acaddoc") ||
		strings.Contains(clean, "http") ||
		strings.Contains(clean, "xmlhttp") ||
		strings.Contains(clean, "adodb") ||
		strings.Contains(clean, "wscript") ||
		strings.Contains(clean, "powershell") ||
		strings.Contains(clean, "cmd.exe") ||
		strings.Contains(clean, "regsvr32") ||
		strings.Contains(clean, "vl-file-copy") ||
		strings.Contains(clean, "vl-file-delete") ||
		strings.Contains(clean, "vla-delete") ||
		strings.Contains(clean, "vla-get-modelspace") ||
		strings.Contains(clean, "wcmatch") ||
		strings.Contains(clean, "dwgname") ||
		strings.Contains(clean, "objectname") ||
		strings.Contains(clean, "startup") {
		*parts = append(*parts, clean)
	}
}

func isMetadataEvidenceKey(key string) bool {
	switch key {
	case "resource_summary",
		"urls",
		"com_objects",
		"commands",
		"cmd_strings",
		"registry_keys",
		"file_paths",
		"filenames",
		"paths",
		"reactors",
		"summary",
		"kind",
		"category",
		"evidence":
		return true
	default:
		return strings.HasSuffix(key, "_resource_summary")
	}
}

func compactLowerSource(evidence *EvidenceContext) string {
	if evidence == nil {
		return ""
	}
	source := strings.ToLower(evidence.Source)
	if source == "" {
		return ""
	}
	if len(source) > maxSourceEvidenceBytes {
		source = source[:maxSourceEvidenceBytes]
	}
	return source
}

func normalizedText(normalized []*normalizer.NormalizedNode) string {
	var b strings.Builder
	for _, node := range normalized {
		if node == nil {
			continue
		}
		if node.FunctionName != "" {
			b.WriteString(strings.ToLower(node.FunctionName))
			b.WriteByte(' ')
		}
		b.WriteString(lowerNodeArgumentsText(node.Arguments))
		b.WriteByte(' ')
	}
	return strings.TrimSpace(b.String())
}
