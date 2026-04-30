package scoring

import (
	"math"
	"regexp"
	"strings"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/graph"
	"github.com/evilcad/cadscanner/pkg/ir"
)

// Scorer scores the detection results
type Scorer struct {
	config        *config.Config
	contextScorer *ContextScorer
}

var scoringStartupPattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx)\b`)

var ruleFloorIDs = []string{
	"STARTUP_LOAD_001",
	"STARTUP_REWRITE_001",
	"WORM_REPL_001",
	"WORM_001",
	"DESTRUCT_001",
	"NET_DROPPER_001",
	"PROC_EXEC_001",
	"STARTUP_HOOK_001",
	"COM_DROPPER_001",
	"SCRIPTCTRL_001",
	"EXFIL_STUB_001",
	"DESTRUCT_STUB_001",
	"STARTUP_INFECT_001",
	"REACT_PROP_001",
	"REC_FAS_PROP_001",
	"NET_STUB_001",
	"FINDCOPY_001",
	"STARTUP_COPY_STR_001",
	"REGISTRY_001",
	"BOOTDAT_CHAIN_001",
}

func isScoringStartupTarget(target string) bool {
	lower := strings.ToLower(target)
	return strings.Contains(lower, "acad.lsp") ||
		strings.Contains(lower, "acaddoc.lsp") ||
		strings.Contains(lower, "acad.fas") ||
		strings.Contains(lower, "acad.vlx") ||
		strings.Contains(lower, "startup") ||
		scoringStartupPattern.MatchString(lower)
}

// FormalInput carries formal analysis results into the main Scorer.
// This is the bridge between the formal/graph layer and the decision model.
type FormalInput struct {
	PredicateResults map[string]*graph.PredicateResult
	FormalScore      *FormalScoreResult
}

// ScoreResult represents the scoring result
type ScoreResult struct {
	MaliciousPosterior    float64
	BenignPosterior       float64
	DecisionThreshold     float64
	DecisionModel         string
	RiskScore             float64
	BehaviorEvidence      map[string]float64
	BehaviorProbabilities map[string]float64
	BehaviorLogits        map[string]float64
	BehaviorGates         map[string]float64
	BehaviorWeights       map[string]float64
	BehaviorTerms         map[string]float64
	EvidenceFeature       map[string]float64
	EvidenceRule          map[string]float64
	EvidenceAttack        map[string]float64
	EvidenceFormal        map[string]float64
	ContextScore          *ContextScoreResult
}

// New creates a new scorer
func New(cfg *config.Config) *Scorer {
	return &Scorer{
		config:        cfg,
		contextScorer: NewContextScorer(cfg),
	}
}

func (s *Scorer) configuredWeight(name string, fallback float64) float64 {
	if s.config == nil {
		return fallback
	}
	switch name {
	case "rule":
		if s.config.Scoring.RuleWeight > 0 {
			return s.config.Scoring.RuleWeight
		}
	case "attack":
		if s.config.Scoring.AttackWeight > 0 {
			return s.config.Scoring.AttackWeight
		}
	case "feature":
		if s.config.Scoring.FeatureWeight > 0 {
			return s.config.Scoring.FeatureWeight
		}
	case "formal":
		if s.config.Scoring.FormalWeight > 0 {
			return s.config.Scoring.FormalWeight
		}
	}
	return fallback
}

func (s *Scorer) configuredSigmoidSlope() float64 {
	if s.config != nil && s.config.Scoring.SigmoidSlope > 0 {
		return s.config.Scoring.SigmoidSlope
	}
	return 4.0
}

func (s *Scorer) configuredRuleFloor(ruleID string) float64 {
	if s.config == nil || s.config.Scoring.RiskFloors == nil {
		return 0.0
	}
	return s.config.Scoring.RiskFloors[ruleID]
}

func (s *Scorer) configuredRuleMultiplier(ruleID string) float64 {
	if s.config == nil || s.config.Scoring.RuleMultipliers == nil {
		return 1.0
	}
	if mult, ok := s.config.Scoring.RuleMultipliers[ruleID]; ok && mult > 0 {
		return mult
	}
	return 1.0
}

func redistributeFormalWeight(ruleWeight, attackWeight, featureWeight, formalWeight, formalEvidence float64) (float64, float64, float64, float64) {
	if formalWeight <= 0 || formalEvidence > 0 {
		return ruleWeight, attackWeight, featureWeight, formalWeight
	}
	nonFormalTotal := ruleWeight + attackWeight + featureWeight
	if nonFormalTotal <= 0 {
		return ruleWeight, attackWeight, featureWeight, 0.0
	}
	scale := (nonFormalTotal + formalWeight) / nonFormalTotal
	return ruleWeight * scale, attackWeight * scale, featureWeight * scale, 0.0
}

// scoreFileWrite returns severity for FILE_WRITE based on target path
// Temporary files: 0.3, Startup files: 0.9, Normal files: 0.6
func (s *Scorer) scoreFileWrite(effect ir.IREffect) float64 {
	target := strings.ToLower(effect.Target)
	source := strings.ToLower(effect.Source)

	// Check for temporary file patterns in target or source (benign)
	tempPatterns := []string{
		"tmp", "temp", "mktemp", ".tmp", ".temp",
		".dcl", // AutoCAD dialog files
		"vl-filename-mktemp",
	}
	for _, pattern := range tempPatterns {
		if strings.Contains(target, pattern) || strings.Contains(source, pattern) {
			return 0.3 // Low severity for temp/dialog files
		}
	}

	// Check for common temp file variable names (e.g., fn from vl-filename-mktemp)
	// These are typically short variable names used for temporary file handles
	tempVarNames := []string{"fn", "tmp", "temp", "f"}
	for _, varName := range tempVarNames {
		if target == varName {
			return 0.0 // No severity for temp file variables created via mktemp-style flows
		}
	}

	// Check for startup/persistence file patterns (dangerous)
	startupPatterns := []string{
		"acad.lsp", "acaddoc.lsp", "acad.fas", "acad.vlx",
		"startup", "runonce",
	}
	for _, pattern := range startupPatterns {
		if strings.Contains(target, pattern) {
			return 0.9 // High severity for startup files
		}
	}
	if isScoringStartupTarget(target) {
		return 0.9
	}

	// Default for normal file writes
	return 0.6
}

// scoreCOMCreate returns severity for COM_CREATE based on source function
// vl-load-com and similar AutoCAD COM initializations are benign: 0.15
// Other COM object creation: 0.8
func (s *Scorer) scoreCOMCreate(effect ir.IREffect) float64 {
	source := strings.ToLower(effect.Source)
	target := strings.ToLower(effect.Target)

	// AutoCAD COM initialization functions (benign - just enable COM access)
	benignCOMInit := []string{
		"vl-load-com",
	}

	for _, benign := range benignCOMInit {
		if source == benign || strings.Contains(source, benign) {
			return 0.02 // Effectively benign COM initialization
		}
	}

	// Check for dangerous COM objects being created
	if strings.Contains(target, "wscript.shell") || strings.Contains(target, "shell.application") ||
		strings.Contains(target, "wscript") || strings.Contains(target, "vbscript") ||
		strings.Contains(target, "scriptlet") || strings.Contains(target, "adodb.stream") ||
		strings.Contains(target, "adodb.connection") {
		return 0.85
	}
	if strings.Contains(target, "xmlhttp") || strings.Contains(target, "msxml") || strings.Contains(target, "microsoft.xmlhttp") {
		return 0.55
	}
	if strings.Contains(target, "filesystemobject") || strings.Contains(target, "scripting.filesystemobject") {
		return 0.25
	}

	// Default for unknown COM creation
	return 0.5
}

// scoreCOMInvoke returns severity for COM_INVOKE based on target object type
// Benign AutoCAD VLA operations: 0.2, Suspicious: 0.5, Dangerous: 0.8
func (s *Scorer) scoreCOMInvoke(effect ir.IREffect) float64 {
	target := strings.ToLower(effect.Target)
	source := strings.ToLower(effect.Source)

	// Check for dangerous COM objects
	if strings.Contains(target, "wscript.shell") || strings.Contains(source, "wscript.shell") ||
		strings.Contains(target, "shell.application") || strings.Contains(source, "shell.application") ||
		strings.Contains(target, "adodb.stream") || strings.Contains(source, "adodb.stream") ||
		strings.Contains(target, "adodb.connection") || strings.Contains(source, "adodb.connection") ||
		strings.Contains(target, "vbscript") || strings.Contains(source, "vbscript") ||
		strings.Contains(target, "scriptlet") || strings.Contains(source, "scriptlet") {
		return 0.8
	}
	if strings.Contains(target, "xmlhttp") || strings.Contains(source, "xmlhttp") ||
		strings.Contains(target, "msxml") || strings.Contains(source, "msxml") ||
		strings.Contains(target, "microsoft.xmlhttp") || strings.Contains(source, "microsoft.xmlhttp") {
		return 0.55
	}
	if strings.Contains(target, "filesystemobject") || strings.Contains(source, "filesystemobject") {
		return 0.2
	}

	// Check for VBA code injection patterns via vlax-invoke-method FIRST
	// These are malicious VBA macro virus patterns, not benign VLA operations
	// Must check before the general vlax- prefix check
	codeInjectTargets := []string{
		"insertlines", "addfromstring", "codemodule",
		"vbproject", "vbcomponents",
	}
	for _, inject := range codeInjectTargets {
		if strings.Contains(target, inject) || strings.Contains(source, inject) {
			return 0.92 // Very high severity for VBA code injection
		}
	}

	// Check for AutoCAD internal VLA operations (benign)
	// These are normal drawing/geometry operations, NOT malicious COM calls
	benignVLAOps := []string{
		"vla-", "vlax-",
		"getattributes", "gettextstring", "insertionpoint",
		"effectivename", "getboundingbox", "getpoint", "getentity",
		"getselection", "addline", "addcircle", "addtext", "addmtext",
		"add", "get", "put", "delete", "item", "count", "explode",
		"active", "document", "modelspace", "paperspace", "blocks",
		"layer", "color", "linetype", "coordinates", "normal",
		"objectname", "startangle", "endangle", "radius", "height",
	}

	for _, benign := range benignVLAOps {
		if strings.HasPrefix(source, benign) || strings.Contains(target, benign) {
			return 0.2 // Low severity for benign VLA operations
		}
	}

	// Explicitly benign VLAX operations (property getters, type conversions)
	benignVLAXExact := []string{
		"vlax-get-property", "vlax-get",
		"vlax-put-property", "vlax-put",
		"vlax-invoke-method", "vlax-invoke",
		"vlax-ename->vla-object", "vlax-ename->vla",
		"vlax-vla-object->ename",
		"vlax-variant-value", "vlax-variant-type",
		"vlax-make-variant", "vlax-make-safearray",
		"vlax-erased-p", "vlax-release-object",
		"vlax-curve-get", "vlax-curve-getdistatparam",
	}
	for _, op := range benignVLAXExact {
		if source == op || strings.HasPrefix(source, op+" ") {
			return 0.15 // Very low severity for pure property access
		}
	}

	// Default for unknown COM operations
	return 0.5
}

// Score scores the detection results with optional formal analysis input.
// semanticTags and envChecks are generated by the IR layer and flow through
// the pipeline context — no more empty placeholder values.
func (s *Scorer) Score(detectResult *detector.DetectResult, irResult *ir.IRResult, formal *FormalInput, semanticTags map[string][]ir.SemanticTag, envChecks []string) *ScoreResult {
	result := &ScoreResult{
		MaliciousPosterior:    0.0,
		BenignPosterior:       0.0,
		DecisionThreshold:     s.config.Scoring.DecisionThreshold,
		DecisionModel:         "bayesian",
		RiskScore:             0.0,
		BehaviorEvidence:      make(map[string]float64),
		BehaviorProbabilities: make(map[string]float64),
		BehaviorLogits:        make(map[string]float64),
		BehaviorGates:         make(map[string]float64),
		BehaviorWeights:       make(map[string]float64),
		BehaviorTerms:         make(map[string]float64),
		EvidenceFeature:       make(map[string]float64),
		EvidenceRule:          make(map[string]float64),
		EvidenceAttack:        make(map[string]float64),
		EvidenceFormal:        make(map[string]float64),
	}

	// Calculate evidence from rules
	ruleEvidence := 0.0
	for _, rule := range detectResult.MatchedRules {
		ruleEvidence += rule.Severity * s.configuredRuleMultiplier(rule.ID)
	}
	if len(detectResult.MatchedRules) > 0 {
		ruleEvidence /= float64(len(detectResult.MatchedRules))
	}
	result.EvidenceRule["malicious"] = ruleEvidence

	// Calculate evidence from ATT&CK techniques
	attackEvidence := 0.0
	for _, tech := range detectResult.AttackResult.Techniques {
		attackEvidence += tech.Confidence
	}
	if len(detectResult.AttackResult.Techniques) > 0 {
		attackEvidence /= float64(len(detectResult.AttackResult.Techniques))
	}
	result.EvidenceAttack["malicious"] = attackEvidence

	// Check for VBA injection rule match
	hasVBAInjectRule := false
	matchedRuleIDs := make(map[string]bool)
	for _, rule := range detectResult.MatchedRules {
		matchedRuleIDs[rule.ID] = true
		if rule.ID == "VBA_INJECT_001" {
			hasVBAInjectRule = true
		}
	}

	// Calculate evidence from features (IR effects)
	featureEvidence := 0.0
	effectCount := 0.0
	for _, effect := range irResult.Effects {
		targetLower := strings.ToLower(effect.Target)
		sourceLower := strings.ToLower(effect.Source)
		// Assign severity based on effect type
		severity := 0.5
		switch effect.EffectType {
		case ir.FILE_WRITE:
			// Use scoreFileWrite to distinguish temp files from malicious writes
			severity = s.scoreFileWrite(effect)
		case ir.REGISTRY_MODIFY:
			if detector.IsSuspiciousRegistryPath(effect.Target) {
				severity = 0.9
			} else {
				severity = 0.25
			}
		case ir.PROCESS_CREATE:
			if detector.IsSuspiciousProcessCommand(effect.Target) {
				severity = 0.9
			} else {
				severity = 0.35
			}
		case ir.NETWORK_CONNECT:
			severity = 0.65
		case ir.COM_CREATE:
			// Use scoreCOMCreate to distinguish benign COM init from dangerous COM creation
			severity = s.scoreCOMCreate(effect)
		case ir.COM_INVOKE:
			// Use scoreCOMInvoke to distinguish benign VLA from malicious COM
			severity = s.scoreCOMInvoke(effect)
			// Boost severity for code injection patterns
			if strings.Contains(targetLower, "insertlines") ||
				strings.Contains(targetLower, "codemodule") ||
				strings.Contains(targetLower, "addfromstring") {
				severity = 0.95
			}
			// If VBA injection rule matched, boost vlax-invoke severity
			// because it likely represents VBA code injection
			if hasVBAInjectRule && strings.Contains(sourceLower, "vlax-invoke") {
				severity = 0.90
			}
		case ir.COMMAND_HIJACK:
			severity = 0.85 // Command hijacking is dangerous
		case ir.FILE_READ, ir.REGISTRY_READ:
			severity = 0.3
		}
		featureEvidence += severity
		effectCount++
	}

	if effectCount > 0 {
		featureEvidence /= effectCount
	}
	result.EvidenceFeature["malicious"] = featureEvidence

	// Calculate formal evidence from predicates and formal score
	formalEvidence := 0.0
	if formal != nil {
		// Only satisfied predicates contribute to evidence (match Python behavior)
		for name, pred := range formal.PredicateResults {
			if pred.Satisfied {
				formalEvidence += pred.Confidence * 0.5
				result.EvidenceFormal[name] = pred.Confidence
			}
		}
		// Formal score decomposition contributes only if significant
		if formal.FormalScore != nil && formal.FormalScore.Final > 0.5 {
			formalEvidence += formal.FormalScore.Final * 0.3
			result.EvidenceFormal["formal_score"] = formal.FormalScore.Final
		}
		formalEvidence = math.Min(1.0, formalEvidence)
	}
	result.EvidenceFormal["combined"] = formalEvidence

	// Combine evidence using weighted average
	// With formal channel: rule=0.30, attack=0.25, feature=0.25, formal=0.20
	// Without formal channel: rule=0.40, attack=0.30, feature=0.30
	weightRule := s.configuredWeight("rule", 0.30)
	weightAttack := s.configuredWeight("attack", 0.25)
	weightFeature := s.configuredWeight("feature", 0.25)
	weightFormal := s.configuredWeight("formal", 0.20)

	if formal == nil {
		weightRule = 0.4
		weightAttack = 0.3
		weightFeature = 0.3
		weightFormal = 0.0
	}

	weightRule, weightAttack, weightFeature, weightFormal =
		redistributeFormalWeight(weightRule, weightAttack, weightFeature, weightFormal, formalEvidence)

	combinedEvidence := weightRule*ruleEvidence + weightAttack*attackEvidence + weightFeature*featureEvidence + weightFormal*formalEvidence

	// Calculate posterior probability using a threshold-centered sigmoid.
	// This keeps weak evidence below 0.5 instead of treating any non-zero
	// evidence as malicious by default.
	bias := 0.5
	k := s.configuredSigmoidSlope()
	logit := k * (combinedEvidence - bias)
	result.BehaviorLogits["malicious"] = logit

	// Apply sigmoid gate
	gate := 1.0 / (1.0 + math.Exp(-logit))
	result.BehaviorGates["malicious"] = gate

	// Set posterior
	result.MaliciousPosterior = gate
	result.BenignPosterior = 1.0 - gate

	// Calculate risk score
	result.RiskScore = result.MaliciousPosterior

	// Set behavior probabilities
	result.BehaviorProbabilities["malicious"] = result.MaliciousPosterior
	result.BehaviorProbabilities["benign"] = result.BenignPosterior

	// Set behavior evidence
	result.BehaviorEvidence["malicious"] = combinedEvidence

	// Set behavior weights
	result.BehaviorWeights["malicious"] = 1.0
	result.BehaviorWeights["rule"] = weightRule
	result.BehaviorWeights["attack"] = weightAttack
	result.BehaviorWeights["feature"] = weightFeature
	result.BehaviorWeights["formal"] = weightFormal

	// Set behavior terms
	result.BehaviorTerms["malicious"] = weightRule*ruleEvidence + weightAttack*attackEvidence + weightFeature*featureEvidence + weightFormal*formalEvidence

	// Calculate context score using real semantic tags and env checks from IR layer
	result.ContextScore = s.contextScorer.CalculateContextScore(irResult.Effects, irResult.LiftedEffects, semanticTags, envChecks)

	// Adjust risk score based on context.
	// Keep only the positive boost: the low-context penalty suppresses
	// short malicious loaders and startup-chain stubs too aggressively.
	contextAdjustment := result.ContextScore.FinalScore
	if contextAdjustment > 0.7 {
		// High context score - likely malicious
		result.RiskScore = math.Min(1.0, result.RiskScore*1.2)
	}

	// Startup-chain code loading is a strong malicious indicator in this corpus.
	// Preserve a high floor so loader stubs are not washed out by sparse context.
	for _, ruleID := range ruleFloorIDs {
		if matchedRuleIDs[ruleID] {
			result.RiskScore = math.Max(result.RiskScore, s.configuredRuleFloor(ruleID))
		}
	}

	// Recalculate posterior based on adjusted risk score
	result.MaliciousPosterior = result.RiskScore
	result.BenignPosterior = 1.0 - result.MaliciousPosterior
	result.BehaviorProbabilities["malicious"] = result.MaliciousPosterior
	result.BehaviorProbabilities["benign"] = result.BenignPosterior

	return result
}
