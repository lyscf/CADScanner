package scoring

import (
	"math"
	"regexp"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/ir"
)

// ContextScoreResult represents the context scoring result
type ContextScoreResult struct {
	EnvAwareness float64
	Persistence  float64
	Execution    float64
	FinalScore   float64
	Weights      map[string]float64
}

// ContextScorer provides context-aware scoring
type ContextScorer struct {
	config *config.Config
}

var contextStartupPattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx)\b`)

func isContextStartupTarget(target string) bool {
	lower := contains(target, "acad.lsp") ||
		contains(target, "acaddoc.lsp") ||
		contains(target, "startup") ||
		contains(target, ".mnl")
	return lower || contextStartupPattern.MatchString(target)
}

// NewContextScorer creates a new context scorer
func NewContextScorer(cfg *config.Config) *ContextScorer {
	return &ContextScorer{
		config: cfg,
	}
}

// CalculateContextScore calculates enhanced context score with breakdown
func (s *ContextScorer) CalculateContextScore(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, semanticTags map[string][]ir.SemanticTag, envChecks []string) *ContextScoreResult {
	result := &ContextScoreResult{
		Weights: make(map[string]float64),
	}

	// Get weights from config or use defaults
	envWeight := 0.3
	persistWeight := 0.35
	execWeight := 0.35

	if s.config != nil {
		if w, ok := s.config.Scoring.ContextComponents["env_awareness"]; ok {
			envWeight = w
		}
		if w, ok := s.config.Scoring.ContextComponents["persistence"]; ok {
			persistWeight = w
		}
		if w, ok := s.config.Scoring.ContextComponents["execution"]; ok {
			execWeight = w
		}
	}

	result.Weights["env_awareness"] = envWeight
	result.Weights["persistence"] = persistWeight
	result.Weights["execution"] = execWeight

	// Factor 1: Environment Awareness (envWeight)
	result.EnvAwareness = s.calculateEnvAwareness(effects, liftedEffects, semanticTags, envChecks)

	// Factor 2: Persistence Strength (persistWeight)
	result.Persistence = s.calculatePersistence(effects, liftedEffects, semanticTags)

	// Factor 3: Execution Capability (execWeight)
	result.Execution = s.calculateExecution(effects, liftedEffects, semanticTags)

	// Weighted combination
	result.FinalScore = envWeight*result.EnvAwareness + persistWeight*result.Persistence + execWeight*result.Execution
	result.FinalScore = math.Min(1.0, result.FinalScore)

	return result
}

// calculateEnvAwareness calculates environment awareness score
func (s *ContextScorer) calculateEnvAwareness(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, semanticTags map[string][]ir.SemanticTag, envChecks []string) float64 {
	score := 0.0

	// Use semantic tags if available
	if len(semanticTags) > 0 {
		for _, tags := range semanticTags {
			for _, tag := range tags {
				switch tag {
				case ir.TAG_ENV_CHECK:
					score += 0.5
				case ir.TAG_MAC_CHECK:
					score += 0.3
				case ir.TAG_DATE_CHECK:
					score += 0.2
				case ir.TAG_HOST_ID:
					score += 0.5
				case ir.TAG_FILE_CTX:
					score += 0.3
				case ir.TAG_APP_CTX:
					score += 0.2
				default:
					score += 0.1
				}
			}
		}
	} else {
		// Check for environment checks from normalized nodes
		for _, check := range envChecks {
			// Weight by type
			if contains(check, "time") || contains(check, "date") {
				score += 0.4 // Delayed execution
			} else if contains(check, "mac") || contains(check, "host") {
				score += 0.5 // Targeting
			} else if contains(check, "file") {
				score += 0.3 // Propagation
			} else if contains(check, "app") || contains(check, "acad") {
				score += 0.2 // Detection
			} else {
				score += 0.1
			}
		}
	}

	// Check for environment-related IR effects
	for _, effect := range effects {
		if contains(effect.Source, "getvar") || contains(effect.Source, "getenv") {
			score += 0.3
		}
	}

	return math.Min(1.0, score)
}

// calculatePersistence calculates persistence strength score
func (s *ContextScorer) calculatePersistence(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, semanticTags map[string][]ir.SemanticTag) float64 {
	score := 0.0

	// Use semantic tags if available
	if len(semanticTags) > 0 {
		for _, tags := range semanticTags {
			for _, tag := range tags {
				switch tag {
				case ir.TAG_STARTUP_HOOK:
					score += 0.4
				case ir.TAG_REGISTRY_MOD:
					score += 0.3
				case ir.TAG_SELF_REPLICATION:
					score += 0.5
				case ir.TAG_AUTOLOAD:
					score += 0.4
				default:
					score += 0.1
				}
			}
		}
	}

	// Check for startup file persistence
	for _, effect := range effects {
		effectTypeStr := string(effect.EffectType)
		targetStr := effect.Target
		sourceStr := effect.Source

		if (contains(effectTypeStr, "file_write") || contains(effectTypeStr, "persistence")) &&
			(isContextStartupTarget(targetStr) || contains(targetStr, "acaddoc")) {
			score += 1.0
		}

		// Check for registry persistence
		if contains(effectTypeStr, "registry") || contains(effectTypeStr, "reg_modify") {
			score += 0.3
		}

		// Check for COM-based persistence
		if contains(effectTypeStr, "com") && (contains(targetStr, "startup") || contains(sourceStr, "startup")) {
			score += 0.4
		}

		// Check for self-replication indicators
		if contains(effectTypeStr, "file_write") && contains(sourceStr, "write") {
			if isContextStartupTarget(targetStr) {
				score += 0.8
			}
		}
	}

	// Check lifted effects for persistence
	for _, lifted := range liftedEffects {
		liftedTypeStr := string(lifted.EffectType)
		methodStr := lifted.Method
		targetStr := lifted.Target

		if (contains(liftedTypeStr, "persistence") || contains(methodStr, "startup")) &&
			(isContextStartupTarget(targetStr) || contains(targetStr, "acaddoc")) {
			score += 1.0
		}
	}

	return math.Min(1.0, score)
}

// calculateExecution calculates execution capability score
func (s *ContextScorer) calculateExecution(effects []ir.IREffect, liftedEffects []ir.LiftedEffect, semanticTags map[string][]ir.SemanticTag) float64 {
	score := 0.0

	// Use semantic tags if available
	if len(semanticTags) > 0 {
		for _, tags := range semanticTags {
			for _, tag := range tags {
				switch tag {
				case ir.TAG_PROCESS_EXEC:
					score += 0.6
				case ir.TAG_SHELL_EXEC:
					score += 0.2
				case ir.TAG_COM_INVOKE:
					score += 0.1
				case ir.TAG_CODE_EXEC:
					score += 0.15
				case ir.TAG_DYNAMIC_EVAL:
					score += 0.15
				default:
					score += 0.05
				}
			}
		}
	}

	for _, effect := range effects {
		effectTypeStr := string(effect.EffectType)
		sourceStr := effect.Source
		targetStr := effect.Target

		// Check for process execution
		if contains(effectTypeStr, "process") || contains(effectTypeStr, "exec") || contains(effectTypeStr, "command") {
			score += 0.6
		}

		// Check for shell execution
		if contains(sourceStr, "shell") || contains(sourceStr, "cmd") || contains(sourceStr, "wscript") {
			score += 0.2
		}

		// Check for COM usage
		if contains(effectTypeStr, "com") {
			score += 0.1
		}

		// Check for dynamic eval
		if contains(effectTypeStr, "eval") || contains(sourceStr, "eval") {
			score += 0.15
		}

		// Check for code loading
		if contains(effectTypeStr, "load") || contains(sourceStr, "load") {
			score += 0.1
		}
		if contains(sourceStr, "load") && isContextStartupTarget(targetStr) {
			score += 0.35
		}
		if codeLoad, ok := effect.Metadata["code_load"].(bool); ok && codeLoad {
			score += 0.15
			if isContextStartupTarget(targetStr) {
				score += 0.25
			}
		}
	}

	// Check lifted effects for execution
	for _, lifted := range liftedEffects {
		liftedTypeStr := string(lifted.EffectType)

		if contains(liftedTypeStr, "process") || contains(liftedTypeStr, "exec") {
			score += 0.6
		}
		if contains(liftedTypeStr, "code") {
			score += 0.15
		}
	}

	return math.Min(1.0, score)
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

// findSubstring performs case-insensitive substring search
func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			// Simple case-insensitive comparison for ASCII
			sc := s[i+j]
			subc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc = sc + ('a' - 'A')
			}
			if subc >= 'A' && subc <= 'Z' {
				subc = subc + ('a' - 'A')
			}
			if sc != subc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
