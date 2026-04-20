package analyzer

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/llm"
)

// EncodingStage produces the LLM behavior encoding.
type EncodingStage struct {
	config *config.Config
}

func NewEncodingStage(cfg *config.Config) *EncodingStage { return &EncodingStage{config: cfg} }

func (s *EncodingStage) Name() string { return "encoding" }

func (s *EncodingStage) Run(ctx context.Context, pipeCtx *PipelineContext) error {
	start := time.Now()
	encoder := llm.NewBehaviorEncoder()
	irResult := pipeCtx.IRResult
	llmEncoding := encoder.Encode(irResult.Effects, irResult.LiftedEffects, irResult.FunctionSummaries, irResult.PropagationEvidence)
	pipeCtx.LLMEncoding = llmEncoding.Encoding
	if pipeCtx.EncodingTiming != nil {
		pipeCtx.EncodingTiming["encode"] = time.Since(start)
	}

	if s.config == nil || !s.config.LLM.Enabled {
		return nil
	}

	analyzeStart := time.Now()
	client := llm.NewClient(s.config.LLM)
	analysis, err := client.Analyze(ctx, llm.Request{
		Filepath:            pipeCtx.Filepath,
		InputType:           pipeCtx.InputType,
		RuleVerdict:         deriveRuleVerdict(pipeCtx),
		RiskScore:           deriveRiskScore(pipeCtx),
		MaliciousConfidence: deriveMaliciousConfidence(pipeCtx),
		MatchedRules:        matchedRuleNames(pipeCtx),
		AttackTechniques:    attackTechniqueNames(pipeCtx),
		LLMEncoding:         pipeCtx.LLMEncoding,
	})
	if pipeCtx.EncodingTiming != nil {
		pipeCtx.EncodingTiming["semantic"] = time.Since(analyzeStart)
	}
	if err != nil {
		pipeCtx.LLMResult = &llm.SemanticAnalysis{
			SemanticLabel: deriveFallbackSemanticLabel(pipeCtx),
			Error:         err.Error(),
		}
		return nil
	}
	pipeCtx.LLMResult = analysis
	return nil
}

func deriveRuleVerdict(pipeCtx *PipelineContext) string {
	if pipeCtx == nil || pipeCtx.ScoreResult == nil {
		return "UNKNOWN"
	}
	if pipeCtx.ScoreResult.MaliciousPosterior >= pipeCtx.ScoreResult.DecisionThreshold {
		return "MALICIOUS"
	}
	return "BENIGN"
}

func deriveMaliciousConfidence(pipeCtx *PipelineContext) float64 {
	if pipeCtx == nil || pipeCtx.ScoreResult == nil {
		return 0
	}
	return pipeCtx.ScoreResult.MaliciousPosterior
}

func deriveRiskScore(pipeCtx *PipelineContext) float64 {
	if pipeCtx == nil || pipeCtx.ScoreResult == nil {
		return 0
	}
	return pipeCtx.ScoreResult.RiskScore
}

func deriveFallbackSemanticLabel(pipeCtx *PipelineContext) llm.SemanticLabel {
	switch deriveRuleVerdict(pipeCtx) {
	case "MALICIOUS":
		return llm.LabelMalicious
	case "BENIGN":
		return llm.LabelBenign
	default:
		return llm.LabelSuspicious
	}
}

func matchedRuleNames(pipeCtx *PipelineContext) []string {
	if pipeCtx == nil || pipeCtx.DetectResult == nil {
		return nil
	}
	out := make([]string, 0, len(pipeCtx.DetectResult.MatchedRules))
	for _, rule := range pipeCtx.DetectResult.MatchedRules {
		out = append(out, formatRule(rule))
	}
	sort.Strings(out)
	return out
}

func formatRule(rule detector.MatchedRule) string {
	if rule.ID == "" {
		return rule.Name
	}
	if rule.Name == "" {
		return rule.ID
	}
	return rule.ID + ":" + rule.Name
}

func attackTechniqueNames(pipeCtx *PipelineContext) []string {
	if pipeCtx == nil || pipeCtx.DetectResult == nil || pipeCtx.DetectResult.AttackResult == nil {
		return nil
	}
	out := make([]string, 0, len(pipeCtx.DetectResult.AttackResult.Techniques))
	for _, tech := range pipeCtx.DetectResult.AttackResult.Techniques {
		label := tech.ID
		if tech.Name != "" {
			label = strings.TrimSpace(label + ":" + tech.Name)
		}
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}
