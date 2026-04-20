package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/scoring"
)

// DetectionStage runs pattern detection and scoring.
type DetectionStage struct {
	config   *config.Config
	detector *detector.Detector
	scorer   *scoring.Scorer
}

func NewDetectionStage(cfg *config.Config, d *detector.Detector, s *scoring.Scorer) *DetectionStage {
	return &DetectionStage{config: cfg, detector: d, scorer: s}
}

func (s *DetectionStage) Name() string { return "detection" }

func (s *DetectionStage) Run(ctx context.Context, pipeCtx *PipelineContext) error {
	start := time.Now()
	detectResult, err := s.detector.Detect(pipeCtx.IRResult, pipeCtx.Normalized, &detector.EvidenceContext{
		Source:  pipeCtx.Source,
		FASMeta: pipeCtx.FASMeta,
		VLXMeta: pipeCtx.VLXMeta,
	})
	if err != nil {
		return err
	}
	detectTime := time.Since(start)
	pipeCtx.DetectResult = detectResult

	// Bridge formal analysis results into the scoring decision model
	formalInput := &scoring.FormalInput{
		PredicateResults: pipeCtx.PredicateResults,
		FormalScore:      pipeCtx.FormalScoreResult,
	}
	start = time.Now()
	pipeCtx.ScoreResult = s.scorer.Score(detectResult, pipeCtx.IRResult, formalInput, pipeCtx.SemanticTags, pipeCtx.EnvChecks)
	scoreTime := time.Since(start)
	if pipeCtx.DetectionTiming != nil {
		pipeCtx.DetectionTiming["detect"] = detectTime
		pipeCtx.DetectionTiming["score"] = scoreTime
	}
	if debugutil.TimingEnabled() && (detectTime > 200*time.Millisecond || scoreTime > 200*time.Millisecond) {
		techniques := 0
		if detectResult.AttackResult != nil {
			techniques = len(detectResult.AttackResult.Techniques)
		}
		fmt.Fprintf(os.Stderr, "  [DETECTION-TIMING] detect=%v score=%v (rules=%d techniques=%d)\n",
			detectTime, scoreTime, len(detectResult.MatchedRules), techniques)
	}

	return nil
}
