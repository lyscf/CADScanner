package batcheval

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/config"
)

// Evaluator performs batch evaluation of samples.
type Evaluator struct {
	analyzer     *analyzer.Analyzer
	config       *config.Config
	workers      int
	timeout      time.Duration
	failFast     bool
	showProgress bool
}

// EvaluatorOption configures the Evaluator.
type EvaluatorOption func(*Evaluator)

// WithWorkers sets the number of concurrent workers.
func WithWorkers(n int) EvaluatorOption {
	return func(e *Evaluator) {
		e.workers = n
	}
}

// WithTimeout sets the per-sample timeout.
func WithTimeout(d time.Duration) EvaluatorOption {
	return func(e *Evaluator) {
		e.timeout = d
	}
}

// WithFailFast enables fail-fast mode (stop on first error).
func WithFailFast(enabled bool) EvaluatorOption {
	return func(e *Evaluator) {
		e.failFast = enabled
	}
}

// WithProgress enables progress bar output.
func WithProgress(enabled bool) EvaluatorOption {
	return func(e *Evaluator) {
		e.showProgress = enabled
	}
}

// NewEvaluator creates a new batch evaluator.
func NewEvaluator(cfg *config.Config, opts ...EvaluatorOption) (*Evaluator, error) {
	a, err := analyzer.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create analyzer: %w", err)
	}

	e := &Evaluator{
		analyzer:     a,
		config:       cfg,
		workers:      1,
		timeout:      10 * time.Second,
		failFast:     false,
		showProgress: true,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e, nil
}

// EvaluateOne analyzes a single sample with timeout.
func (e *Evaluator) EvaluateOne(sample string) EvalRow {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	type result struct {
		row EvalRow
		err error
	}

	ch := make(chan result, 1)

	go func() {
		row := e.evaluateOneWithContext(ctx, sample)
		ch <- result{row: row}
	}()

	select {
	case <-ctx.Done():
		return EvalRow{
			Sample:     sample,
			Verdict:    "TIMEOUT",
			PMalicious: 0.0,
			Risk:       0.0,
			Error:      fmt.Sprintf("Analysis timeout after %v", e.timeout),
		}
	case res := <-ch:
		return res.row
	}
}

func (e *Evaluator) evaluateOneWithContext(ctx context.Context, sample string) EvalRow {
	res, err := e.analyzer.AnalyzeFile(ctx, sample, false)
	if err != nil {
		return EvalRow{
			Sample:  sample,
			Verdict: "ERROR",
			Error:   err.Error(),
		}
	}

	// Extract attack result info
	attackRisk := 0.0 // AttackResult doesn't have RiskScore field directly
	techniques := 0
	if res.AttackResult != nil {
		techniques = len(res.AttackResult.Techniques)
	}

	// Rule count from matched rules
	ruleCount := len(res.MatchedRules)

	// Decision model and threshold from score result (single source of truth)
	decisionModel := "bayesian"
	threshold := 0.5
	if res.ScoreResult != nil {
		decisionModel = res.ScoreResult.DecisionModel
		threshold = res.ScoreResult.DecisionThreshold
	}

	verdict := "BENIGN"
	if res.IsMalicious {
		verdict = "MALICIOUS"
	}

	row := EvalRow{
		Sample:            sample,
		InputType:         res.InputType,
		Verdict:           verdict,
		RuleVerdict:       res.RuleVerdict,
		FinalVerdict:      res.FinalVerdict,
		DecisionAgreement: res.DecisionAgreement,
		FusionSummary:     res.FusionSummary,
		PMalicious:        res.MaliciousConfidence,
		Risk:              res.RiskScore,
		Threshold:         threshold,
		DecisionModel:     decisionModel,
		AttackRisk:        attackRisk,
		Techniques:        techniques,
		RuleCount:         ruleCount,
		ReadMs:            res.Timing.ReadMs,
		FrontendMs:        res.Timing.StageMs["frontend"],
		ParseMs:           res.Timing.FrontendMs["parse"],
		IRMs:              res.Timing.StageMs["ir"],
		FormalMs:          res.Timing.StageMs["formal"],
		DetectionMs:       res.Timing.StageMs["detection"],
		EncodingMs:        res.Timing.StageMs["encoding"],
		TotalMs:           res.Timing.TotalMs,
		Error:             "",
	}
	if res.LLMAnalysis != nil {
		row.SemanticLabel = string(res.LLMAnalysis.SemanticLabel)
		row.SemanticConfidence = res.LLMAnalysis.Confidence
		row.LLMProvider = res.LLMAnalysis.Provider
		row.LLMModel = res.LLMAnalysis.Model
		row.PromptTokens = res.LLMAnalysis.PromptTokens
		row.CompletionTokens = res.LLMAnalysis.CompletionTokens
		row.LLMLatencyMs = res.LLMAnalysis.LatencyMs
		row.CacheHit = res.LLMAnalysis.CacheHit
	}

	return row
}

// EvaluateSamples evaluates multiple samples with optional concurrency.
func (e *Evaluator) EvaluateSamples(samples []string) ([]EvalRow, error) {
	if e.workers <= 1 {
		return e.evaluateSequential(samples)
	}
	return e.evaluateConcurrent(samples)
}

func (e *Evaluator) evaluateSequential(samples []string) ([]EvalRow, error) {
	rows := make([]EvalRow, 0, len(samples))
	total := len(samples)

	if e.showProgress {
		e.renderProgress(0, total, "")
	}

	for i, sample := range samples {
		row := e.EvaluateOne(sample)
		rows = append(rows, row)

		if e.failFast && (row.Verdict == "ERROR" || row.Verdict == "TIMEOUT") {
			return rows, fmt.Errorf("fail-fast triggered: %s", row.Error)
		}

		if e.showProgress {
			e.renderProgress(i+1, total, sample)
		}
	}

	if e.showProgress {
		fmt.Println()
	}

	return rows, nil
}

func (e *Evaluator) evaluateConcurrent(samples []string) ([]EvalRow, error) {
	total := len(samples)
	rows := make([]EvalRow, total)

	// Progress tracking
	var doneCount int
	var mu sync.Mutex

	if e.showProgress {
		e.renderProgress(0, total, "")
	}

	// Worker pool
	type job struct {
		index  int
		sample string
	}

	jobs := make(chan job, total)
	var wg sync.WaitGroup

	// Error channel for fail-fast
	errCh := make(chan error, 1)
	var errOnce sync.Once

	// Start workers
	workerCount := e.workers
	if workerCount > total {
		workerCount = total
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check if fail-fast already triggered
				select {
				case <-errCh:
					return
				default:
				}

				row := e.EvaluateOne(j.sample)
				rows[j.index] = row

				mu.Lock()
				doneCount++
				if e.showProgress {
					e.renderProgress(doneCount, total, j.sample)
				}
				mu.Unlock()

				if e.failFast && (row.Verdict == "ERROR" || row.Verdict == "TIMEOUT") {
					errOnce.Do(func() {
						errCh <- fmt.Errorf("fail-fast triggered on %s: %s", j.sample, row.Error)
					})
				}
			}
		}()
	}

	// Send jobs
	for i, sample := range samples {
		select {
		case <-errCh:
			close(jobs)
			goto wait
		case jobs <- job{index: i, sample: sample}:
		}
	}
	close(jobs)

wait:
	wg.Wait()

	if e.showProgress {
		fmt.Println()
	}

	select {
	case err := <-errCh:
		return rows, err
	default:
		return rows, nil
	}
}

func (e *Evaluator) renderProgress(done, total int, sample string) {
	if total <= 0 {
		total = 1
	}
	ratio := float64(done) / float64(total)
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	width := 30
	filled := int(ratio * float64(width))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)

	label := ""
	if sample != "" {
		label = "  " + shortenSampleLabel(sample, 96)
	}
	fmt.Printf("\rProgress: [%s] %d/%d (%5.1f%%)%s", bar, done, total, ratio*100, label)

	if done >= total {
		fmt.Println()
	}
}

func shortenSampleLabel(sample string, maxLen int) string {
	if maxLen <= 3 || len(sample) <= maxLen {
		return sample
	}
	return "..." + sample[len(sample)-maxLen+3:]
}

// MustLoadConfig loads config or returns defaults on error.
func MustLoadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		// Return default config
		return &config.Config{
			Analysis: config.AnalysisConfig{
				MaxFileSize:         10 * 1024 * 1024,
				Timeout:             30,
				EnableVerbose:       false,
				EnableDeobfuscation: true,
			},
			Detection: config.DetectionConfig{
				Threshold:    0.5,
				EnableRules:  true,
				EnableATTACK: true,
			},
			Scoring: config.ScoringConfig{
				DecisionThreshold: 0.5,
				EnableFormal:      true,
				PrimitiveWeight:   0.5,
				PatternWeight:     0.3,
				ContextWeight:     0.2,
				ContextComponents: map[string]float64{
					"env_awareness": 0.3,
					"persistence":   0.35,
					"execution":     0.35,
				},
			},
		}
	}
	return cfg
}

// Run is a convenience function that runs the full batch evaluation pipeline.
func Run(root string, recursive bool, opts ...EvaluatorOption) ([]EvalRow, error) {
	// Check if root exists
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("sample directory not found: %s", root)
	}

	// Find samples
	samples, err := FindSamples(root, recursive)
	if err != nil {
		return nil, fmt.Errorf("failed to find samples: %w", err)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no supported samples found under: %s", root)
	}

	// Create evaluator
	cfg := MustLoadConfig("")
	eval, err := NewEvaluator(cfg, opts...)
	if err != nil {
		return nil, err
	}

	// Evaluate
	return eval.EvaluateSamples(samples)
}
