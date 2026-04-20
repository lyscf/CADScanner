package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/batcheval"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/normalizer"
	"github.com/evilcad/cadscanner/pkg/scoring"
)

type analyzedSample struct {
	Path          string
	InputType     string
	Label         string
	CandidateAPIs []string
	Pipeline      *analyzer.PipelineContext
	Elapsed       time.Duration
}

type sampleSummary struct {
	Sample          string  `json:"sample"`
	Label           string  `json:"label"`
	InputType       string  `json:"input_type"`
	CandidateAPIs   int     `json:"candidate_apis"`
	OriginalRisk    float64 `json:"original_risk"`
	OriginalVerdict string  `json:"original_verdict"`
	AnalyzeMs       float64 `json:"analyze_ms"`
}

type levelMetrics struct {
	MaskFraction     float64 `json:"mask_fraction"`
	KeptFraction     float64 `json:"kept_fraction"`
	Seed             int64   `json:"seed"`
	TP               int     `json:"tp"`
	TN               int     `json:"tn"`
	FP               int     `json:"fp"`
	FN               int     `json:"fn"`
	TPR              float64 `json:"tpr"`
	FPR              float64 `json:"fpr"`
	ACC              float64 `json:"acc"`
	Precision        float64 `json:"precision"`
	F1               float64 `json:"f1"`
	MaskedAPIsMean   float64 `json:"masked_apis_mean"`
	MaskedAPIsMax    int     `json:"masked_apis_max"`
	EligibleSamples  int     `json:"eligible_samples"`
	EvaluatedSamples int     `json:"evaluated_samples"`
}

type aggregateMetrics struct {
	MaskFraction   float64 `json:"mask_fraction"`
	KeptFraction   float64 `json:"kept_fraction"`
	Runs           int     `json:"runs"`
	TPRMean        float64 `json:"tpr_mean"`
	TPRStd         float64 `json:"tpr_std"`
	FPRMean        float64 `json:"fpr_mean"`
	FPRStd         float64 `json:"fpr_std"`
	ACCMean        float64 `json:"acc_mean"`
	ACCStd         float64 `json:"acc_std"`
	F1Mean         float64 `json:"f1_mean"`
	F1Std          float64 `json:"f1_std"`
	PrecisionMean  float64 `json:"precision_mean"`
	PrecisionStd   float64 `json:"precision_std"`
	MaskedAPIsMean float64 `json:"masked_apis_mean"`
	MaskedAPIsStd  float64 `json:"masked_apis_std"`
}

type formatCount struct {
	Format string `json:"format"`
	Count  int    `json:"count"`
}

type formatReport struct {
	Format           string             `json:"format"`
	TotalSamples     int                `json:"total_samples"`
	MaliciousSamples int                `json:"malicious_samples"`
	BenignSamples    int                `json:"benign_samples"`
	PerRun           []levelMetrics     `json:"per_run"`
	Aggregate        []aggregateMetrics `json:"aggregate"`
}

type report struct {
	GeneratedAt       string             `json:"generated_at"`
	BenchmarkSource   string             `json:"benchmark_source"`
	Root              string             `json:"root"`
	ConfigPath        string             `json:"config_path,omitempty"`
	MaskMode          string             `json:"mask_mode"`
	Formats           []string           `json:"formats"`
	TimeoutSeconds    int                `json:"timeout_seconds"`
	Levels            []float64          `json:"levels"`
	Seeds             int                `json:"seeds"`
	BaseSeed          int64              `json:"base_seed"`
	ApproximationNote string             `json:"approximation_note"`
	TotalSamples      int                `json:"total_samples"`
	AnalyzedSamples   int                `json:"analyzed_samples"`
	FormatCounts      []formatCount      `json:"format_counts"`
	MaliciousSamples  int                `json:"malicious_samples"`
	BenignSamples     int                `json:"benign_samples"`
	Summaries         []sampleSummary    `json:"summaries"`
	PerRun            []levelMetrics     `json:"per_run"`
	Aggregate         []aggregateMetrics `json:"aggregate"`
	ByFormat          []formatReport     `json:"by_format"`
	Errors            []string           `json:"errors,omitempty"`
}

type maskingPlan struct {
	Mode       string
	TokenMask  map[string]struct{}
	Fraction   float64
	RandomSeed int64
}

var lispKeywords = map[string]struct{}{
	"defun": {}, "setq": {}, "if": {}, "cond": {}, "progn": {}, "while": {},
	"repeat": {}, "foreach": {}, "lambda": {}, "quote": {}, "function": {},
	"and": {}, "or": {}, "not": {}, "list": {}, "car": {}, "cdr": {},
	"cons": {}, "append": {}, "progn*": {}, "eval": {}, "apply": {},
}

var knownAutoLISPAPIs = map[string]bool{
	"acad_colordlg": true, "acad_strlsort": true, "angle": true, "autoload": true,
	"command": true, "dictadd": true, "dictsearch": true, "distance": true,
	"entdel": true, "entget": true, "entmake": true, "entmod": true, "entsel": true,
	"findfile": true, "getangle": true, "getdist": true, "getenv": true,
	"getint": true, "getpoint": true, "getreal": true, "getstring": true,
	"getvar": true, "inters": true, "load": true, "polar": true, "setenv": true,
	"setvar": true, "ssadd": true, "ssdel": true, "ssget": true, "sslength": true,
	"ssname": true, "startapp": true, "strcase": true, "strcat": true,
	"strlen": true, "substr": true, "tblnext": true, "tblsearch": true,
}

func main() {
	var (
		root        = flag.String("root", "examples", "sample root directory")
		configPath  = flag.String("config", "", "config file path")
		manifestCSV = flag.String("manifest-csv", "paper_benchmark_manifest.csv", "CSV whose sample column defines the benchmark; empty means scan root")
		outPath     = flag.String("out", "api_sufficiency.json", "JSON output path")
		recursive   = flag.Bool("recursive", false, "recursively scan root when manifest is empty")
		formatsFlag = flag.String("formats", "fas,vlx", "comma-separated input formats to include")
		timeoutSec  = flag.Int("timeout", 60, "per-sample timeout in seconds")
		levelsFlag  = flag.String("levels", "0,0.1,0.3,0.4,0.5,0.6", "comma-separated API masking fractions")
		seeds       = flag.Int("seeds", 10, "number of random seeds")
		baseSeed    = flag.Int64("base-seed", 20260418, "base random seed")
		maskMode    = flag.String("mask-mode", "token", "masking mode: token or surface")
		format      = flag.String("format", "human", "Output format: human or json")
	)
	flag.Parse()
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("apisufficiency: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(2)
	}
	cfg.LLM.Enabled = false

	levels, err := parseLevels(*levelsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -levels: %v\n", err)
		os.Exit(2)
	}
	formats, err := parseFormats(*formatsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -formats: %v\n", err)
		os.Exit(2)
	}
	if *maskMode != "token" && *maskMode != "surface" {
		fmt.Fprintf(os.Stderr, "invalid -mask-mode: %s\n", *maskMode)
		os.Exit(2)
	}

	samples, benchmarkSource, err := loadBenchmarkSamples(*root, *manifestCSV, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load samples: %v\n", err)
		os.Exit(2)
	}

	selectedSamples := filterSamplesByFormats(samples, formats)
	if len(selectedSamples) == 0 {
		fmt.Fprintf(os.Stderr, "no matching samples found for formats: %s\n", strings.Join(formats, ","))
		os.Exit(2)
	}

	a, err := analyzer.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create analyzer: %v\n", err)
		os.Exit(2)
	}

	d := detector.New(cfg)
	// Recreate scorer locally so replay uses the same config path as the main analyzer.
	s := scoring.New(cfg)

	analyzed, summaries, errors := analyzeCompiledSamples(a, selectedSamples, time.Duration(*timeoutSec)*time.Second)
	if len(analyzed) == 0 {
		fmt.Fprintln(os.Stderr, "no selected samples analyzed successfully")
		os.Exit(2)
	}

	perRun, aggregate := runMaskingExperiment(analyzed, levels, *seeds, *baseSeed, d, s, cfg, *maskMode)
	byFormat := buildFormatReports(analyzed, formats, levels, *seeds, *baseSeed, d, s, cfg, *maskMode)

	report := report{
		GeneratedAt:       time.Now().Format(time.RFC3339),
		BenchmarkSource:   benchmarkSource,
		Root:              *root,
		ConfigPath:        *configPath,
		MaskMode:          *maskMode,
		Formats:           formats,
		TimeoutSeconds:    *timeoutSec,
		Levels:            levels,
		Seeds:             *seeds,
		BaseSeed:          *baseSeed,
		ApproximationNote: "This command replays only the downstream detection/scoring layers after in-memory masking or random degradation of the recovered representation. It does not re-run decryption, parsing, or formal graph construction from scratch, so results should be interpreted as replay-based stress tests rather than a full end-to-end recovery replay.",
		TotalSamples:      len(samples),
		AnalyzedSamples:   len(analyzed),
		FormatCounts:      summarizeFormats(analyzed),
		MaliciousSamples:  countByLabel(analyzed, "malicious"),
		BenignSamples:     countByLabel(analyzed, "benign"),
		Summaries:         summaries,
		PerRun:            perRun,
		Aggregate:         aggregate,
		ByFormat:          byFormat,
		Errors:            errors,
	}

	if err := writeJSON(*outPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		os.Exit(2)
	}

	if outputFormat == "json" {
		cliutil.WriteJSON(map[string]any{
			"command": "apisufficiency",
			"report_path": *outPath,
			"report": report,
		})
		return
	}

	fmt.Printf("Benchmark: %s\n", benchmarkSource)
	fmt.Printf("Formats: %s\n", strings.Join(formats, ","))
	fmt.Printf("Samples analyzed successfully: %d\n", len(analyzed))
	fmt.Printf("Malicious / Benign: %d / %d\n", report.MaliciousSamples, report.BenignSamples)
	for _, row := range aggregate {
		fmt.Printf("mask=%.0f%% kept=%.0f%% runs=%d TPR=%.2f±%.2f FPR=%.2f±%.2f F1=%.3f±%.3f masked_api=%.2f±%.2f\n",
			row.MaskFraction*100.0,
			row.KeptFraction*100.0,
			row.Runs,
			row.TPRMean*100.0,
			row.TPRStd*100.0,
			row.FPRMean*100.0,
			row.FPRStd*100.0,
			row.F1Mean,
			row.F1Std,
			row.MaskedAPIsMean,
			row.MaskedAPIsStd)
	}
	fmt.Printf("Result JSON: %s\n", *outPath)
}

func analyzeCompiledSamples(a *analyzer.Analyzer, samples []string, timeout time.Duration) ([]analyzedSample, []sampleSummary, []string) {
	out := make([]analyzedSample, 0, len(samples))
	summaries := make([]sampleSummary, 0, len(samples))
	var errors []string

	for i, sample := range samples {
		fmt.Fprintf(os.Stderr, "[apisufficiency] analyze %d/%d %s\n", i+1, len(samples), filepath.Base(sample))

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		pipeCtx, elapsed, err := a.AnalyzePipeline(ctx, sample, false)
		cancel()
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", sample, err))
			continue
		}

		candidates := extractMaskableAPIs(pipeCtx)
		detectResult := pipeCtx.DetectResult
		scoreResult := pipeCtx.ScoreResult
		verdict := "BENIGN"
		risk := 0.0
		if scoreResult != nil {
			risk = scoreResult.RiskScore
			if scoreResult.MaliciousPosterior >= scoreResult.DecisionThreshold {
				verdict = "MALICIOUS"
			}
		}
		if detectResult == nil || scoreResult == nil || pipeCtx.IRResult == nil {
			errors = append(errors, fmt.Sprintf("%s: incomplete pipeline outputs", sample))
			continue
		}

		label := "malicious"
		if strings.HasPrefix(filepath.Base(sample), "white_") {
			label = "benign"
		}

		out = append(out, analyzedSample{
			Path:          sample,
			InputType:     pipeCtx.InputType,
			Label:         label,
			CandidateAPIs: candidates,
			Pipeline:      pipeCtx,
			Elapsed:       elapsed,
		})
		summaries = append(summaries, sampleSummary{
			Sample:          sample,
			Label:           label,
			InputType:       pipeCtx.InputType,
			CandidateAPIs:   len(candidates),
			OriginalRisk:    risk,
			OriginalVerdict: verdict,
			AnalyzeMs:       durationMs(elapsed),
		})
	}

	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Sample < summaries[j].Sample })
	return out, summaries, errors
}

func buildFormatReports(samples []analyzedSample, formats []string, levels []float64, seeds int, baseSeed int64, d *detector.Detector, s *scoring.Scorer, cfg *config.Config, maskMode string) []formatReport {
	out := make([]formatReport, 0, len(formats))
	for _, format := range formats {
		subset := filterAnalyzedByFormat(samples, format)
		if len(subset) == 0 {
			continue
		}
		perRun, aggregate := runMaskingExperiment(subset, levels, seeds, baseSeed, d, s, cfg, maskMode)
		out = append(out, formatReport{
			Format:           format,
			TotalSamples:     len(subset),
			MaliciousSamples: countByLabel(subset, "malicious"),
			BenignSamples:    countByLabel(subset, "benign"),
			PerRun:           perRun,
			Aggregate:        aggregate,
		})
	}
	return out
}

func runMaskingExperiment(samples []analyzedSample, levels []float64, seeds int, baseSeed int64, d *detector.Detector, s *scoring.Scorer, cfg *config.Config, maskMode string) ([]levelMetrics, []aggregateMetrics) {
	perRun := make([]levelMetrics, 0, len(levels)*seeds)

	for _, level := range levels {
		for seedIdx := 0; seedIdx < seeds; seedIdx++ {
			seed := baseSeed + int64(seedIdx)
			rng := rand.New(rand.NewSource(seed))
			rows := make([]batcheval.EvalRow, 0, len(samples))
			maskedCounts := make([]float64, 0, len(samples))
			eligible := 0
			maskedMax := 0

			for _, sample := range samples {
				plan := buildMaskingPlan(sample, maskMode, level, seed, rng)
				replayed, maskedCount, eligibleCount := replaySample(sample, plan, d, s, cfg)
				if eligibleCount > 0 {
					eligible++
				}
				if maskedCount > maskedMax {
					maskedMax = maskedCount
				}
				maskedCounts = append(maskedCounts, float64(maskedCount))
				rows = append(rows, batcheval.EvalRow{
					Sample:  sample.Path,
					Verdict: replayed,
				})
			}

			m := batcheval.CalculateMetrics(rows)
			precision := safeDiv(float64(m.TP), float64(m.TP+m.FP))
			f1 := safeDiv(2.0*precision*m.TPR, precision+m.TPR)
			perRun = append(perRun, levelMetrics{
				MaskFraction:     level,
				KeptFraction:     1.0 - level,
				Seed:             seed,
				TP:               m.TP,
				TN:               m.TN,
				FP:               m.FP,
				FN:               m.FN,
				TPR:              m.TPR,
				FPR:              m.FPR,
				ACC:              m.ACC,
				Precision:        precision,
				F1:               f1,
				MaskedAPIsMean:   mean(maskedCounts),
				MaskedAPIsMax:    maskedMax,
				EligibleSamples:  eligible,
				EvaluatedSamples: len(rows),
			})
		}
	}

	return perRun, aggregateRuns(levels, perRun)
}

func buildMaskingPlan(sample analyzedSample, mode string, fraction float64, seed int64, rng *rand.Rand) maskingPlan {
	plan := maskingPlan{
		Mode:       mode,
		Fraction:   fraction,
		RandomSeed: seed + int64(rng.Intn(1_000_000)),
	}
	if mode == "token" {
		plan.TokenMask = chooseMaskedAPIs(sample.CandidateAPIs, fraction, rng)
	}
	return plan
}

func replaySample(sample analyzedSample, plan maskingPlan, d *detector.Detector, s *scoring.Scorer, cfg *config.Config) (string, int, int) {
	var (
		normalized    []*normalizer.NormalizedNode
		replayedIR    *ir.IRResult
		maskedCount   int
		eligibleCount int
	)
	switch plan.Mode {
	case "surface":
		sampleRNG := rand.New(rand.NewSource(plan.RandomSeed))
		var maskedNodes, eligibleNodes int
		normalized, maskedNodes, eligibleNodes = cloneNormalizedNodesSurface(sample.Pipeline.Normalized, plan.Fraction, sampleRNG)
		var maskedEffects, eligibleEffects int
		replayedIR, maskedEffects, eligibleEffects = cloneIRResultSurface(sample.Pipeline.IRResult, plan.Fraction, sampleRNG)
		maskedCount = maskedNodes + maskedEffects
		eligibleCount = eligibleNodes + eligibleEffects
	default:
		normalized = cloneNormalizedNodes(sample.Pipeline.Normalized, plan.TokenMask)
		replayedIR = cloneIRResult(sample.Pipeline.IRResult, plan.TokenMask)
		maskedCount = len(plan.TokenMask)
		eligibleCount = len(sample.CandidateAPIs)
	}

	var formalInput *scoring.FormalInput
	if sample.Pipeline.PredicateResults != nil || sample.Pipeline.FormalScoreResult != nil {
		formalInput = &scoring.FormalInput{
			PredicateResults: sample.Pipeline.PredicateResults,
			FormalScore:      sample.Pipeline.FormalScoreResult,
		}
	}

	detectResult, err := d.Detect(replayedIR, normalized, nil)
	if err != nil {
		return "ERROR", maskedCount, eligibleCount
	}
	scoreResult := s.Score(detectResult, replayedIR, formalInput, replayedIR.SemanticTags, replayedIR.EnvChecks)
	if scoreResult == nil {
		return "ERROR", maskedCount, eligibleCount
	}
	if scoreResult.MaliciousPosterior >= cfg.Scoring.DecisionThreshold {
		return "MALICIOUS", maskedCount, eligibleCount
	}
	return "BENIGN", maskedCount, eligibleCount
}

func cloneIRResult(src *ir.IRResult, masked map[string]struct{}) *ir.IRResult {
	if src == nil {
		return nil
	}

	effects := make([]ir.IREffect, 0, len(src.Effects))
	for _, effect := range src.Effects {
		if effectUsesMaskedAPI(effect, masked) {
			continue
		}
		effects = append(effects, cloneEffect(effect))
	}

	tagger := ir.NewSemanticTagger()
	semanticTags := tagger.TagEffects(effects)
	envChecks := make([]string, 0)
	for _, effect := range effects {
		if effect.EffectType == ir.ENV_CHECK {
			envChecks = append(envChecks, effect.Target)
		}
	}

	return &ir.IRResult{
		Functions:           src.Functions,
		Effects:             effects,
		LiftedEffects:       src.LiftedEffects,
		PropagationEvidence: src.PropagationEvidence,
		FunctionSummaries:   src.FunctionSummaries,
		CallGraph:           src.CallGraph,
		SemanticTags:        semanticTags,
		EnvChecks:           envChecks,
	}
}

func cloneEffect(src ir.IREffect) ir.IREffect {
	dst := src
	if src.Metadata != nil {
		dst.Metadata = cloneStringAnyMap(src.Metadata)
	}
	return dst
}

func cloneIRResultSurface(src *ir.IRResult, fraction float64, rng *rand.Rand) (*ir.IRResult, int, int) {
	if src == nil {
		return nil, 0, 0
	}

	effects := make([]ir.IREffect, 0, len(src.Effects))
	masked := 0
	eligible := len(src.Effects)
	for _, effect := range src.Effects {
		if shouldMaskSurfaceUnit(fraction, rng) {
			masked++
			continue
		}
		effects = append(effects, cloneEffect(effect))
	}

	tagger := ir.NewSemanticTagger()
	semanticTags := tagger.TagEffects(effects)
	envChecks := make([]string, 0)
	for _, effect := range effects {
		if effect.EffectType == ir.ENV_CHECK {
			envChecks = append(envChecks, effect.Target)
		}
	}

	return &ir.IRResult{
		Functions:           src.Functions,
		Effects:             effects,
		LiftedEffects:       src.LiftedEffects,
		PropagationEvidence: src.PropagationEvidence,
		FunctionSummaries:   src.FunctionSummaries,
		CallGraph:           src.CallGraph,
		SemanticTags:        semanticTags,
		EnvChecks:           envChecks,
	}, masked, eligible
}

func cloneNormalizedNodes(nodes []*normalizer.NormalizedNode, masked map[string]struct{}) []*normalizer.NormalizedNode {
	out := make([]*normalizer.NormalizedNode, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, cloneNormalizedNode(node, masked))
	}
	return out
}

func cloneNormalizedNodesSurface(nodes []*normalizer.NormalizedNode, fraction float64, rng *rand.Rand) ([]*normalizer.NormalizedNode, int, int) {
	out := make([]*normalizer.NormalizedNode, 0, len(nodes))
	masked := 0
	eligible := 0
	for _, node := range nodes {
		cloned, nodeMasked, nodeEligible := cloneNormalizedNodeSurface(node, fraction, rng)
		masked += nodeMasked
		eligible += nodeEligible
		if cloned != nil {
			out = append(out, cloned)
		}
	}
	return out, masked, eligible
}

func cloneNormalizedNode(node *normalizer.NormalizedNode, masked map[string]struct{}) *normalizer.NormalizedNode {
	if node == nil {
		return nil
	}

	cloned := &normalizer.NormalizedNode{
		Operation:    node.Operation,
		FunctionName: node.FunctionName,
		Arguments:    cloneArguments(node.Arguments, masked),
		Line:         node.Line,
		Column:       node.Column,
	}
	if node.Metadata != nil {
		cloned.Metadata = cloneStringAnyMap(node.Metadata)
	}

	if isMaskedToken(node.FunctionName, masked) {
		cloned.FunctionName = "__masked_api__"
	}
	return cloned
}

func cloneNormalizedNodeSurface(node *normalizer.NormalizedNode, fraction float64, rng *rand.Rand) (*normalizer.NormalizedNode, int, int) {
	if node == nil {
		return nil, 0, 0
	}

	eligible := 1
	if shouldMaskSurfaceUnit(fraction, rng) {
		return nil, 1, eligible
	}

	args, masked, argEligible := cloneArgumentsSurface(node.Arguments, fraction, rng)
	cloned := &normalizer.NormalizedNode{
		Operation:    node.Operation,
		FunctionName: node.FunctionName,
		Arguments:    args,
		Line:         node.Line,
		Column:       node.Column,
	}
	if node.Metadata != nil {
		cloned.Metadata = cloneStringAnyMap(node.Metadata)
	}
	return cloned, masked, eligible + argEligible
}

func cloneArguments(args []interface{}, masked map[string]struct{}) []interface{} {
	out := make([]interface{}, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case *normalizer.NormalizedNode:
			out[i] = cloneNormalizedNode(v, masked)
		case []interface{}:
			out[i] = cloneArguments(v, masked)
		case string:
			if isMaskedToken(v, masked) {
				out[i] = "__masked_api__"
			} else {
				out[i] = v
			}
		default:
			out[i] = v
		}
	}
	return out
}

func cloneArgumentsSurface(args []interface{}, fraction float64, rng *rand.Rand) ([]interface{}, int, int) {
	out := make([]interface{}, 0, len(args))
	masked := 0
	eligible := 0
	for _, arg := range args {
		switch v := arg.(type) {
		case *normalizer.NormalizedNode:
			cloned, childMasked, childEligible := cloneNormalizedNodeSurface(v, fraction, rng)
			masked += childMasked
			eligible += childEligible
			if cloned != nil {
				out = append(out, cloned)
			}
		case []interface{}:
			cloned, childMasked, childEligible := cloneArgumentsSurface(v, fraction, rng)
			masked += childMasked
			eligible += childEligible
			out = append(out, cloned)
		case string:
			eligible++
			if shouldMaskSurfaceUnit(fraction, rng) {
				masked++
				out = append(out, "__masked_surface__")
			} else {
				out = append(out, v)
			}
		default:
			out = append(out, v)
		}
	}
	return out, masked, eligible
}

func shouldMaskSurfaceUnit(fraction float64, rng *rand.Rand) bool {
	if fraction <= 0 {
		return false
	}
	if fraction >= 1 {
		return true
	}
	return rng.Float64() < fraction
}

func cloneStringAnyMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		switch tv := v.(type) {
		case map[string]interface{}:
			dst[k] = cloneStringAnyMap(tv)
		case []interface{}:
			dst[k] = cloneAnySlice(tv)
		default:
			dst[k] = tv
		}
	}
	return dst
}

func cloneAnySlice(src []interface{}) []interface{} {
	dst := make([]interface{}, len(src))
	for i, item := range src {
		switch tv := item.(type) {
		case map[string]interface{}:
			dst[i] = cloneStringAnyMap(tv)
		case []interface{}:
			dst[i] = cloneAnySlice(tv)
		default:
			dst[i] = tv
		}
	}
	return dst
}

func effectUsesMaskedAPI(effect ir.IREffect, masked map[string]struct{}) bool {
	if len(masked) == 0 {
		return false
	}
	if isMaskedToken(effect.Source, masked) {
		return true
	}
	if fn, ok := effect.Metadata["function"].(string); ok && isMaskedToken(fn, masked) {
		return true
	}
	if method, ok := effect.Metadata["method"].(string); ok && isMaskedToken(method, masked) {
		return true
	}
	return false
}

func extractMaskableAPIs(pipeCtx *analyzer.PipelineContext) []string {
	var items []string
	items = append(items, extractRecoveredCalls(pipeCtx.FASMeta)...)
	items = append(items, extractAPIsFromNormalized(pipeCtx.Normalized)...)
	if pipeCtx.IRResult != nil {
		for _, effect := range pipeCtx.IRResult.Effects {
			items = append(items, effect.Source)
			if fn, ok := effect.Metadata["function"].(string); ok {
				items = append(items, fn)
			}
			if method, ok := effect.Metadata["method"].(string); ok {
				items = append(items, method)
			}
		}
	}
	return filterLikelyAPIs(items)
}

func extractAPIsFromNormalized(nodes []*normalizer.NormalizedNode) []string {
	var out []string
	for _, node := range nodes {
		collectAPIsFromNode(node, &out)
	}
	return canonicalizeList(out)
}

func collectAPIsFromNode(node *normalizer.NormalizedNode, out *[]string) {
	if node == nil {
		return
	}
	*out = append(*out, node.FunctionName)
	for _, arg := range node.Arguments {
		switch v := arg.(type) {
		case *normalizer.NormalizedNode:
			collectAPIsFromNode(v, out)
		case []interface{}:
			collectAPIsFromArgs(v, out)
		case string:
			*out = append(*out, v)
		}
	}
}

func collectAPIsFromArgs(args []interface{}, out *[]string) {
	for _, arg := range args {
		switch v := arg.(type) {
		case *normalizer.NormalizedNode:
			collectAPIsFromNode(v, out)
		case []interface{}:
			collectAPIsFromArgs(v, out)
		case string:
			*out = append(*out, v)
		}
	}
}

func extractRecoveredCalls(meta map[string]interface{}) []string {
	raw, ok := meta["recovered_functions"]
	if !ok {
		return nil
	}

	var out []string
	switch list := raw.(type) {
	case []map[string]interface{}:
		for _, item := range list {
			out = append(out, extractCallsField(item["calls"])...)
		}
	case []interface{}:
		for _, item := range list {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, extractCallsField(m["calls"])...)
		}
	}
	return canonicalizeList(out)
}

func extractCallsField(raw interface{}) []string {
	switch v := raw.(type) {
	case []string:
		return canonicalizeList(v)
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return canonicalizeList(out)
	default:
		return nil
	}
}

func chooseMaskedAPIs(candidates []string, fraction float64, rng *rand.Rand) map[string]struct{} {
	masked := make(map[string]struct{})
	if fraction <= 0 || len(candidates) == 0 {
		return masked
	}

	count := int(math.Round(fraction * float64(len(candidates))))
	if count <= 0 {
		count = 1
	}
	if count > len(candidates) {
		count = len(candidates)
	}

	perm := rng.Perm(len(candidates))
	for i := 0; i < count; i++ {
		masked[candidates[perm[i]]] = struct{}{}
	}
	return masked
}

func aggregateRuns(levels []float64, rows []levelMetrics) []aggregateMetrics {
	grouped := make(map[float64][]levelMetrics)
	for _, row := range rows {
		grouped[row.MaskFraction] = append(grouped[row.MaskFraction], row)
	}

	out := make([]aggregateMetrics, 0, len(levels))
	for _, level := range levels {
		group := grouped[level]
		tprVals := collectMetric(group, func(row levelMetrics) float64 { return row.TPR })
		fprVals := collectMetric(group, func(row levelMetrics) float64 { return row.FPR })
		accVals := collectMetric(group, func(row levelMetrics) float64 { return row.ACC })
		f1Vals := collectMetric(group, func(row levelMetrics) float64 { return row.F1 })
		precisionVals := collectMetric(group, func(row levelMetrics) float64 { return row.Precision })
		maskedVals := collectMetric(group, func(row levelMetrics) float64 { return row.MaskedAPIsMean })

		out = append(out, aggregateMetrics{
			MaskFraction:   level,
			KeptFraction:   1.0 - level,
			Runs:           len(group),
			TPRMean:        mean(tprVals),
			TPRStd:         stddev(tprVals),
			FPRMean:        mean(fprVals),
			FPRStd:         stddev(fprVals),
			ACCMean:        mean(accVals),
			ACCStd:         stddev(accVals),
			F1Mean:         mean(f1Vals),
			F1Std:          stddev(f1Vals),
			PrecisionMean:  mean(precisionVals),
			PrecisionStd:   stddev(precisionVals),
			MaskedAPIsMean: mean(maskedVals),
			MaskedAPIsStd:  stddev(maskedVals),
		})
	}
	return out
}

func collectMetric(rows []levelMetrics, pick func(levelMetrics) float64) []float64 {
	out := make([]float64, 0, len(rows))
	for _, row := range rows {
		out = append(out, pick(row))
	}
	return out
}

func parseLevels(raw string) ([]float64, error) {
	parts := strings.Split(raw, ",")
	levels := make([]float64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return nil, err
		}
		if v < 0 || v > 1 {
			return nil, fmt.Errorf("level %q out of range [0,1]", part)
		}
		levels = append(levels, v)
	}
	if len(levels) == 0 {
		return nil, fmt.Errorf("no masking levels provided")
	}
	sort.Float64s(levels)
	return levels, nil
}

func parseFormats(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	var formats []string
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if part != "fas" && part != "vlx" {
			return nil, fmt.Errorf("unsupported format %q", part)
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		formats = append(formats, part)
	}
	if len(formats) == 0 {
		return nil, fmt.Errorf("no formats provided")
	}
	sort.Strings(formats)
	return formats, nil
}

func filterSamplesByFormats(samples []string, formats []string) []string {
	allowed := make(map[string]struct{}, len(formats))
	for _, format := range formats {
		allowed["."+format] = struct{}{}
	}

	out := make([]string, 0, len(samples))
	for _, sample := range samples {
		if _, ok := allowed[strings.ToLower(filepath.Ext(sample))]; ok {
			out = append(out, sample)
		}
	}
	return out
}

func filterAnalyzedByFormat(samples []analyzedSample, format string) []analyzedSample {
	out := make([]analyzedSample, 0, len(samples))
	for _, sample := range samples {
		if strings.EqualFold(sample.InputType, format) {
			out = append(out, sample)
		}
	}
	return out
}

func loadBenchmarkSamples(root, manifestCSV string, recursive bool) ([]string, string, error) {
	if manifestCSV != "" {
		if _, err := os.Stat(manifestCSV); err == nil {
			rows, err := readCSVSampleColumn(manifestCSV)
			if err != nil {
				return nil, "", err
			}
			return rows, manifestCSV, nil
		}
		if manifestCSV == "paper_benchmark_manifest.csv" {
			if _, err := os.Stat("results_gpt54.csv"); err == nil {
				rows, err := readCSVSampleColumn("results_gpt54.csv")
				if err != nil {
					return nil, "", err
				}
				return rows, "results_gpt54.csv", nil
			}
		}
	}

	rows, err := batcheval.FindSamples(root, recursive)
	if err != nil {
		return nil, "", err
	}
	return rows, root, nil
}

func readCSVSampleColumn(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		if fallback, fallbackErr := readLineManifest(path); fallbackErr == nil {
			return fallback, nil
		}
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("empty csv: %s", path)
	}

	sampleIdx := -1
	for i, col := range records[0] {
		if strings.EqualFold(strings.TrimSpace(col), "sample") {
			sampleIdx = i
			break
		}
	}
	if sampleIdx < 0 {
		return nil, fmt.Errorf("sample column not found in %s", path)
	}

	seen := make(map[string]bool)
	out := make([]string, 0, len(records)-1)
	for _, record := range records[1:] {
		if sampleIdx >= len(record) {
			continue
		}
		sample := strings.TrimSpace(record[sampleIdx])
		if sample == "" || seen[sample] {
			continue
		}
		seen[sample] = true
		out = append(out, sample)
	}
	sort.Strings(out)
	return out, nil
}

func readLineManifest(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	out := []string{}
	seen := make(map[string]bool)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "" || strings.EqualFold(line, "sample") {
			continue
		}
		line = strings.Trim(line, "\"")
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func filterLikelyAPIs(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		n := normalizeToken(item)
		if n == "" {
			continue
		}
		if _, skip := lispKeywords[n]; skip {
			continue
		}
		if strings.HasPrefix(n, "c:") {
			continue
		}
		if strings.HasPrefix(n, "vl-") || strings.HasPrefix(n, "vla-") || strings.HasPrefix(n, "vlax-") || strings.HasPrefix(n, "vlr-") || knownAutoLISPAPIs[n] {
			out = append(out, n)
		}
	}
	return canonicalizeList(out)
}

func canonicalizeList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		n := normalizeToken(item)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func normalizeToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	s = strings.TrimSpace(s)
	return strings.ToLower(s)
}

func isMaskedToken(s string, masked map[string]struct{}) bool {
	if len(masked) == 0 {
		return false
	}
	_, ok := masked[normalizeToken(s)]
	return ok
}

func countByLabel(samples []analyzedSample, label string) int {
	count := 0
	for _, sample := range samples {
		if sample.Label == label {
			count++
		}
	}
	return count
}

func summarizeFormats(samples []analyzedSample) []formatCount {
	counts := make(map[string]int)
	for _, sample := range samples {
		counts[strings.ToLower(sample.InputType)]++
	}

	formats := make([]string, 0, len(counts))
	for format := range counts {
		formats = append(formats, format)
	}
	sort.Strings(formats)

	out := make([]formatCount, 0, len(formats))
	for _, format := range formats {
		out = append(out, formatCount{
			Format: format,
			Count:  counts[format],
		})
	}
	return out
}

func writeJSON(path string, data interface{}) error {
	blob, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644)
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	total := 0.0
	for _, v := range vals {
		total += v
	}
	return total / float64(len(vals))
}

func stddev(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := mean(vals)
	acc := 0.0
	for _, v := range vals {
		diff := v - m
		acc += diff * diff
	}
	return math.Sqrt(acc / float64(len(vals)))
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func durationMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
