package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/batcheval"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/llm"
)

type llmMetrics struct {
	TP int
	TN int
	FP int
	FN int
}

type fusionMetrics struct {
	TP int
	TN int
	FP int
	FN int
}

func main() {
	var (
		root        = flag.String("root", "examples", "Sample root directory")
		recursive   = flag.Bool("recursive", false, "Recursively scan sample directory")
		configPath  = flag.String("config", "config.yaml", "Path to config file")
		fillMissing = flag.Bool("fill-missing", false, "Request LLM for samples not matched from cache")
		workers     = flag.Int("workers", 0, "Concurrent workers for fill-missing; defaults to CPU count")
		format      = flag.String("format", "human", "Output format: human or json")
	)
	flag.Parse()
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("llmmetrics: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(2)
	}
	if cfg.LLM.Model == "" {
		fmt.Fprintln(os.Stderr, "llm model is empty in config")
		os.Exit(2)
	}

	samples, err := batcheval.FindSamples(*root, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find samples: %v\n", err)
		os.Exit(2)
	}
	if len(samples) == 0 {
		fmt.Fprintf(os.Stderr, "no supported samples found under: %s\n", *root)
		os.Exit(2)
	}

	cacheBySample, cacheStats, err := loadCacheBySample(cfg.LLM.CacheDir, cfg.LLM.Model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load cache: %v\n", err)
		os.Exit(2)
	}

	metrics := llmMetrics{}
	var maliciousCount, suspiciousCount, benignCount int
	var totalPrompt, totalCompletion int
	var totalLatency float64
	cacheHits := 0
	cacheMisses := 0
	backfilled := 0
	backfillErrors := 0
	missingSamples := make([]string, 0)

	for _, sample := range samples {
		analysis, ok := cacheBySample[normalizeSample(sample)]
		if !ok {
			cacheMisses++
			if *fillMissing {
				missingSamples = append(missingSamples, sample)
			}
			continue
		}
		cacheHits++
		accumulate(sample, analysis, &metrics, &maliciousCount, &suspiciousCount, &benignCount, &totalPrompt, &totalCompletion, &totalLatency)
	}

	if *fillMissing && len(missingSamples) > 0 {
		workerCount := *workers
		if workerCount <= 0 {
			workerCount = runtime.NumCPU()
		}
		if workerCount > len(missingSamples) {
			workerCount = len(missingSamples)
		}
		type fillResult struct {
			sample   string
			analysis *llm.SemanticAnalysis
			err      error
		}
		fmt.Fprintf(os.Stderr, "[llmmetrics] cache misses=%d, starting backfill with workers=%d\n", len(missingSamples), workerCount)
		jobs := make(chan string, len(missingSamples))
		results := make(chan fillResult, len(missingSamples))
		var wg sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a, err := analyzer.New(cfg)
				if err != nil {
					for sample := range jobs {
						results <- fillResult{sample: sample, err: err}
					}
					return
				}
				for sample := range jobs {
					analysis, err := analyzeSampleWithLLM(a, sample, cfg)
					results <- fillResult{sample: sample, analysis: analysis, err: err}
				}
			}()
		}
		for _, sample := range missingSamples {
			jobs <- sample
		}
		close(jobs)
		go func() {
			wg.Wait()
			close(results)
		}()
		completed := 0
		lastPrinted := 0
		for result := range results {
			completed++
			if result.err != nil || result.analysis == nil || result.analysis.SemanticLabel == "" {
				backfillErrors++
				if result.err != nil {
					fmt.Fprintf(os.Stderr, "[llmmetrics][backfill][error] sample=%s err=%v\n", result.sample, result.err)
				} else {
					fmt.Fprintf(os.Stderr, "[llmmetrics][backfill][error] sample=%s err=missing semantic label\n", result.sample)
				}
			} else {
				backfilled++
				cacheBySample[normalizeSample(result.sample)] = result.analysis
				accumulate(result.sample, result.analysis, &metrics, &maliciousCount, &suspiciousCount, &benignCount, &totalPrompt, &totalCompletion, &totalLatency)
			}
			if completed == len(missingSamples) || completed-lastPrinted >= workerCount || completed%25 == 0 {
				fmt.Fprintf(os.Stderr, "[llmmetrics] backfill progress %d/%d success=%d failed=%d\n", completed, len(missingSamples), backfilled, backfillErrors)
				lastPrinted = completed
			}
		}
		fmt.Fprintf(os.Stderr, "[llmmetrics] backfill done success=%d failed=%d\n", backfilled, backfillErrors)
	}

	fusion, fusionEvaluated, fusionErrors := evaluateAverageFusion(samples, cacheBySample, cfg, *workers)

	maliciousTotal := metrics.TP + metrics.FN
	benignTotal := metrics.TN + metrics.FP
	total := maliciousTotal + benignTotal

	if outputFormat == "json" {
		cliutil.WriteJSON(map[string]any{
			"command": "llmmetrics",
			"model": cfg.LLM.Model,
			"dataset_samples": len(samples),
			"fill_missing": *fillMissing,
			"fill_workers": *workers,
			"evaluated_samples": total,
			"cache": map[string]any{
				"total_model_files": cacheStats.TotalModelFiles,
				"missing_sample_metadata": cacheStats.MissingSample,
				"hits": cacheHits,
				"misses": cacheMisses,
				"backfilled": backfilled,
				"backfill_errors": backfillErrors,
			},
			"semantic_labels": map[string]int{
				"malicious": maliciousCount,
				"suspicious": suspiciousCount,
				"benign": benignCount,
			},
			"llm_only": metrics,
			"fusion": map[string]any{
				"metrics": fusion,
				"evaluated_samples": fusionEvaluated,
				"errors": fusionErrors,
			},
			"usage": map[string]any{
				"prompt_tokens": totalPrompt,
				"completion_tokens": totalCompletion,
				"avg_latency_ms": func() float64 {
					if total == 0 {
						return 0
					}
					return totalLatency / float64(total)
				}(),
			},
		})
		return
	}

	fmt.Printf("Model: %s\n", cfg.LLM.Model)
	fmt.Printf("Dataset samples: %d\n", len(samples))
	fmt.Printf("Fill missing: %t\n", *fillMissing)
	if *fillMissing {
		effectiveWorkers := *workers
		if effectiveWorkers <= 0 {
			effectiveWorkers = runtime.NumCPU()
		}
		fmt.Printf("Fill workers: %d\n", effectiveWorkers)
	}
	fmt.Printf("Evaluated samples: %d\n", total)
	fmt.Printf("Cache files for model: %d\n", cacheStats.TotalModelFiles)
	fmt.Printf("Cache files missing sample metadata: %d\n", cacheStats.MissingSample)
	fmt.Printf("Cache hits: %d\n", cacheHits)
	fmt.Printf("Cache misses: %d\n", cacheMisses)
	if *fillMissing {
		fmt.Printf("Backfilled via analyzer+LLM: %d\n", backfilled)
		fmt.Printf("Backfill failures: %d\n", backfillErrors)
	}
	fmt.Printf("Semantic labels: MALICIOUS=%d SUSPICIOUS=%d BENIGN=%d\n", maliciousCount, suspiciousCount, benignCount)
	fmt.Println()
	fmt.Printf("LLM-only metrics (treat SUSPICIOUS as non-malicious):\n")
	fmt.Printf("  TP=%d FN=%d TN=%d FP=%d\n", metrics.TP, metrics.FN, metrics.TN, metrics.FP)
	fmt.Printf("  TPR=%.2f%%\n", percent(metrics.TP, maliciousTotal))
	fmt.Printf("  FPR=%.2f%%\n", percent(metrics.FP, benignTotal))
	fmt.Printf("  ACC=%.2f%%\n", percent(metrics.TP+metrics.TN, total))
	fmt.Println()
	fmt.Printf("Rule+LLM average metrics (fused_score=(rule_score+llm_score)/2):\n")
	fmt.Printf("  Evaluated samples: %d\n", fusionEvaluated)
	fmt.Printf("  Evaluation failures: %d\n", fusionErrors)
	fmt.Printf("  TP=%d FN=%d TN=%d FP=%d\n", fusion.TP, fusion.FN, fusion.TN, fusion.FP)
	fmt.Printf("  TPR=%.2f%%\n", percent(fusion.TP, fusion.TP+fusion.FN))
	fmt.Printf("  FPR=%.2f%%\n", percent(fusion.FP, fusion.TN+fusion.FP))
	fmt.Printf("  ACC=%.2f%%\n", percent(fusion.TP+fusion.TN, fusionEvaluated))
	fmt.Println()
	fmt.Printf("LLM usage:\n")
	fmt.Printf("  prompt_tokens=%d\n", totalPrompt)
	fmt.Printf("  completion_tokens=%d\n", totalCompletion)
	if total > 0 {
		fmt.Printf("  avg_latency_ms=%.2f\n", totalLatency/float64(total))
	}
}

type cacheLoadStats struct {
	TotalModelFiles int
	MissingSample   int
}

func loadCacheBySample(cacheDir string, model string) (map[string]*llm.SemanticAnalysis, cacheLoadStats, error) {
	result := make(map[string]*llm.SemanticAnalysis)
	if strings.TrimSpace(cacheDir) == "" {
		return result, cacheLoadStats{}, nil
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, cacheLoadStats{}, err
	}
	stats := cacheLoadStats{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(cacheDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var analysis llm.SemanticAnalysis
		if err := json.Unmarshal(data, &analysis); err != nil {
			continue
		}
		if analysis.Model != model {
			continue
		}
		stats.TotalModelFiles++
		if analysis.Sample == "" {
			stats.MissingSample++
			continue
		}
		sample := normalizeSample(analysis.Sample)
		if _, exists := result[sample]; !exists {
			result[sample] = &analysis
		}
	}
	return result, stats, nil
}

func normalizeSample(sample string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(sample), "/", "\\")
	normalized = filepath.Clean(normalized)
	return strings.ToLower(normalized)
}

func analyzeSampleWithLLM(a *analyzer.Analyzer, sample string, cfg *config.Config) (analysis *llm.SemanticAnalysis, err error) {
	if a == nil {
		return nil, fmt.Errorf("analyzer is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			analysis = nil
			err = fmt.Errorf("panic while analyzing %s: %v", sample, r)
		}
	}()
	timeout := time.Duration(cfg.LLM.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := a.AnalyzeFile(ctx, sample, false)
	if err != nil {
		return nil, err
	}
	if res == nil || res.LLMAnalysis == nil {
		return nil, fmt.Errorf("missing llm analysis result")
	}
	if strings.TrimSpace(res.LLMAnalysis.Error) != "" {
		return nil, fmt.Errorf("llm analysis error for %s: %s", sample, strings.TrimSpace(res.LLMAnalysis.Error))
	}
	return res.LLMAnalysis, nil
}

type fusionEvalResult struct {
	sample    string
	ruleScore float64
	llmScore  float64
	threshold float64
	evaluated bool
	err       error
}

func evaluateAverageFusion(samples []string, llmBySample map[string]*llm.SemanticAnalysis, cfg *config.Config, workers int) (fusionMetrics, int, int) {
	metrics := fusionMetrics{}
	if len(samples) == 0 {
		return metrics, 0, 0
	}

	workerCount := workers
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	if workerCount > len(samples) {
		workerCount = len(samples)
	}

	fmt.Fprintf(os.Stderr, "[llmmetrics] evaluating rule+llm average fusion for %d samples with workers=%d (reuse cached/backfilled llm, recompute rule scores only)\n", len(samples), workerCount)

	jobs := make(chan string, len(samples))
	results := make(chan fusionEvalResult, len(samples))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := analyzer.New(ruleOnlyConfig(cfg))
			if err != nil {
				for sample := range jobs {
					results <- fusionEvalResult{sample: sample, err: err}
				}
				return
			}
			for sample := range jobs {
				analysis, ok := llmBySample[normalizeSample(sample)]
				if !ok || analysis == nil || analysis.SemanticLabel == "" {
					results <- fusionEvalResult{sample: sample, err: fmt.Errorf("missing llm analysis for fusion")}
					continue
				}
				results <- analyzeFusionSample(a, sample, analysis, cfg)
			}
		}()
	}
	for _, sample := range samples {
		jobs <- sample
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	evaluated := 0
	errors := 0
	completed := 0
	lastPrinted := 0
	for result := range results {
		completed++
		if result.err != nil || !result.evaluated {
			errors++
		} else {
			evaluated++
			accumulateFusion(result.sample, result.ruleScore, result.llmScore, result.threshold, &metrics)
		}
		if completed == len(samples) || completed-lastPrinted >= workerCount || completed%25 == 0 {
			fmt.Fprintf(os.Stderr, "[llmmetrics] fusion progress %d/%d success=%d failed=%d\n", completed, len(samples), evaluated, errors)
			lastPrinted = completed
		}
	}

	return metrics, evaluated, errors
}

func analyzeFusionSample(a *analyzer.Analyzer, sample string, analysis *llm.SemanticAnalysis, cfg *config.Config) fusionEvalResult {
	if a == nil {
		return fusionEvalResult{sample: sample, err: fmt.Errorf("analyzer is nil")}
	}
	timeout := time.Duration(cfg.LLM.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := a.AnalyzeFile(ctx, sample, false)
	if err != nil {
		return fusionEvalResult{sample: sample, err: err}
	}
	if res == nil || res.ScoreResult == nil {
		return fusionEvalResult{sample: sample, err: fmt.Errorf("missing fusion inputs")}
	}
	return fusionEvalResult{
		sample:    sample,
		ruleScore: res.RiskScore,
		llmScore:  llmMaliciousScore(analysis),
		threshold: res.ScoreResult.DecisionThreshold,
		evaluated: true,
	}
}

func ruleOnlyConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	cloned := *cfg
	cloned.LLM = cfg.LLM
	cloned.LLM.Enabled = false
	cloned.LLM.EnableFusion = false
	return &cloned
}

func llmMaliciousScore(analysis *llm.SemanticAnalysis) float64 {
	if analysis == nil {
		return 0.5
	}
	conf := analysis.Confidence
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}

	switch strings.ToUpper(string(analysis.SemanticLabel)) {
	case "MALICIOUS":
		return 0.5 + 0.5*conf
	case "BENIGN":
		return 0.5 - 0.5*conf
	default:
		return 0.5
	}
}

func accumulateFusion(sample string, ruleScore, llmScore, threshold float64, metrics *fusionMetrics) {
	if metrics == nil {
		return
	}
	fusedScore := (ruleScore + llmScore) / 2.0
	isWhite := strings.HasPrefix(filepath.Base(sample), "white_")
	predMalicious := fusedScore >= threshold
	if isWhite && !predMalicious {
		metrics.TN++
	} else if isWhite && predMalicious {
		metrics.FP++
	} else if !isWhite && predMalicious {
		metrics.TP++
	} else {
		metrics.FN++
	}
}

func accumulate(sample string, analysis *llm.SemanticAnalysis, metrics *llmMetrics, maliciousCount, suspiciousCount, benignCount, totalPrompt, totalCompletion *int, totalLatency *float64) {
	if analysis == nil {
		return
	}
	label := strings.ToUpper(string(analysis.SemanticLabel))
	switch label {
	case "MALICIOUS":
		*maliciousCount = *maliciousCount + 1
	case "SUSPICIOUS":
		*suspiciousCount = *suspiciousCount + 1
	default:
		*benignCount = *benignCount + 1
	}

	*totalPrompt += analysis.PromptTokens
	*totalCompletion += analysis.CompletionTokens
	*totalLatency += analysis.LatencyMs

	isWhite := strings.HasPrefix(filepath.Base(sample), "white_")
	predMalicious := label == "MALICIOUS"
	if isWhite && !predMalicious {
		metrics.TN++
	} else if isWhite && predMalicious {
		metrics.FP++
	} else if !isWhite && predMalicious {
		metrics.TP++
	} else {
		metrics.FN++
	}
}

func percent(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) * 100.0 / float64(denom)
}
