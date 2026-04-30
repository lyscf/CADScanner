// Package batcheval provides batch evaluation capabilities for CADScanner,
// matching the functionality of tools/batch_eval.py.
package batcheval

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SupportedExtensions lists the file types that can be analyzed.
var SupportedExtensions = []string{".lsp", ".fas", ".vlx"}

// EvalRow represents a single sample evaluation result.
type EvalRow struct {
	Sample        string  `json:"sample"`
	InputType     string  `json:"input_type"`
	Verdict       string  `json:"verdict"` // MALICIOUS, BENIGN, TIMEOUT, ERROR
	RuleVerdict   string  `json:"rule_verdict,omitempty"`
	FinalVerdict  string  `json:"final_verdict,omitempty"`
	SemanticLabel string  `json:"semantic_label,omitempty"`
	SemanticConfidence float64 `json:"semantic_confidence,omitempty"`
	DecisionAgreement bool `json:"decision_agreement,omitempty"`
	FusionSummary string `json:"fusion_summary,omitempty"`
	LLMProvider   string  `json:"llm_provider,omitempty"`
	LLMModel      string  `json:"llm_model,omitempty"`
	PromptTokens  int     `json:"prompt_tokens,omitempty"`
	CompletionTokens int  `json:"completion_tokens,omitempty"`
	LLMLatencyMs  float64 `json:"llm_latency_ms,omitempty"`
	CacheHit      bool    `json:"cache_hit,omitempty"`
	PMalicious    float64 `json:"p_malicious"`
	Risk          float64 `json:"risk"`
	Threshold     float64 `json:"threshold"`
	DecisionModel string  `json:"decision_model"`
	AttackRisk    float64 `json:"attack_risk"`
	Techniques    int     `json:"techniques"`
	RuleCount     int     `json:"rule_count"`
	ReadMs        float64 `json:"read_ms"`
	FrontendMs    float64 `json:"frontend_ms"`
	ParseMs       float64 `json:"parse_ms"`
	IRMs          float64 `json:"ir_ms"`
	FormalMs      float64 `json:"formal_ms"`
	DetectionMs   float64 `json:"detection_ms"`
	EncodingMs    float64 `json:"encoding_ms"`
	TotalMs       float64 `json:"total_ms"`
	Error         string  `json:"error"`
}

// TimingStats summarizes evaluation timing in milliseconds.
type TimingStats struct {
	Count        int
	ReadAvgMs    float64
	FrontendAvgMs float64
	ParseAvgMs   float64
	IRAvgMs      float64
	FormalAvgMs  float64
	DetectionAvgMs float64
	EncodingAvgMs float64
	TotalAvgMs   float64
	ReadP50Ms    float64
	FrontendP50Ms float64
	ParseP50Ms   float64
	IRP50Ms      float64
	FormalP50Ms  float64
	DetectionP50Ms float64
	EncodingP50Ms float64
	TotalP50Ms   float64
	ReadMaxMs    float64
	FrontendMaxMs float64
	ParseMaxMs   float64
	IRMaxMs      float64
	FormalMaxMs  float64
	DetectionMaxMs float64
	EncodingMaxMs float64
	TotalMaxMs   float64
}

// FindSamples discovers samples in a directory.
func FindSamples(root string, recursive bool) ([]string, error) {
	var samples []string

	if recursive {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip errors, continue walking
			}
			if !info.IsDir() && isSupportedExt(path) {
				samples = append(samples, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				path := filepath.Join(root, entry.Name())
				if isSupportedExt(path) {
					samples = append(samples, path)
				}
			}
		}
	}

	sort.Strings(samples)
	return samples, nil
}

func isSupportedExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, supported := range SupportedExtensions {
		if ext == supported {
			return true
		}
	}
	return false
}

// Metrics holds classification metrics.
type Metrics struct {
	TP              int
	TN              int
	FP              int
	FN              int
	Total           int
	MaliciousTotal  int
	BenignTotal     int
	FNR             float64
	FPR             float64
	TPR             float64
	ACC             float64
}

// CalculateMetrics computes TP/FP/TN/FN and derived metrics.
// Ground truth: files starting with "white_" are benign, others are malicious.
func CalculateMetrics(rows []EvalRow) Metrics {
	var tp, tn, fp, fn int

	for _, row := range rows {
		if row.Verdict == "TIMEOUT" || row.Verdict == "ERROR" {
			continue
		}

		isWhite := strings.HasPrefix(filepath.Base(row.Sample), "white_")
		isMalicious := row.Verdict == "MALICIOUS"

		if isWhite && !isMalicious {
			tn++
		} else if isWhite && isMalicious {
			fp++
		} else if !isWhite && isMalicious {
			tp++
		} else {
			fn++
		}
	}

	maliciousTotal := tp + fn
	benignTotal := tn + fp
	totalEval := tp + tn + fp + fn

	return Metrics{
		TP:             tp,
		TN:             tn,
		FP:             fp,
		FN:             fn,
		Total:          totalEval,
		MaliciousTotal: maliciousTotal,
		BenignTotal:    benignTotal,
		FNR:            safeDiv(float64(fn), float64(maliciousTotal)),
		FPR:            safeDiv(float64(fp), float64(benignTotal)),
		TPR:            safeDiv(float64(tp), float64(maliciousTotal)),
		ACC:            safeDiv(float64(tp+tn), float64(totalEval)),
	}
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0.0
	}
	return a / b
}

// CalculateTimingStats computes aggregate timing statistics over completed rows.
func CalculateTimingStats(rows []EvalRow) TimingStats {
	readVals := collectTiming(rows, func(r EvalRow) float64 { return r.ReadMs })
	frontendVals := collectTiming(rows, func(r EvalRow) float64 { return r.FrontendMs })
	parseVals := collectTiming(rows, func(r EvalRow) float64 { return r.ParseMs })
	irVals := collectTiming(rows, func(r EvalRow) float64 { return r.IRMs })
	formalVals := collectTiming(rows, func(r EvalRow) float64 { return r.FormalMs })
	detectVals := collectTiming(rows, func(r EvalRow) float64 { return r.DetectionMs })
	encodingVals := collectTiming(rows, func(r EvalRow) float64 { return r.EncodingMs })
	totalVals := collectTiming(rows, func(r EvalRow) float64 { return r.TotalMs })

	return TimingStats{
		Count:           len(totalVals),
		ReadAvgMs:       avg(readVals),
		FrontendAvgMs:   avg(frontendVals),
		ParseAvgMs:      avg(parseVals),
		IRAvgMs:         avg(irVals),
		FormalAvgMs:     avg(formalVals),
		DetectionAvgMs:  avg(detectVals),
		EncodingAvgMs:   avg(encodingVals),
		TotalAvgMs:      avg(totalVals),
		ReadP50Ms:       percentile50(readVals),
		FrontendP50Ms:   percentile50(frontendVals),
		ParseP50Ms:      percentile50(parseVals),
		IRP50Ms:         percentile50(irVals),
		FormalP50Ms:     percentile50(formalVals),
		DetectionP50Ms:  percentile50(detectVals),
		EncodingP50Ms:   percentile50(encodingVals),
		TotalP50Ms:      percentile50(totalVals),
		ReadMaxMs:       max(readVals),
		FrontendMaxMs:   max(frontendVals),
		ParseMaxMs:      max(parseVals),
		IRMaxMs:         max(irVals),
		FormalMaxMs:     max(formalVals),
		DetectionMaxMs:  max(detectVals),
		EncodingMaxMs:   max(encodingVals),
		TotalMaxMs:      max(totalVals),
	}
}

// PrintReport prints a formatted report to stdout.
func PrintReport(rows []EvalRow) {
	fmt.Println("\n=== Batch Evaluation Results ===")

	var malicious, benign, timeout, errorCount int
	for _, r := range rows {
		switch r.Verdict {
		case "MALICIOUS":
			malicious++
		case "BENIGN":
			benign++
		case "TIMEOUT":
			timeout++
		case "ERROR":
			errorCount++
		}
	}

	fmt.Printf("Total: %d\n", len(rows))
	fmt.Printf("MALICIOUS: %d\n", malicious)
	fmt.Printf("BENIGN: %d\n", benign)
	fmt.Printf("TIMEOUT: %d\n", timeout)
	fmt.Printf("ERROR: %d\n", errorCount)
	fmt.Println()

	header := fmt.Sprintf("%-10s %7s %7s %6s Sample", "Verdict", "P(M|F)", "Risk", "Type")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))

	// Sort: errors/timeouts last, then by risk descending
	sorted := make([]EvalRow, len(rows))
	copy(sorted, rows)
	sort.Slice(sorted, func(i, j int) bool {
		iError := sorted[i].Verdict == "ERROR" || sorted[i].Verdict == "TIMEOUT"
		jError := sorted[j].Verdict == "ERROR" || sorted[j].Verdict == "TIMEOUT"
		if iError != jError {
			return !iError
		}
		if sorted[i].Risk != sorted[j].Risk {
			return sorted[i].Risk > sorted[j].Risk
		}
		return sorted[i].Sample < sorted[j].Sample
	})

	for _, row := range sorted {
		fmt.Printf("%-10s %7.2f %7.2f %6s %s\n", row.Verdict, row.PMalicious, row.Risk, row.InputType, row.Sample)
		fmt.Printf("%-10s %7s %7s %6s time: total=%6.2fms parse=%6.2fms frontend=%6.2fms ir=%6.2fms formal=%6.2fms detect=%6.2fms\n",
			"", "", "", "", row.TotalMs, row.ParseMs, row.FrontendMs, row.IRMs, row.FormalMs, row.DetectionMs)
		if row.SemanticLabel != "" {
			fmt.Printf("%-10s %7s %7s %6s llm: semantic=%s conf=%.2f final=%s fusion=%s latency=%6.2fms cache=%t\n",
				"", "", "", "", row.SemanticLabel, row.SemanticConfidence, row.FinalVerdict, row.FusionSummary, row.LLMLatencyMs, row.CacheHit)
		}
		if row.Error != "" {
			fmt.Printf("%-10s %7s %7s %6s ERROR: %s\n", "", "", "", "", row.Error)
		}
	}

	m := CalculateMetrics(rows)
	fmt.Println()
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  TP : %4d  (malicious -> detected)\n", m.TP)
	fmt.Printf("  FN : %4d  (malicious -> missed)\n", m.FN)
	fmt.Printf("  TN : %4d  (benign -> correct)\n", m.TN)
	fmt.Printf("  FP : %4d  (benign -> false positive)\n", m.FP)
	fmt.Println()
	fmt.Printf("  FNR : %.2f%%  (%d/%d)\n", m.FNR*100, m.FN, m.MaliciousTotal)
	fmt.Printf("  FPR : %.2f%%  (%d/%d)\n", m.FPR*100, m.FP, m.BenignTotal)
	fmt.Printf("  TPR : %.2f%%  (%d/%d)\n", m.TPR*100, m.TP, m.MaliciousTotal)
	fmt.Printf("  ACC : %.2f%%\n", m.ACC*100)
	fmt.Println(strings.Repeat("=", 50))

	ts := CalculateTimingStats(rows)
	if ts.Count > 0 {
		fmt.Println("Timing (ms):")
		fmt.Printf("  Read      avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.ReadAvgMs, ts.ReadP50Ms, ts.ReadMaxMs)
		fmt.Printf("  Parse     avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.ParseAvgMs, ts.ParseP50Ms, ts.ParseMaxMs)
		fmt.Printf("  Frontend  avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.FrontendAvgMs, ts.FrontendP50Ms, ts.FrontendMaxMs)
		fmt.Printf("  IR        avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.IRAvgMs, ts.IRP50Ms, ts.IRMaxMs)
		fmt.Printf("  Formal    avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.FormalAvgMs, ts.FormalP50Ms, ts.FormalMaxMs)
		fmt.Printf("  Detect    avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.DetectionAvgMs, ts.DetectionP50Ms, ts.DetectionMaxMs)
		fmt.Printf("  Encode    avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.EncodingAvgMs, ts.EncodingP50Ms, ts.EncodingMaxMs)
		fmt.Printf("  Total     avg=%8.2f  p50=%8.2f  max=%8.2f\n", ts.TotalAvgMs, ts.TotalP50Ms, ts.TotalMaxMs)
	}
}

// WriteJSON writes results to a JSON file.
func WriteJSON(rows []EvalRow, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rows)
}

// WriteCSV writes results to a CSV file.
func WriteCSV(rows []EvalRow, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	if len(rows) > 0 {
		headers := []string{"sample", "input_type", "verdict", "p_malicious", "risk", "threshold",
			"rule_verdict", "final_verdict", "semantic_label", "semantic_confidence", "decision_agreement", "fusion_summary",
			"llm_provider", "llm_model", "prompt_tokens", "completion_tokens", "llm_latency_ms", "cache_hit",
			"decision_model", "attack_risk", "techniques", "rule_count",
			"read_ms", "frontend_ms", "parse_ms", "ir_ms", "formal_ms", "detection_ms", "encoding_ms", "total_ms",
			"error"}
		if err := w.Write(headers); err != nil {
			return err
		}
	}

	for _, row := range rows {
		record := []string{
			row.Sample,
			row.InputType,
			row.Verdict,
			fmt.Sprintf("%.4f", row.PMalicious),
			fmt.Sprintf("%.4f", row.Risk),
			fmt.Sprintf("%.4f", row.Threshold),
			row.RuleVerdict,
			row.FinalVerdict,
			row.SemanticLabel,
			fmt.Sprintf("%.4f", row.SemanticConfidence),
			fmt.Sprintf("%t", row.DecisionAgreement),
			row.FusionSummary,
			row.LLMProvider,
			row.LLMModel,
			fmt.Sprintf("%d", row.PromptTokens),
			fmt.Sprintf("%d", row.CompletionTokens),
			fmt.Sprintf("%.4f", row.LLMLatencyMs),
			fmt.Sprintf("%t", row.CacheHit),
			row.DecisionModel,
			fmt.Sprintf("%.4f", row.AttackRisk),
			fmt.Sprintf("%d", row.Techniques),
			fmt.Sprintf("%d", row.RuleCount),
			fmt.Sprintf("%.4f", row.ReadMs),
			fmt.Sprintf("%.4f", row.FrontendMs),
			fmt.Sprintf("%.4f", row.ParseMs),
			fmt.Sprintf("%.4f", row.IRMs),
			fmt.Sprintf("%.4f", row.FormalMs),
			fmt.Sprintf("%.4f", row.DetectionMs),
			fmt.Sprintf("%.4f", row.EncodingMs),
			fmt.Sprintf("%.4f", row.TotalMs),
			row.Error,
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func collectTiming(rows []EvalRow, pick func(EvalRow) float64) []float64 {
	vals := make([]float64, 0, len(rows))
	for _, row := range rows {
		if row.Verdict == "TIMEOUT" || row.Verdict == "ERROR" {
			continue
		}
		vals = append(vals, pick(row))
	}
	sort.Float64s(vals)
	return vals
}

func avg(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func percentile50(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return (vals[mid-1] + vals[mid]) / 2
}

func max(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	return vals[len(vals)-1]
}
