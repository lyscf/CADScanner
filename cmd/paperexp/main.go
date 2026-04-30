package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
)

type sampleStat struct {
	Sample          string             `json:"sample"`
	Label           string             `json:"label"`
	InputType       string             `json:"input_type,omitempty"`
	MD5             string             `json:"md5,omitempty"`
	SHA1            string             `json:"sha1,omitempty"`
	SHA256          string             `json:"sha256,omitempty"`
	VTMatchType     string             `json:"vt_match_type,omitempty"`
	Family          string             `json:"family,omitempty"`
	FamilySource    string             `json:"family_source,omitempty"`
	VTLabel         string             `json:"vt_label,omitempty"`
	VTNames         []string           `json:"vt_names,omitempty"`
	RuleEvidence    float64            `json:"rule_evidence"`
	AttackEvidence  float64            `json:"attack_evidence"`
	FeatureEvidence float64            `json:"feature_evidence"`
	FormalEvidence  float64            `json:"formal_evidence"`
	ContextScore    float64            `json:"context_score"`
	MatchedRuleIDs  []string           `json:"matched_rule_ids"`
	MatchedRules    []matchedRuleStat  `json:"matched_rules,omitempty"`
	CurrentRisk     float64            `json:"current_risk"`
	AnalysisMs      float64            `json:"analysis_ms,omitempty"`
	ReadMs          float64            `json:"read_ms,omitempty"`
	StageMs         map[string]float64 `json:"stage_ms,omitempty"`
	FrontendMs      map[string]float64 `json:"frontend_ms,omitempty"`
	IRMs            map[string]float64 `json:"ir_ms,omitempty"`
	FormalMs        map[string]float64 `json:"formal_ms,omitempty"`
	DetectionMs     map[string]float64 `json:"detection_ms,omitempty"`
	EncodingMs      map[string]float64 `json:"encoding_ms,omitempty"`
	ReadDetailMs    map[string]float64 `json:"read_detail_ms,omitempty"`
}

type baselineSample struct {
	Sample      string `json:"sample"`
	Label       string `json:"label"`
	InputType   string `json:"input_type,omitempty"`
	Split       string `json:"split,omitempty"`
	Text        string `json:"text"`
	Semantic    string `json:"semantic,omitempty"`
	RuleIDsText string `json:"rule_ids_text,omitempty"`
}

type matchedRuleStat struct {
	ID       string  `json:"id"`
	Severity float64 `json:"severity"`
}

type parameters struct {
	RuleWeight        float64            `json:"rule_weight"`
	AttackWeight      float64            `json:"attack_weight"`
	FeatureWeight     float64            `json:"feature_weight"`
	FormalWeight      float64            `json:"formal_weight"`
	SigmoidSlope      float64            `json:"sigmoid_slope"`
	DecisionThreshold float64            `json:"decision_threshold"`
	FloorMultiplier   float64            `json:"floor_multiplier"`
	RiskFloors        map[string]float64 `json:"risk_floors"`
	RuleMultipliers   map[string]float64 `json:"rule_multipliers,omitempty"`
}

type metrics struct {
	TP        int     `json:"tp"`
	TN        int     `json:"tn"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	FPR       float64 `json:"fpr"`
	ACC       float64 `json:"acc"`
	Total     int     `json:"total"`
}

type experimentResult struct {
	BenchmarkSource   string           `json:"benchmark_source"`
	VTMetadataDir     string           `json:"vt_metadata_dir,omitempty"`
	VTIndexPath       string           `json:"vt_index_path,omitempty"`
	Seed              int64            `json:"seed"`
	DevRatio          float64          `json:"dev_ratio"`
	MaxFPR            float64          `json:"max_fpr"`
	Selected          parameters       `json:"selected"`
	DevMetrics        metrics          `json:"dev_metrics"`
	TestMetrics       metrics          `json:"test_metrics"`
	FullMetrics       metrics          `json:"full_metrics"`
	FamilySummary     []familyStat     `json:"family_summary,omitempty"`
	AlternativeSplits []splitResult    `json:"alternative_splits,omitempty"`
	VTCoverage        vtCoverage       `json:"vt_coverage"`
	Ablations         []ablationResult `json:"ablations,omitempty"`
	DevSamples        []string         `json:"dev_samples"`
	TestSamples       []string         `json:"test_samples"`
	Errors            []string         `json:"errors,omitempty"`
	Analyzed          []sampleStat     `json:"analyzed_samples"`
}

type ablationResult struct {
	Name    string     `json:"name"`
	Params  parameters `json:"params"`
	Metrics metrics    `json:"metrics"`
}

type splitResult struct {
	Name        string     `json:"name"`
	Params      parameters `json:"params"`
	DevMetrics  metrics    `json:"dev_metrics"`
	TestMetrics metrics    `json:"test_metrics"`
	DevSamples  []string   `json:"dev_samples,omitempty"`
	TestSamples []string   `json:"test_samples,omitempty"`
}

type vtFamilyInfo struct {
	Family       string
	Label        string
	PopularNames []string
	Source       string
}

type vtFileEnvelope struct {
	Data struct {
		Attributes struct {
			MD5                         string `json:"md5"`
			SHA1                        string `json:"sha1"`
			SHA256                      string `json:"sha256"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
				PopularThreatName    []struct {
					Value string `json:"value"`
					Count int    `json:"count"`
				} `json:"popular_threat_name"`
			} `json:"popular_threat_classification"`
		} `json:"attributes"`
	} `json:"data"`
}

type familyStat struct {
	Family  string   `json:"family"`
	Source  string   `json:"source,omitempty"`
	VTLabel string   `json:"vt_label,omitempty"`
	Total   int      `json:"total"`
	TP      int      `json:"tp"`
	FN      int      `json:"fn"`
	Recall  float64  `json:"recall"`
	Samples []string `json:"samples,omitempty"`
}

type vtCoverage struct {
	MaliciousTotal       int      `json:"malicious_total"`
	UniqueMaliciousStems int      `json:"unique_malicious_stems"`
	DirectJSONSamples    int      `json:"direct_json_samples"`
	IndexOnlySamples     int      `json:"index_only_samples"`
	UnmatchedSamples     int      `json:"unmatched_samples"`
	DirectJSONStems      int      `json:"direct_json_stems"`
	IndexOnlyStems       int      `json:"index_only_stems"`
	UnmatchedStems       int      `json:"unmatched_stems"`
	UnmatchedExamples    []string `json:"unmatched_examples,omitempty"`
}

type vtIndexFile struct {
	TotalBadSamples int                          `json:"total_bad_samples"`
	UniqueHashes    int                          `json:"unique_hashes"`
	VTReportsFound  int                          `json:"vt_reports_found"`
	MissingHashes   []string                     `json:"missing_hashes"`
	Samples         map[string]vtIndexSampleInfo `json:"samples"`
}

type vtIndexSampleInfo struct {
	SHA256     string                       `json:"sha256"`
	MD5        string                       `json:"md5"`
	Malicious  int                          `json:"malicious"`
	Suspicious int                          `json:"suspicious"`
	Engines    map[string]vtEngineDetection `json:"engines"`
}

type vtLookup struct {
	Families   map[string]vtFamilyInfo
	DirectKeys map[string]struct{}
	IndexKeys  map[string]struct{}
	Dir        string
	Index      string
}

type sampleHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

type vtEngineDetection struct {
	Category string `json:"category"`
	Result   string `json:"result"`
}

func main() {
	var (
		root            = flag.String("root", "examples", "sample root directory")
		configPath      = flag.String("config", "", "config file path")
		manifestCSV     = flag.String("manifest-csv", "paper_benchmark_manifest.csv", "CSV whose sample column defines the normalized benchmark; default path is auto-regenerated from root before analysis")
		refreshManifest = flag.Bool("refresh-manifest", true, "regenerate the manifest from root before analysis when manifest-csv is set")
		vtDir           = flag.String("vt-dir", filepath.Join("..", "download"), "directory containing VirusTotal JSON responses by sha256")
		vtIndexPath     = flag.String("vt-index", filepath.Join("..", "vt_results.json"), "VirusTotal index JSON used to recover metadata coverage beyond direct JSON files")
		outPath         = flag.String("out", "paper_experiment.json", "JSON output path")
		baselineOutPath = flag.String("baseline-out", "", "optional JSONL path to export recovered representations for RQ4-B baselines")
		timeoutSec      = flag.Int("timeout", 60, "per-sample timeout in seconds")
		seed            = flag.Int64("seed", 20260416, "random seed for deterministic stratified split")
		devRatio        = flag.Float64("dev-ratio", 0.55, "development split ratio")
		maxFPR          = flag.Float64("max-fpr", 0.03, "maximum allowed dev FPR during calibration")
		format          = flag.String("format", "human", "Output format: human or json")
	)
	flag.Parse()
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("paperexp: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(2)
	}
	cfg.LLM.Enabled = false

	samples, benchmarkSource, err := loadBenchmarkSamples(*root, *manifestCSV, *refreshManifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load benchmark samples: %v\n", err)
		os.Exit(2)
	}

	a, err := analyzer.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create analyzer: %v\n", err)
		os.Exit(2)
	}

	vtLookup, err := loadVTMetadata(*vtDir, *vtIndexPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load VT metadata: %v\n", err)
		os.Exit(2)
	}

	stats, baselineRows, errors := analyzeSamples(a, samples, vtLookup, time.Duration(*timeoutSec)*time.Second)
	if len(stats) == 0 {
		fmt.Fprintln(os.Stderr, "no samples analyzed successfully")
		os.Exit(2)
	}

	dev, test := stratifiedSplit(stats, *devRatio, *seed)
	selected, devMetrics := calibrate(dev, cfg, *maxFPR)
	testMetrics := evaluate(test, selected)
	fullMetrics := evaluate(stats, selected)
	altSplits := evaluateAlternativeSplits(stats, cfg, *devRatio, *seed, *maxFPR)

	result := experimentResult{
		BenchmarkSource:   benchmarkSource,
		VTMetadataDir:     vtLookup.Dir,
		VTIndexPath:       vtLookup.Index,
		Seed:              *seed,
		DevRatio:          *devRatio,
		MaxFPR:            *maxFPR,
		Selected:          selected,
		DevMetrics:        devMetrics,
		TestMetrics:       testMetrics,
		FullMetrics:       fullMetrics,
		FamilySummary:     summarizeFamilies(stats, selected),
		AlternativeSplits: altSplits,
		VTCoverage:        summarizeVTCoverage(stats, vtLookup.DirectKeys, vtLookup.IndexKeys),
		Ablations:         evaluateAblations(test, selected),
		DevSamples:        sampleNames(dev),
		TestSamples:       sampleNames(test),
		Errors:            errors,
		Analyzed:          stats,
	}

	if *baselineOutPath != "" {
		assignBaselineSplits(baselineRows, dev, test)
		if err := writeBaselineExport(*baselineOutPath, baselineRows); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write baseline export: %v\n", err)
			os.Exit(2)
		}
	}

	if err := writeJSON(*outPath, result); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write result JSON: %v\n", err)
		os.Exit(2)
	}

	if outputFormat == "json" {
		cliutil.WriteJSON(map[string]any{
			"command": "paperexp",
			"result_path": *outPath,
			"baseline_out": *baselineOutPath,
			"result": result,
		})
		return
	}

	fmt.Printf("Benchmark: %s\n", benchmarkSource)
	fmt.Printf("Analyzed: %d samples\n", len(stats))
	fmt.Printf("Dev/Test: %d / %d\n", len(dev), len(test))
	if len(errors) > 0 {
		fmt.Printf("Analysis errors/timeouts: %d\n", len(errors))
	}
	if len(result.FamilySummary) > 0 {
		fmt.Printf("Malicious families with VT metadata: %d\n", len(result.FamilySummary))
	}
	printVTCoverage(result.VTCoverage)
	fmt.Printf("Selected params: threshold=%.2f k=%.2f weights=[rule=%.2f attack=%.2f feature=%.2f formal=%.2f] floor_x=%.2f\n",
		selected.DecisionThreshold, selected.SigmoidSlope, selected.RuleWeight, selected.AttackWeight,
		selected.FeatureWeight, selected.FormalWeight, selected.FloorMultiplier)
	printMetrics("Dev", devMetrics)
	printMetrics("Test", testMetrics)
	printMetrics("Full replay", fullMetrics)
	printAlternativeSplits(result.AlternativeSplits)
	printAblations(result.Ablations)
	printFamilySummary(result.FamilySummary)
	fmt.Printf("Result JSON: %s\n", *outPath)
}

func loadBenchmarkSamples(root, manifestCSV string, refreshManifest bool) ([]string, string, error) {
	if manifestCSV != "" && refreshManifest {
		samples, err := scanBenchmarkSamples(root)
		if err != nil {
			return nil, "", err
		}
		if err := writeBenchmarkManifest(manifestCSV, samples); err != nil {
			return nil, "", err
		}
		return samples, manifestCSV, nil
	}

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

	samples, err := scanBenchmarkSamples(root)
	if err != nil {
		return nil, "", err
	}
	return samples, root, nil
}

func scanBenchmarkSamples(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	samples := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".lsp" || ext == ".fas" || ext == ".vlx" {
			samples = append(samples, filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(samples)
	return samples, nil
}

func writeBenchmarkManifest(path string, samples []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write([]string{"sample"}); err != nil {
		return err
	}
	for _, sample := range samples {
		if err := w.Write([]string{sample}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
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
		if strings.EqualFold(col, "sample") {
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

func analyzeSamples(a *analyzer.Analyzer, samples []string, vtLookup vtLookup, timeout time.Duration) ([]sampleStat, []baselineSample, []string) {
	stats := make([]sampleStat, 0, len(samples))
	baselineRows := make([]baselineSample, 0, len(samples))
	errors := []string{}
	startAll := time.Now()
	for i, sample := range samples {
		fmt.Fprintf(os.Stderr, "[paperexp] START %d/%d %s\n", i+1, len(samples), sample)
		sampleStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		res, err := a.AnalyzeFile(ctx, sample, false)
		cancel()
		sampleDur := time.Since(sampleStart)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[paperexp] ERROR %d/%d %s (%v): %v\n", i+1, len(samples), sample, sampleDur, err)
			errors = append(errors, fmt.Sprintf("%s: %v", sample, err))
			continue
		}
		if sampleDur > 2*time.Second {
			fmt.Fprintf(os.Stderr, "[paperexp] SLOW  %d/%d %s (%v)\n", i+1, len(samples), sample, sampleDur)
		}
		if res.ScoreResult == nil {
			fmt.Fprintf(os.Stderr, "[paperexp] ERROR %d/%d %s (%v): missing score result\n", i+1, len(samples), sample, sampleDur)
			errors = append(errors, fmt.Sprintf("%s: missing score result", sample))
			continue
		}
		ruleIDs := make([]string, 0, len(res.MatchedRules))
		matchedRules := make([]matchedRuleStat, 0, len(res.MatchedRules))
		for _, rule := range res.MatchedRules {
			ruleIDs = append(ruleIDs, rule.ID)
			matchedRules = append(matchedRules, matchedRuleStat{
				ID:       rule.ID,
				Severity: rule.Severity,
			})
		}
		sort.Strings(ruleIDs)

		hashes, hashErr := computeSampleHashes(sample)
		if hashErr != nil {
			errors = append(errors, fmt.Sprintf("%s: hash computation failed: %v", sample, hashErr))
		}
		vtInfo, vtMatchType := lookupVTInfo(hashes, vtLookup)

		stat := sampleStat{
			Sample:          sample,
			Label:           groundTruth(sample),
			InputType:       res.InputType,
			MD5:             hashes.MD5,
			SHA1:            hashes.SHA1,
			SHA256:          hashes.SHA256,
			VTMatchType:     vtMatchType,
			Family:          vtInfo.Family,
			FamilySource:    vtInfo.Source,
			VTLabel:         vtInfo.Label,
			VTNames:         vtInfo.PopularNames,
			RuleEvidence:    res.ScoreResult.EvidenceRule["malicious"],
			AttackEvidence:  res.ScoreResult.EvidenceAttack["malicious"],
			FeatureEvidence: res.ScoreResult.EvidenceFeature["malicious"],
			FormalEvidence:  res.ScoreResult.EvidenceFormal["combined"],
			ContextScore:    0.0,
			MatchedRuleIDs:  ruleIDs,
			MatchedRules:    matchedRules,
			CurrentRisk:     res.RiskScore,
			AnalysisMs:      res.Timing.TotalMs,
			ReadMs:          res.Timing.ReadMs,
			StageMs:         res.Timing.StageMs,
			FrontendMs:      res.Timing.FrontendMs,
			IRMs:            res.Timing.IRMs,
			FormalMs:        res.Timing.FormalMs,
			DetectionMs:     res.Timing.DetectionMs,
			EncodingMs:      res.Timing.EncodingMs,
			ReadDetailMs:    res.Timing.ReadDetailMs,
		}
		if res.ScoreResult.ContextScore != nil {
			stat.ContextScore = res.ScoreResult.ContextScore.FinalScore
		}
		stats = append(stats, stat)
		baselineRows = append(baselineRows, baselineSample{
			Sample:      sample,
			Label:       stat.Label,
			InputType:   res.InputType,
			Text:        normalizeBaselineText(res.Source),
			Semantic:    normalizeBaselineText(res.LLMEncoding),
			RuleIDsText: strings.Join(ruleIDs, " "),
		})
		elapsed := time.Since(startAll).Round(time.Millisecond)
		fmt.Fprintf(os.Stderr, "[paperexp] DONE  %d/%d %s (%v, elapsed=%v)\n", i+1, len(samples), sample, sampleDur.Round(time.Millisecond), elapsed)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Sample < stats[j].Sample })
	sort.Slice(baselineRows, func(i, j int) bool { return baselineRows[i].Sample < baselineRows[j].Sample })
	return stats, baselineRows, errors
}

func normalizeBaselineText(text string) string {
	text = strings.ReplaceAll(text, "\x00", " ")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSpace(text)
	return text
}

func assignBaselineSplits(rows []baselineSample, dev, test []sampleStat) {
	splits := make(map[string]string, len(dev)+len(test))
	for _, stat := range dev {
		splits[stat.Sample] = "dev"
	}
	for _, stat := range test {
		splits[stat.Sample] = "test"
	}
	for i := range rows {
		rows[i].Split = splits[rows[i].Sample]
	}
}

func writeBaselineExport(path string, rows []baselineSample) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func groundTruth(sample string) string {
	if strings.HasPrefix(filepath.Base(sample), "white_") {
		return "BENIGN"
	}
	return "MALICIOUS"
}

func computeSampleHashes(sample string) (sampleHashes, error) {
	f, err := os.Open(sample)
	if err != nil {
		return sampleHashes{}, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256), f); err != nil {
		return sampleHashes{}, err
	}
	return sampleHashes{
		MD5:    fmt.Sprintf("%x", hMD5.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", hSHA1.Sum(nil)),
		SHA256: fmt.Sprintf("%x", hSHA256.Sum(nil)),
	}, nil
}

func lookupVTInfo(h sampleHashes, vt vtLookup) (vtFamilyInfo, string) {
	keys := []string{strings.ToLower(h.SHA256), strings.ToLower(h.SHA1), strings.ToLower(h.MD5)}
	for _, key := range keys {
		if key == "" {
			continue
		}
		info, ok := vt.Families[key]
		if !ok {
			continue
		}
		matchType := ""
		if _, ok := vt.DirectKeys[key]; ok {
			matchType = "direct-json"
		} else if _, ok := vt.IndexKeys[key]; ok {
			matchType = "vt-index"
		}
		return info, matchType
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := vt.DirectKeys[key]; ok {
			return vtFamilyInfo{}, "direct-json"
		}
		if _, ok := vt.IndexKeys[key]; ok {
			return vtFamilyInfo{}, "vt-index"
		}
	}
	return vtFamilyInfo{}, ""
}

func stratifiedSplit(stats []sampleStat, devRatio float64, seed int64) ([]sampleStat, []sampleStat) {
	malicious := []sampleStat{}
	benign := []sampleStat{}
	for _, stat := range stats {
		if stat.Label == "BENIGN" {
			benign = append(benign, stat)
		} else {
			malicious = append(malicious, stat)
		}
	}

	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(malicious), func(i, j int) { malicious[i], malicious[j] = malicious[j], malicious[i] })
	rng.Shuffle(len(benign), func(i, j int) { benign[i], benign[j] = benign[j], benign[i] })

	devMal := splitCount(len(malicious), devRatio)
	devBen := splitCount(len(benign), devRatio)

	dev := append(append([]sampleStat{}, malicious[:devMal]...), benign[:devBen]...)
	test := append(append([]sampleStat{}, malicious[devMal:]...), benign[devBen:]...)
	sort.Slice(dev, func(i, j int) bool { return dev[i].Sample < dev[j].Sample })
	sort.Slice(test, func(i, j int) bool { return test[i].Sample < test[j].Sample })
	return dev, test
}

func evaluateAlternativeSplits(stats []sampleStat, cfg *config.Config, devRatio float64, seed int64, maxFPR float64) []splitResult {
	results := make([]splitResult, 0, 2)

	if dev, test := familyDisjointSplit(stats, devRatio, seed); len(dev) > 0 && len(test) > 0 {
		selected, devMetrics := calibrate(dev, cfg, maxFPR)
		results = append(results, splitResult{
			Name:        "family-disjoint",
			Params:      selected,
			DevMetrics:  devMetrics,
			TestMetrics: evaluate(test, selected),
			DevSamples:  sampleNames(dev),
			TestSamples: sampleNames(test),
		})
	}

	if dev, test := sourceDisjointSplit(stats, devRatio, seed); len(dev) > 0 && len(test) > 0 {
		selected, devMetrics := calibrate(dev, cfg, maxFPR)
		results = append(results, splitResult{
			Name:        "source-disjoint",
			Params:      selected,
			DevMetrics:  devMetrics,
			TestMetrics: evaluate(test, selected),
			DevSamples:  sampleNames(dev),
			TestSamples: sampleNames(test),
		})
	}

	return results
}

func familyDisjointSplit(stats []sampleStat, devRatio float64, seed int64) ([]sampleStat, []sampleStat) {
	maliciousGroups := make(map[string][]sampleStat)
	benign := make([]sampleStat, 0)
	for _, stat := range stats {
		if stat.Label == "BENIGN" {
			benign = append(benign, stat)
			continue
		}
		key := strings.TrimSpace(strings.ToLower(stat.Family))
		if key == "" {
			key = "singleton:" + strings.ToLower(filepath.Base(stat.Sample))
		}
		maliciousGroups[key] = append(maliciousGroups[key], stat)
	}

	rng := rand.New(rand.NewSource(seed + 17))
	maliciousKeys := make([]string, 0, len(maliciousGroups))
	for key := range maliciousGroups {
		maliciousKeys = append(maliciousKeys, key)
	}
	sort.Strings(maliciousKeys)
	rng.Shuffle(len(maliciousKeys), func(i, j int) { maliciousKeys[i], maliciousKeys[j] = maliciousKeys[j], maliciousKeys[i] })

	targetDevMal := splitCount(countLabel(stats, "MALICIOUS"), devRatio)
	dev := make([]sampleStat, 0, len(stats))
	test := make([]sampleStat, 0, len(stats))
	devMal := 0
	for _, key := range maliciousKeys {
		group := maliciousGroups[key]
		if devMal < targetDevMal {
			dev = append(dev, group...)
			devMal += len(group)
		} else {
			test = append(test, group...)
		}
	}

	rng.Shuffle(len(benign), func(i, j int) { benign[i], benign[j] = benign[j], benign[i] })
	targetDevBen := splitCount(len(benign), devRatio)
	dev = append(dev, benign[:targetDevBen]...)
	test = append(test, benign[targetDevBen:]...)

	sort.Slice(dev, func(i, j int) bool { return dev[i].Sample < dev[j].Sample })
	sort.Slice(test, func(i, j int) bool { return test[i].Sample < test[j].Sample })
	return dev, test
}

func sourceDisjointSplit(stats []sampleStat, devRatio float64, seed int64) ([]sampleStat, []sampleStat) {
	type grouped struct {
		key   string
		items []sampleStat
		mal   int
		ben   int
	}

	groupsByKey := make(map[string]*grouped)
	for _, stat := range stats {
		key := sourceGroupKey(stat)
		group := groupsByKey[key]
		if group == nil {
			group = &grouped{key: key}
			groupsByKey[key] = group
		}
		group.items = append(group.items, stat)
		if stat.Label == "BENIGN" {
			group.ben++
		} else {
			group.mal++
		}
	}

	groups := make([]*grouped, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].key < groups[j].key })
	rng := rand.New(rand.NewSource(seed + 43))
	rng.Shuffle(len(groups), func(i, j int) { groups[i], groups[j] = groups[j], groups[i] })

	targetDevMal := splitCount(countLabel(stats, "MALICIOUS"), devRatio)
	targetDevBen := splitCount(countLabel(stats, "BENIGN"), devRatio)
	dev := make([]sampleStat, 0, len(stats))
	test := make([]sampleStat, 0, len(stats))
	devMal, devBen := 0, 0

	for _, group := range groups {
		assignDev := chooseSourceGroupForDev(devMal, devBen, targetDevMal, targetDevBen, group.mal, group.ben)
		if assignDev {
			dev = append(dev, group.items...)
			devMal += group.mal
			devBen += group.ben
		} else {
			test = append(test, group.items...)
		}
	}

	if len(dev) == 0 || len(test) == 0 {
		return stratifiedSplit(stats, devRatio, seed+91)
	}

	sort.Slice(dev, func(i, j int) bool { return dev[i].Sample < dev[j].Sample })
	sort.Slice(test, func(i, j int) bool { return test[i].Sample < test[j].Sample })
	return dev, test
}

func chooseSourceGroupForDev(devMal, devBen, targetMal, targetBen, groupMal, groupBen int) bool {
	scoreIfDev := absInt((devMal+groupMal)-targetMal) + absInt((devBen+groupBen)-targetBen)
	scoreIfTest := absInt(devMal-targetMal) + absInt(devBen-targetBen)
	if scoreIfDev == scoreIfTest {
		if devMal < targetMal {
			return true
		}
		if devBen < targetBen {
			return true
		}
		return false
	}
	return scoreIfDev < scoreIfTest
}

func countLabel(stats []sampleStat, label string) int {
	total := 0
	for _, stat := range stats {
		if stat.Label == label {
			total++
		}
	}
	return total
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sourceGroupKey(stat sampleStat) string {
	base := strings.ToLower(filepath.Base(stat.Sample))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	for _, suffix := range []string{".acad", ".acaddoc", ".mnl", ".dcl"} {
		base = strings.TrimSuffix(base, suffix)
	}
	base = strings.TrimPrefix(base, "white_")
	base = strings.TrimSpace(base)
	if base == "" {
		return "sample:" + strings.ToLower(filepath.Base(stat.Sample))
	}

	tokens := splitGroupTokens(base)
	if len(tokens) == 0 {
		return "sample:" + base
	}
	filtered := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if token == "" || token == "white" {
			continue
		}
		filtered = append(filtered, token)
	}
	if len(filtered) == 0 {
		return "sample:" + base
	}
	for i, token := range filtered {
		if isHashLikeToken(token) {
			if i+1 < len(filtered) && !isHashLikeToken(filtered[i+1]) && !isGenericSourceToken(filtered[i+1]) {
				if i+2 < len(filtered) && !isHashLikeToken(filtered[i+2]) && !isGenericSourceToken(filtered[i+2]) {
					return "src:" + filtered[i+1] + "_" + filtered[i+2]
				}
				return "src:" + filtered[i+1]
			}
			return "hash:" + token[:minInt(16, len(token))]
		}
		if isGenericSourceToken(token) {
			continue
		}
		if i+1 < len(filtered) && !isHashLikeToken(filtered[i+1]) && !isGenericSourceToken(filtered[i+1]) {
			return "src:" + token + "_" + filtered[i+1]
		}
		return "src:" + token
	}
	return "sample:" + base
}

func splitGroupTokens(base string) []string {
	fields := strings.FieldsFunc(base, func(r rune) bool {
		switch r {
		case '_', '-', ' ', '.', '(', ')', '[', ']', '{', '}', '+':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func isHashLikeToken(token string) bool {
	if len(token) < 16 {
		return false
	}
	for _, r := range token {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func isGenericSourceToken(token string) bool {
	switch token {
	case "vt", "vtmsistake", "sample", "file", "plugin", "lisp", "lisps", "tool", "tools", "program", "programs":
		return true
	default:
		return false
	}
}

func splitCount(total int, ratio float64) int {
	if total <= 1 {
		return total
	}
	count := int(math.Round(float64(total) * ratio))
	if count < 1 {
		count = 1
	}
	if count >= total {
		count = total - 1
	}
	return count
}

func calibrate(dev []sampleStat, cfg *config.Config, maxFPR float64) (parameters, metrics) {
	baseFloors := cloneFloors(cfg.Scoring.RiskFloors)
	thresholds := []float64{0.45, 0.50, 0.55, 0.60, 0.65}
	slopes := []float64{3.0, 4.0, 5.0, 6.0}
	floorMultipliers := []float64{0.90, 1.00, 1.10}

	best := parameters{
		RuleWeight:        cfg.Scoring.RuleWeight,
		AttackWeight:      cfg.Scoring.AttackWeight,
		FeatureWeight:     cfg.Scoring.FeatureWeight,
		FormalWeight:      cfg.Scoring.FormalWeight,
		SigmoidSlope:      cfg.Scoring.SigmoidSlope,
		DecisionThreshold: cfg.Scoring.DecisionThreshold,
		FloorMultiplier:   1.0,
		RiskFloors:        baseFloors,
		RuleMultipliers:   defaultRuleMultipliers(),
	}
	bestMetrics := evaluate(dev, best)
	bestConstrained := bestMetrics.FPR <= maxFPR

	ruleWeights := []float64{0.25, 0.30, 0.35, 0.40}
	attackWeights := []float64{0.20, 0.25, 0.30}
	featureWeights := []float64{0.20, 0.25, 0.30}

	for _, rw := range ruleWeights {
		for _, aw := range attackWeights {
			for _, fw := range featureWeights {
				formalW := 1.0 - rw - aw - fw
				if formalW < 0.05 || formalW > 0.30 {
					continue
				}
				for _, slope := range slopes {
					for _, threshold := range thresholds {
						for _, mult := range floorMultipliers {
							candidate := parameters{
								RuleWeight:        rw,
								AttackWeight:      aw,
								FeatureWeight:     fw,
								FormalWeight:      formalW,
								SigmoidSlope:      slope,
								DecisionThreshold: threshold,
								FloorMultiplier:   mult,
								RiskFloors:        scaledFloors(baseFloors, mult),
								RuleMultipliers:   defaultRuleMultipliers(),
							}
							m := evaluate(dev, candidate)
							constrained := m.FPR <= maxFPR
							if betterCandidate(m, constrained, bestMetrics, bestConstrained) {
								best = candidate
								bestMetrics = m
								bestConstrained = constrained
							}
						}
					}
				}
			}
		}
	}

	best, bestMetrics = calibrateRuleMultipliers(dev, best, bestMetrics, maxFPR)
	return best, bestMetrics
}

func defaultRuleMultipliers() map[string]float64 {
	return map[string]float64{
		"COM_DROPPER_001":  1.0,
		"FINDCOPY_001":     1.0,
		"NET_DROPPER_001":  1.0,
		"NET_STUB_001":     1.0,
		"NETWORK_001":      1.0,
		"REC_FAS_PROP_001": 1.0,
		"REGISTRY_001":     1.0,
	}
}

func calibrateRuleMultipliers(dev []sampleStat, base parameters, baseMetrics metrics, maxFPR float64) (parameters, metrics) {
	best := cloneParameters(base)
	bestMetrics := baseMetrics
	bestConstrained := bestMetrics.FPR <= maxFPR
	candidateValues := []float64{0.40, 0.55, 0.70, 0.85, 1.00, 1.15}
	targetRules := orderedRuleMultiplierKeys(best.RuleMultipliers)

	for pass := 0; pass < 3; pass++ {
		improved := false
		for _, ruleID := range targetRules {
			localBest := best
			localMetrics := bestMetrics
			localConstrained := bestConstrained
			current := best.RuleMultipliers[ruleID]

			for _, mult := range candidateValues {
				if mult == current {
					continue
				}
				candidate := cloneParameters(best)
				candidate.RuleMultipliers[ruleID] = mult
				m := evaluate(dev, candidate)
				constrained := m.FPR <= maxFPR
				if betterCandidate(m, constrained, localMetrics, localConstrained) {
					localBest = candidate
					localMetrics = m
					localConstrained = constrained
				}
			}

			if localBest.RuleMultipliers[ruleID] != best.RuleMultipliers[ruleID] {
				best = localBest
				bestMetrics = localMetrics
				bestConstrained = localConstrained
				improved = true
			}
		}
		if !improved {
			break
		}
	}

	return best, bestMetrics
}

func evaluateAblations(stats []sampleStat, selected parameters) []ablationResult {
	configs := []ablationResult{
		{Name: "Feature-Only", Params: featureOnlyParameters(selected)},
		{Name: "Rule+ATT&CK Only", Params: ruleAttackOnlyParameters(selected)},
		{Name: "No-Floor", Params: noFloorParameters(selected)},
		{Name: "No-Formal", Params: noFormalParameters(selected)},
		{Name: "Full", Params: cloneParameters(selected)},
	}
	for i := range configs {
		configs[i].Metrics = evaluate(stats, configs[i].Params)
	}
	return configs
}

func featureOnlyParameters(base parameters) parameters {
	p := cloneParameters(base)
	p.RuleWeight = 0
	p.AttackWeight = 0
	p.FeatureWeight = 1
	p.FormalWeight = 0
	p.RiskFloors = map[string]float64{}
	return p
}

func ruleAttackOnlyParameters(base parameters) parameters {
	p := cloneParameters(base)
	total := base.RuleWeight + base.AttackWeight
	if total <= 0 {
		p.RuleWeight = 0.5
		p.AttackWeight = 0.5
	} else {
		p.RuleWeight = base.RuleWeight / total
		p.AttackWeight = base.AttackWeight / total
	}
	p.FeatureWeight = 0
	p.FormalWeight = 0
	p.RiskFloors = map[string]float64{}
	return p
}

func noFloorParameters(base parameters) parameters {
	p := cloneParameters(base)
	p.RiskFloors = map[string]float64{}
	return p
}

func noFormalParameters(base parameters) parameters {
	p := cloneParameters(base)
	total := base.RuleWeight + base.AttackWeight + base.FeatureWeight
	if total <= 0 {
		return p
	}
	p.RuleWeight = base.RuleWeight / total
	p.AttackWeight = base.AttackWeight / total
	p.FeatureWeight = base.FeatureWeight / total
	p.FormalWeight = 0
	return p
}

func orderedRuleMultiplierKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cloneParameters(src parameters) parameters {
	dst := src
	dst.RiskFloors = cloneFloors(src.RiskFloors)
	if src.RuleMultipliers != nil {
		dst.RuleMultipliers = make(map[string]float64, len(src.RuleMultipliers))
		for k, v := range src.RuleMultipliers {
			dst.RuleMultipliers[k] = v
		}
	}
	return dst
}

func betterCandidate(m metrics, constrained bool, best metrics, bestConstrained bool) bool {
	if constrained != bestConstrained {
		return constrained
	}
	if m.F1 != best.F1 {
		return m.F1 > best.F1
	}
	if m.ACC != best.ACC {
		return m.ACC > best.ACC
	}
	return m.FPR < best.FPR
}

func evaluate(stats []sampleStat, params parameters) metrics {
	var tp, tn, fp, fn int
	for _, stat := range stats {
		risk := scoreSample(stat, params)
		predMalicious := risk >= params.DecisionThreshold
		if stat.Label == "BENIGN" {
			if predMalicious {
				fp++
			} else {
				tn++
			}
		} else {
			if predMalicious {
				tp++
			} else {
				fn++
			}
		}
	}

	precision := safeDiv(float64(tp), float64(tp+fp))
	recall := safeDiv(float64(tp), float64(tp+fn))
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return metrics{
		TP:        tp,
		TN:        tn,
		FP:        fp,
		FN:        fn,
		Precision: precision,
		Recall:    recall,
		F1:        f1,
		FPR:       safeDiv(float64(fp), float64(fp+tn)),
		ACC:       safeDiv(float64(tp+tn), float64(tp+tn+fp+fn)),
		Total:     tp + tn + fp + fn,
	}
}

func scoreSample(stat sampleStat, params parameters) float64 {
	ruleEvidence := adjustedRuleEvidence(stat, params.RuleMultipliers)
	ruleWeight, attackWeight, featureWeight, formalWeight :=
		redistributeFormalWeight(params.RuleWeight, params.AttackWeight, params.FeatureWeight, params.FormalWeight, stat.FormalEvidence)
	combined := ruleWeight*ruleEvidence +
		attackWeight*stat.AttackEvidence +
		featureWeight*stat.FeatureEvidence +
		formalWeight*stat.FormalEvidence

	logit := params.SigmoidSlope * (combined - 0.5)
	risk := 1.0 / (1.0 + math.Exp(-logit))
	if stat.ContextScore > 0.7 {
		risk = math.Min(1.0, risk*1.2)
	}
	for _, ruleID := range stat.MatchedRuleIDs {
		if floor, ok := params.RiskFloors[ruleID]; ok {
			risk = math.Max(risk, floor)
		}
	}
	return risk
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

func adjustedRuleEvidence(stat sampleStat, multipliers map[string]float64) float64 {
	if len(stat.MatchedRules) == 0 || len(multipliers) == 0 {
		return stat.RuleEvidence
	}
	total := 0.0
	count := 0.0
	for _, rule := range stat.MatchedRules {
		mult := 1.0
		if v, ok := multipliers[rule.ID]; ok {
			mult = v
		}
		total += rule.Severity * mult
		count++
	}
	if count == 0 {
		return stat.RuleEvidence
	}
	return total / count
}

func sampleNames(stats []sampleStat) []string {
	names := make([]string, 0, len(stats))
	for _, stat := range stats {
		names = append(names, stat.Sample)
	}
	return names
}

func cloneFloors(src map[string]float64) map[string]float64 {
	dst := make(map[string]float64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func scaledFloors(src map[string]float64, scale float64) map[string]float64 {
	dst := make(map[string]float64, len(src))
	for k, v := range src {
		dst[k] = math.Min(1.0, v*scale)
	}
	return dst
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func printMetrics(name string, m metrics) {
	fmt.Printf("%s: TP=%d FN=%d TN=%d FP=%d | TPR=%.2f%% FPR=%.2f%% ACC=%.2f%% F1=%.4f\n",
		name, m.TP, m.FN, m.TN, m.FP, m.Recall*100, m.FPR*100, m.ACC*100, m.F1)
}

func printAblations(rows []ablationResult) {
	if len(rows) == 0 {
		return
	}
	fmt.Println("Ablations:")
	for _, row := range rows {
		printMetrics("  "+row.Name, row.Metrics)
	}
}

func printAlternativeSplits(rows []splitResult) {
	if len(rows) == 0 {
		return
	}
	fmt.Println("Alternative splits:")
	for _, row := range rows {
		printMetrics("  "+row.Name, row.TestMetrics)
	}
}

func loadVTMetadata(dir, indexPath string) (vtLookup, error) {
	out := vtLookup{
		Families:   map[string]vtFamilyInfo{},
		DirectKeys: map[string]struct{}{},
		IndexKeys:  map[string]struct{}{},
	}

	if dir != "" {
		info, err := os.Stat(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				return vtLookup{}, err
			}
		} else {
			if !info.IsDir() {
				return vtLookup{}, fmt.Errorf("vt metadata path is not a directory: %s", dir)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return vtLookup{}, err
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".txt" {
					continue
				}
				path := filepath.Join(dir, entry.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					return vtLookup{}, err
				}
				var env vtFileEnvelope
				if err := json.Unmarshal(data, &env); err != nil {
					return vtLookup{}, fmt.Errorf("parse %s: %w", path, err)
				}
				md5 := strings.ToLower(strings.TrimSpace(env.Data.Attributes.MD5))
				sha1 := strings.ToLower(strings.TrimSpace(env.Data.Attributes.SHA1))
				sha := strings.ToLower(strings.TrimSpace(env.Data.Attributes.SHA256))
				if md5 == "" && sha1 == "" && sha == "" {
					sha = strings.TrimSuffix(strings.ToLower(entry.Name()), ".txt")
				}
				if md5 == "" && sha1 == "" && sha == "" {
					continue
				}
				for _, key := range []string{md5, sha1, sha} {
					if key == "" {
						continue
					}
					out.DirectKeys[key] = struct{}{}
					out.IndexKeys[key] = struct{}{}
				}
				label := strings.TrimSpace(env.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel)
				names := make([]string, 0, len(env.Data.Attributes.PopularThreatClassification.PopularThreatName))
				for _, n := range env.Data.Attributes.PopularThreatClassification.PopularThreatName {
					if strings.TrimSpace(n.Value) != "" {
						names = append(names, strings.ToLower(strings.TrimSpace(n.Value)))
					}
				}
				family := normalizeFamily(label, names)
				if family != "" {
					info := vtFamilyInfo{
						Family:       family,
						Label:        label,
						PopularNames: names,
						Source:       "virustotal-popular-threat",
					}
					for _, key := range []string{md5, sha1, sha} {
						if key != "" {
							out.Families[key] = info
						}
					}
				}
			}
			out.Dir = dir
		}
	}

	if indexPath == "" {
		return out, nil
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return vtLookup{}, err
	}
	var idx vtIndexFile
	if err := json.Unmarshal(data, &idx); err != nil {
		return vtLookup{}, fmt.Errorf("parse %s: %w", indexPath, err)
	}
	for sha, sample := range idx.Samples {
		sha = strings.ToLower(strings.TrimSpace(sha))
		if sha != "" {
			out.IndexKeys[sha] = struct{}{}
		}
		sha1 := strings.ToLower(strings.TrimSpace(sample.SHA256))
		_ = sha1
		md5 := strings.ToLower(strings.TrimSpace(sample.MD5))
		if md5 != "" {
			out.IndexKeys[md5] = struct{}{}
		}
		if strings.TrimSpace(sample.SHA256) != "" {
			out.IndexKeys[strings.ToLower(strings.TrimSpace(sample.SHA256))] = struct{}{}
		}
		if sha == "" || sample.Malicious <= 0 || len(sample.Engines) == 0 {
			continue
		}
		if _, exists := out.Families[sha]; exists {
			continue
		}
		label, names := summarizeEngineLabels(sample.Engines)
		family := normalizeFamily(label, names)
		if family == "" {
			continue
		}
		info := vtFamilyInfo{
			Family:       family,
			Label:        label,
			PopularNames: names,
			Source:       "vt-index-engines",
		}
		for _, key := range []string{md5, sha} {
			if key != "" {
				out.Families[key] = info
			}
		}
	}
	out.Index = indexPath
	return out, nil
}

func summarizeEngineLabels(engines map[string]vtEngineDetection) (string, []string) {
	counts := make(map[string]int)
	rawCounts := make(map[string]int)
	for _, det := range engines {
		if det.Category != "malicious" && det.Category != "suspicious" {
			continue
		}
		result := strings.ToLower(strings.TrimSpace(det.Result))
		if result == "" {
			continue
		}
		rawCounts[result]++
		for _, token := range tokenizeDetection(result) {
			if isFamilyNoise(token) {
				continue
			}
			counts[token]++
		}
	}
	type kv struct {
		Key   string
		Count int
	}
	rawTop := make([]kv, 0, len(rawCounts))
	for k, v := range rawCounts {
		rawTop = append(rawTop, kv{Key: k, Count: v})
	}
	sort.Slice(rawTop, func(i, j int) bool {
		if rawTop[i].Count != rawTop[j].Count {
			return rawTop[i].Count > rawTop[j].Count
		}
		return rawTop[i].Key < rawTop[j].Key
	})
	names := make([]string, 0, 5)
	for i := 0; i < len(rawTop) && i < 5; i++ {
		names = append(names, rawTop[i].Key)
	}
	bestLabel := ""
	bestCount := 0
	for token, count := range counts {
		if count > bestCount || (count == bestCount && token < bestLabel) {
			bestLabel = token
			bestCount = count
		}
	}
	return bestLabel, names
}

func tokenizeDetection(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func isFamilyNoise(token string) bool {
	if len(token) <= 1 {
		return true
	}
	if _, err := fmt.Sscanf(token, "%d", new(int)); err == nil {
		return true
	}
	switch token {
	case "trojan", "worm", "virus", "malware", "generic", "heur", "heuristic", "script", "gen",
		"variant", "agent", "downloader", "loader", "packed", "application", "win32", "w32",
		"acad", "autocad", "alisp", "lisp", "fas", "fascript", "trj", "classic", "suspicious",
		"unsafe", "unknown", "unclassifiedmalware", "securityrisk", "exploit", "als", "acm",
		"nil", "nim", "naa", "asm", "ai", "score", "probably":
		return true
	}
	return false
}

func normalizeFamily(label string, names []string) string {
	counts := make(map[string]int)
	label = strings.ToLower(strings.TrimSpace(label))
	if label != "" {
		for _, token := range tokenizeDetection(label) {
			if isFamilyNoise(token) {
				continue
			}
			counts[token] += 3
		}
	}
	for _, name := range names {
		for _, token := range tokenizeDetection(name) {
			if isFamilyNoise(token) {
				continue
			}
			counts[token]++
		}
	}
	best := ""
	bestCount := 0
	for token, count := range counts {
		if count > bestCount || (count == bestCount && token < best) {
			best = token
			bestCount = count
		}
	}
	return best
}

func summarizeFamilies(stats []sampleStat, params parameters) []familyStat {
	type accum struct {
		source  string
		vtLabel string
		samples []string
		tp      int
		fn      int
	}
	byFamily := make(map[string]*accum)
	for _, stat := range stats {
		if stat.Label != "MALICIOUS" || stat.Family == "" {
			continue
		}
		a := byFamily[stat.Family]
		if a == nil {
			a = &accum{source: stat.FamilySource, vtLabel: stat.VTLabel}
			byFamily[stat.Family] = a
		}
		a.samples = append(a.samples, stat.Sample)
		if scoreSample(stat, params) >= params.DecisionThreshold {
			a.tp++
		} else {
			a.fn++
		}
	}
	out := make([]familyStat, 0, len(byFamily))
	for family, a := range byFamily {
		total := a.tp + a.fn
		recall := 0.0
		if total > 0 {
			recall = float64(a.tp) / float64(total)
		}
		sort.Strings(a.samples)
		out = append(out, familyStat{
			Family:  family,
			Source:  a.source,
			VTLabel: a.vtLabel,
			Total:   total,
			TP:      a.tp,
			FN:      a.fn,
			Recall:  recall,
			Samples: a.samples,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Family < out[j].Family
	})
	return out
}

func printFamilySummary(families []familyStat) {
	if len(families) == 0 {
		return
	}
	limit := len(families)
	if limit > 8 {
		limit = 8
	}
	fmt.Println("Top malicious families:")
	for i := 0; i < limit; i++ {
		f := families[i]
		fmt.Printf("  %s: TP=%d FN=%d recall=%.2f%% n=%d\n", f.Family, f.TP, f.FN, f.Recall*100, f.Total)
	}
}

func summarizeVTCoverage(stats []sampleStat, directKeys, indexKeys map[string]struct{}) vtCoverage {
	type stemCoverage struct {
		direct bool
		index  bool
	}
	coverage := vtCoverage{}
	byStem := make(map[string]*stemCoverage)
	for _, stat := range stats {
		if stat.Label != "MALICIOUS" {
			continue
		}
		coverage.MaliciousTotal++
		stem, direct, index := classifyVTMatch(stat, directKeys, indexKeys)
		if direct {
			coverage.DirectJSONSamples++
		} else if index {
			coverage.IndexOnlySamples++
		} else {
			coverage.UnmatchedSamples++
			coverage.UnmatchedExamples = append(coverage.UnmatchedExamples, stat.Sample)
		}
		entry := byStem[stem]
		if entry == nil {
			entry = &stemCoverage{}
			byStem[stem] = entry
		}
		entry.direct = entry.direct || direct
		entry.index = entry.index || index
	}
	coverage.UniqueMaliciousStems = len(byStem)
	for _, entry := range byStem {
		if entry.direct {
			coverage.DirectJSONStems++
		} else if entry.index {
			coverage.IndexOnlyStems++
		} else {
			coverage.UnmatchedStems++
		}
	}
	sort.Strings(coverage.UnmatchedExamples)
	return coverage
}

func classifyVTMatch(stat sampleStat, directKeys, indexKeys map[string]struct{}) (string, bool, bool) {
	base := strings.ToLower(filepath.Base(stat.Sample))
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	root := strings.Split(stem, ".")[0]
	direct := false
	index := false
	for _, key := range []string{strings.ToLower(stat.MD5), strings.ToLower(stat.SHA1), strings.ToLower(stat.SHA256)} {
		if key == "" {
			continue
		}
		if _, ok := directKeys[key]; ok {
			direct = true
		}
		if _, ok := indexKeys[key]; ok {
			index = true
		}
	}
	return root, direct, index
}

func printVTCoverage(c vtCoverage) {
	if c.MaliciousTotal == 0 {
		return
	}
	fmt.Printf("VT coverage: direct-json=%d, index-only=%d, unmatched=%d (malicious payloads)\n",
		c.DirectJSONSamples, c.IndexOnlySamples, c.UnmatchedSamples)
	fmt.Printf("VT coverage unique stems: direct-json=%d, index-only=%d, unmatched=%d\n",
		c.DirectJSONStems, c.IndexOnlyStems, c.UnmatchedStems)
}

func writeJSON(path string, value interface{}) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
