package analyzer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/adapter"
	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/deobfuscation"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/graph"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/llm"
	"github.com/evilcad/cadscanner/pkg/normalizer"
	"github.com/evilcad/cadscanner/pkg/parser"
	"github.com/evilcad/cadscanner/pkg/scoring"
)

// AnalysisResult represents the complete analysis result.
// Fields are grouped by pipeline stage; each stage owns its own result type.
type AnalysisResult struct {
	// --- Final verdict ---
	Filepath            string
	InputType           string
	IsMalicious         bool
	MaliciousConfidence float64
	RiskScore           float64
	RuleVerdict         string
	FinalVerdict        string
	DecisionAgreement   bool
	FusionSummary       string

	// --- Front-end layer ---
	ASTCount        int
	NormalizedCount int
	Source          string

	// --- IR layer ---
	IRFunctions       map[string]interface{}
	AllEffects        []ir.IREffect
	LiftedEffects     []ir.LiftedEffect
	FunctionSummaries map[string]*ir.FunctionSummary
	InferredBehaviors map[string][]string

	// --- Formal / graph layer ---
	SCCResults          []*graph.SCCResult
	PropagationClosures map[string]*graph.PropagationClosure
	Motifs              []*graph.BehaviorMotif
	FormalScoreResult   *scoring.FormalScoreResult
	PredicateResults    map[string]*graph.PredicateResult

	// --- Compatibility fields (mapped from internal types for JSON/CLI compat) ---
	SynthesizedBehaviors []SynthesizedBehaviorCompat

	// --- Detection / scoring layer ---
	AttackResult *detector.AttackResult
	MatchedRules []detector.MatchedRule
	ScoreResult  *scoring.ScoreResult

	// --- Encoding layer ---
	LLMEncoding string
	LLMAnalysis *llm.SemanticAnalysis

	// --- Deobfuscation layer ---
	ObfuscationPatterns []deobfuscation.ObfuscationPattern

	// --- Adapter metadata ---
	FASMeta map[string]interface{}
	VLXMeta map[string]interface{}

	// --- Timing (milliseconds) ---
	Timing AnalysisTiming
}

// AnalysisTiming exposes per-file timing breakdowns in milliseconds for
// evaluation, reporting, and experiment reproducibility.
type AnalysisTiming struct {
	TotalMs      float64            `json:"total_ms"`
	ReadMs       float64            `json:"read_ms"`
	StageMs      map[string]float64 `json:"stage_ms,omitempty"`
	FrontendMs   map[string]float64 `json:"frontend_ms,omitempty"`
	IRMs         map[string]float64 `json:"ir_ms,omitempty"`
	FormalMs     map[string]float64 `json:"formal_ms,omitempty"`
	DetectionMs  map[string]float64 `json:"detection_ms,omitempty"`
	EncodingMs   map[string]float64 `json:"encoding_ms,omitempty"`
	ReadDetailMs map[string]float64 `json:"read_detail_ms,omitempty"`
}

// SynthesizedBehaviorCompat preserves the old JSON field shape for backward compatibility.
// It is mapped from graph.BehaviorMotif at the DTO boundary only.
type SynthesizedBehaviorCompat struct {
	Behavior   string  `json:"Behavior"`
	Confidence float64 `json:"Confidence"`
	Evidence   string  `json:"Evidence"`
	ProofType  string  `json:"ProofType"`
}

// Analyzer is a thin pipeline orchestrator. It holds only configuration
// and stateless factories; all stateful components are created fresh per
// AnalyzeFile call to prevent cross-file state pollution.
type Analyzer struct {
	config     *config.Config
	fasAdapter *adapter.FASAdapter
	vlxAdapter *adapter.VLXAdapter
	vbaAdapter *adapter.VBAAdapter
	parser     *parser.Parser     // stateless, safe to reuse
	detector   *detector.Detector // holds config only, safe to reuse
	scorer     *scoring.Scorer    // holds config only, safe to reuse
}

// New creates a new analyzer.
func New(cfg *config.Config) (*Analyzer, error) {
	p, err := parser.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	return &Analyzer{
		config:     cfg,
		fasAdapter: adapter.NewFASAdapter(),
		vlxAdapter: adapter.NewVLXAdapter(),
		vbaAdapter: adapter.NewVBAAdapter(),
		parser:     p,
		detector:   detector.New(cfg),
		scorer:     scoring.New(cfg),
	}, nil
}

// AnalyzeFile analyzes a single file by running the pipeline stages.
// Stateful components (Normalizer, IRBuilder, PatternMatcher) are created
// fresh each call to prevent cross-file state pollution.
// The analysis respects context cancellation for proper timeout control.
func (a *Analyzer) AnalyzeFile(ctx context.Context, filepath string, verbose bool) (*AnalysisResult, error) {
	pipeCtx, totalTime, err := a.AnalyzePipeline(ctx, filepath, verbose)
	if err != nil {
		return nil, err
	}
	return a.assembleResult(filepath, pipeCtx, totalTime), nil
}

// AnalyzePipeline runs the full analysis pipeline and returns the populated
// PipelineContext plus total elapsed time. This is intended for experiments
// that need to replay downstream stages on the recovered analysis surface
// without re-implementing the front-end and IR pipeline.
func (a *Analyzer) AnalyzePipeline(ctx context.Context, filepath string, verbose bool) (*PipelineContext, time.Duration, error) {
	analyzeStart := time.Now()

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("analysis cancelled: %w", err)
	}

	// Read and adapt file
	start := time.Now()
	source, analysisSource, inputType, fasMeta, vlxMeta, err := a.readFile(filepath)
	if err != nil {
		return nil, 0, err
	}
	readTime := time.Since(start)

	pipeCtx := &PipelineContext{
		Filepath:        filepath,
		Source:          source,
		AnalysisSource:  analysisSource,
		InputType:       inputType,
		FASMeta:         fasMeta,
		VLXMeta:         vlxMeta,
		StageTiming:     make(map[string]time.Duration),
		FrontendTiming:  make(map[string]time.Duration),
		IRTiming:        make(map[string]time.Duration),
		FormalTiming:    make(map[string]time.Duration),
		DetectionTiming: make(map[string]time.Duration),
		EncodingTiming:  make(map[string]time.Duration),
		ReadTiming:      make(map[string]time.Duration),
	}
	pipeCtx.ReadTiming["total"] = readTime

	// Build fresh pipeline stages per call — stateful components are not shared
	stages := []Stage{
		NewFrontendStage(a.config, a.parser, normalizer.NewNormalizer(), deobfuscation.NewPatternMatcher()),
		NewIRStage(ir.NewBuilder()),
		NewFormalStage(a.config),
		NewDetectionStage(a.config, a.detector, a.scorer),
		NewEncodingStage(a.config),
	}

	// Run pipeline stages sequentially with context checking and timing
	for _, stage := range stages {
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("analysis cancelled at %s stage: %w", stage.Name(), err)
		}
		start := time.Now()
		if err := stage.Run(ctx, pipeCtx); err != nil {
			return nil, 0, fmt.Errorf("%s stage: %w", stage.Name(), err)
		}
		pipeCtx.StageTiming[stage.Name()] = time.Since(start)
	}

	// Print timing breakdown if verbose mode or slow analysis
	stagesTime := pipeCtx.StageTiming["frontend"] + pipeCtx.StageTiming["ir"] +
		pipeCtx.StageTiming["formal"] + pipeCtx.StageTiming["detection"] + pipeCtx.StageTiming["encoding"]
	totalTime := time.Since(analyzeStart)
	if debugutil.TimingEnabled() && (verbose || totalTime > 5*time.Second) {
		fmt.Fprintf(os.Stderr, "[TIMING] %s: total=%v | read=%v frontend=%v ir=%v formal=%v detection=%v encoding=%v\n",
			filepath, totalTime,
			readTime,
			pipeCtx.StageTiming["frontend"],
			pipeCtx.StageTiming["ir"],
			pipeCtx.StageTiming["formal"],
			pipeCtx.StageTiming["detection"],
			pipeCtx.StageTiming["encoding"])
		fmt.Fprintf(os.Stderr, "  [PIPELINE-BREAKDOWN] analyze=%v read=%v stages=%v frontend=%v ir=%v formal=%v detection=%v encoding=%v\n",
			totalTime,
			readTime,
			stagesTime,
			pipeCtx.StageTiming["frontend"],
			pipeCtx.StageTiming["ir"],
			pipeCtx.StageTiming["formal"],
			pipeCtx.StageTiming["detection"],
			pipeCtx.StageTiming["encoding"])
	}

	return pipeCtx, totalTime, nil
}

// assembleResult copies pipeline context into the public AnalysisResult.
func (a *Analyzer) assembleResult(filepath string, ctx *PipelineContext, totalTime time.Duration) *AnalysisResult {
	result := &AnalysisResult{
		Filepath:        filepath,
		InputType:       ctx.InputType,
		Source:          ctx.Source,
		FASMeta:         ctx.FASMeta,
		VLXMeta:         ctx.VLXMeta,
		ASTCount:        len(ctx.AST),
		NormalizedCount: len(ctx.Normalized),

		AllEffects:        ctx.IRResult.Effects,
		LiftedEffects:     ctx.IRResult.LiftedEffects,
		FunctionSummaries: ctx.IRResult.FunctionSummaries,
		InferredBehaviors: extractInferredBehaviors(ctx.IRResult.FunctionSummaries),

		SCCResults:          ctx.SCCResults,
		PropagationClosures: ctx.PropagationClosures,
		Motifs:              ctx.Motifs,
		FormalScoreResult:   ctx.FormalScoreResult,
		PredicateResults:    ctx.PredicateResults,

		AttackResult: ctx.DetectResult.AttackResult,
		MatchedRules: ctx.DetectResult.MatchedRules,
		ScoreResult:  ctx.ScoreResult,

		LLMEncoding:         ctx.LLMEncoding,
		LLMAnalysis:         ctx.LLMResult,
		ObfuscationPatterns: ctx.ObfPatterns,

		SynthesizedBehaviors: mapMotifsToCompat(ctx.Motifs),
		Timing: AnalysisTiming{
			TotalMs:      durationMs(totalTime),
			ReadMs:       durationMs(ctx.ReadTiming["total"]),
			StageMs:      durationMapMs(ctx.StageTiming),
			FrontendMs:   durationMapMs(ctx.FrontendTiming),
			IRMs:         durationMapMs(ctx.IRTiming),
			FormalMs:     durationMapMs(ctx.FormalTiming),
			DetectionMs:  durationMapMs(ctx.DetectionTiming),
			EncodingMs:   durationMapMs(ctx.EncodingTiming),
			ReadDetailMs: durationMapMs(ctx.ReadTiming),
		},
	}

	// IR functions as map[string]interface{} for backward compatibility
	result.IRFunctions = make(map[string]interface{}, len(ctx.IRResult.Functions))
	for name, fn := range ctx.IRResult.Functions {
		result.IRFunctions[name] = fn
	}

	// Final verdict - use Scoring.DecisionThreshold as single source of truth
	result.MaliciousConfidence = ctx.ScoreResult.MaliciousPosterior
	result.RiskScore = ctx.ScoreResult.RiskScore
	result.IsMalicious = result.MaliciousConfidence >= a.config.Scoring.DecisionThreshold
	if result.IsMalicious {
		result.RuleVerdict = "MALICIOUS"
	} else {
		result.RuleVerdict = "BENIGN"
	}
	result.FinalVerdict = result.RuleVerdict
	result.DecisionAgreement = true
	result.FusionSummary = "rule-only"
	if ctx.LLMResult != nil {
		result.FinalVerdict, result.DecisionAgreement, result.FusionSummary = fuseVerdicts(
			result.RuleVerdict,
			result.RiskScore,
			a.config.Scoring.DecisionThreshold,
			ctx.LLMResult,
			a.config.LLM.EnableFusion,
		)
	}
	result.IsMalicious = result.FinalVerdict == "MALICIOUS"

	return result
}

func fuseVerdicts(ruleVerdict string, riskScore float64, threshold float64, analysis *llm.SemanticAnalysis, enableFusion bool) (string, bool, string) {
	if analysis == nil || analysis.SemanticLabel == "" {
		return ruleVerdict, true, "rule-only"
	}

	semanticVerdict := strings.ToUpper(string(analysis.SemanticLabel))
	agreement := semanticVerdict == ruleVerdict
	if !enableFusion {
		return ruleVerdict, agreement, "llm-disabled-fusion"
	}
	if agreement {
		return ruleVerdict, true, "rule-and-llm-agree"
	}

	// Conservative fusion for operational safety: preserve strong rule decisions,
	// otherwise surface disagreement as SUSPICIOUS for analyst review.
	if ruleVerdict == "MALICIOUS" && riskScore >= threshold+0.15 {
		return "MALICIOUS", false, "rule-dominant-strong-malicious"
	}
	if semanticVerdict == "MALICIOUS" && analysis.Confidence >= 0.90 && riskScore >= threshold*0.6 {
		return "MALICIOUS", false, "semantic-escalation"
	}
	return "SUSPICIOUS", false, "rule-llm-disagreement"
}

func durationMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func durationMapMs(src map[string]time.Duration) map[string]float64 {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]float64, len(src))
	for k, v := range src {
		dst[k] = durationMs(v)
	}
	return dst
}

// mapMotifsToCompat maps graph.BehaviorMotif to the old SynthesizedBehaviors JSON shape
// for backward compatibility with existing CLI/JSON consumers.
func mapMotifsToCompat(motifs []*graph.BehaviorMotif) []SynthesizedBehaviorCompat {
	result := make([]SynthesizedBehaviorCompat, 0, len(motifs))
	for _, m := range motifs {
		evidence := ""
		if len(m.Nodes) > 0 {
			evidence = "nodes: " + fmt.Sprintf("%v", m.Nodes)
		}
		result = append(result, SynthesizedBehaviorCompat{
			Behavior:   string(m.MotifType),
			Confidence: m.Confidence,
			Evidence:   evidence,
			ProofType:  "motif",
		})
	}
	return result
}

// extractInferredBehaviors converts FunctionSummary.InferredBehaviors to a simple map.
func extractInferredBehaviors(summaries map[string]*ir.FunctionSummary) map[string][]string {
	result := make(map[string][]string)
	for funcName, summary := range summaries {
		behaviors := make([]string, 0, len(summary.InferredBehaviors))
		for behavior := range summary.InferredBehaviors {
			behaviors = append(behaviors, behavior)
		}
		if len(behaviors) > 0 {
			result[funcName] = behaviors
		}
	}
	return result
}

// readFile reads the source file
func (a *Analyzer) readFile(filepath string) (string, string, string, map[string]interface{}, map[string]interface{}, error) {
	start := time.Now()
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	readDiskTime := time.Since(start)

	source := string(data)

	inputType := "lsp"
	var fasMeta map[string]interface{}
	var vlxMeta map[string]interface{}

	// Determine input type by extension (case-insensitive)
	ext := strings.ToLower(getFileExtension(filepath))
	adaptTime := time.Duration(0)
	switch ext {
	case ".fas":
		inputType = "fas"
		// Adapt FAS file
		start = time.Now()
		fasResult, err := a.fasAdapter.Adapt(data)
		if err != nil {
			return "", "", "", nil, nil, fmt.Errorf("FAS adaptation failed: %w", err)
		}
		adaptTime = time.Since(start)
		source = fasResult.Source
		fasMeta = fasResult.Meta
	case ".vlx":
		inputType = "vlx"
		// Adapt VLX file
		start = time.Now()
		vlxResult, err := a.vlxAdapter.Adapt(data)
		if err != nil {
			return "", "", "", nil, nil, fmt.Errorf("VLX adaptation failed: %w", err)
		}
		adaptTime = time.Since(start)
		source = vlxResult.Source
		vlxMeta = vlxResult.Meta
	case ".lsp", ".mnl":
		inputType = "lsp"
		// Check if this is actually a FAS file disguised as .lsp
		// FAS4 files often have "FAS4-FILE" header
		if hasFASHeaderPrefix(source) {
			// This is actually a FAS file disguised as LSP
			start = time.Now()
			fasResult, err := a.fasAdapter.Adapt(data)
			adaptTime += time.Since(start)
			if err == nil && fasResult.Source != "" {
				source = fasResult.Source
				inputType = "fas"
				fasMeta = fasResult.Meta
			}
		} else if !looksLikeLISPSource(source) && a.vbaAdapter.IsVBASource(source) {
			// Check if this is actually VBA/VBScript disguised as .lsp
			start = time.Now()
			vbaResult := a.vbaAdapter.Adapt(source, filepath)
			adaptTime += time.Since(start)
			source = vbaResult.Source
			inputType = "lsp-vba"
		}
	default:
		inputType = "lsp"
		// Check if this is actually a FAS file disguised with different extension
		if hasFASHeaderPrefix(source) {
			start = time.Now()
			fasResult, err := a.fasAdapter.Adapt(data)
			adaptTime += time.Since(start)
			if err == nil && fasResult.Source != "" {
				source = fasResult.Source
				inputType = "fas"
				fasMeta = fasResult.Meta
			}
		} else if !looksLikeLISPSource(source) && a.vbaAdapter.IsVBASource(source) {
			// Check if this is actually VBA/VBScript disguised as .lsp
			start = time.Now()
			vbaResult := a.vbaAdapter.Adapt(source, filepath)
			adaptTime += time.Since(start)
			source = vbaResult.Source
			inputType = "lsp-vba"
		}
	}

	// Preprocess analysis source after adaptation:
	// 1. remove all comments from the analysis path
	// 2. clean weird prefixes / padding that may confuse the parser
	start = time.Now()
	analysisSource := preprocessAnalysisSource(source)
	preprocessTime := time.Since(start)

	if debugutil.TimingEnabled() && (readDiskTime > 500*time.Millisecond || preprocessTime > 500*time.Millisecond || adaptTime > 500*time.Millisecond) {
		fmt.Fprintf(os.Stderr, "  [READ-TIMING] disk=%v adapt=%v preprocess=%v bytes=%d input=%s\n",
			readDiskTime, adaptTime, preprocessTime, len(data), inputType)
	}

	return source, analysisSource, inputType, fasMeta, vlxMeta, nil
}

// preprocessAnalysisSource prepares source for parser-facing analysis only.
// The current analyzer does not trust comments, so they are removed entirely
// before prefix/padding cleanup.
func preprocessAnalysisSource(source string) string {
	source = stripLISPComments(source)
	source = cleanLISPPrefix(source)
	return source
}

// stripLISPComments removes all line comments from the parser-facing source.
// AutoLISP comments begin with ';' and continue to the end of the line.
func stripLISPComments(source string) string {
	if source == "" {
		return source
	}
	var b strings.Builder
	b.Grow(len(source))

	lineStart := 0
	commentIdx := -1
	trimEnd := 0
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case ';':
			if commentIdx == -1 {
				commentIdx = i
			}
		case '\n':
			end := i
			if commentIdx >= 0 && commentIdx < end {
				end = commentIdx
			}
			for end > lineStart {
				c := source[end-1]
				if c != ' ' && c != '\t' && c != '\r' {
					break
				}
				end--
			}
			if trimEnd > 0 || end > lineStart {
				b.WriteString(source[lineStart:end])
			}
			b.WriteByte('\n')
			lineStart = i + 1
			commentIdx = -1
			trimEnd = 0
		}
	}
	if lineStart < len(source) {
		end := len(source)
		if commentIdx >= 0 && commentIdx < end {
			end = commentIdx
		}
		for end > lineStart {
			c := source[end-1]
			if c != ' ' && c != '\t' && c != '\r' {
				break
			}
			end--
		}
		b.WriteString(source[lineStart:end])
	}
	return b.String()
}

// cleanLISPPrefix removes non-standard prefixes and suspicious padding that
// may confuse the parser after comments have already been stripped.
func cleanLISPPrefix(source string) string {
	knownFuncs := []string{"setq", "defun", "if", "while", "open", "close",
		"write-line", "read-line", "strcat", "findfile", "load", "vl-",
		"progn", "and", "or", "not", "foreach", "repeat", "princ", "command"}

	for i := 0; i < len(source); {
		lineStart := i
		for i < len(source) && source[i] != '\n' {
			i++
		}
		lineEnd := i
		trimmedStart, trimmedEnd := trimSourceLine(source, lineStart, lineEnd)
		if trimmedStart < trimmedEnd && source[trimmedStart] == '(' {
			afterParen := source[trimmedStart+1 : trimmedEnd]
			for _, fn := range knownFuncs {
				if strings.HasPrefix(afterParen, fn) {
					return source[lineStart:]
				}
			}
		}
		if i < len(source) && source[i] == '\n' {
			i++
		}
	}

	return source
}

func hasFASHeaderPrefix(source string) bool {
	const maxHeaderScanBytes = 4 * 1024
	limit := min(len(source), maxHeaderScanBytes)
	for i := 0; i < limit; {
		lineStart := i
		for i < limit && source[i] != '\n' {
			i++
		}
		lineEnd := i
		start, end := trimSourceLine(source, lineStart, lineEnd)
		if start < end {
			line := source[start:end]
			if strings.HasPrefix(line, "FAS4") || strings.HasPrefix(line, "; AutoCAD Binary File") {
				return true
			}
		}
		if i < limit && source[i] == '\n' {
			i++
		}
	}
	return false
}

func looksLikeLISPSource(source string) bool {
	const maxScanBytes = 64 * 1024
	limit := min(len(source), maxScanBytes)
	knownFuncs := []string{"setq", "defun", "if", "while", "open", "close",
		"write-line", "read-line", "strcat", "findfile", "load", "vl-",
		"progn", "and", "or", "not", "foreach", "repeat", "princ", "command"}

	for i := 0; i < limit; {
		lineStart := i
		for i < limit && source[i] != '\n' {
			i++
		}
		lineEnd := i
		trimmedStart, trimmedEnd := trimSourceLine(source, lineStart, lineEnd)
		if trimmedStart < trimmedEnd && source[trimmedStart] == '(' {
			afterParen := source[trimmedStart+1 : trimmedEnd]
			for _, fn := range knownFuncs {
				if strings.HasPrefix(afterParen, fn) {
					return true
				}
			}
		}
		if i < limit && source[i] == '\n' {
			i++
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getFileExtension returns the file extension
func getFileExtension(filepath string) string {
	for i := len(filepath) - 1; i >= 0; i-- {
		if filepath[i] == '.' {
			return filepath[i:]
		}
		if filepath[i] == '/' || filepath[i] == '\\' {
			break
		}
	}
	return ""
}
