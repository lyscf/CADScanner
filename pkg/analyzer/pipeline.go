package analyzer

import (
	"context"
	"time"

	"github.com/evilcad/cadscanner/pkg/deobfuscation"
	"github.com/evilcad/cadscanner/pkg/detector"
	"github.com/evilcad/cadscanner/pkg/graph"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/llm"
	"github.com/evilcad/cadscanner/pkg/normalizer"
	"github.com/evilcad/cadscanner/pkg/parser"
	"github.com/evilcad/cadscanner/pkg/scoring"
)

// PipelineContext carries intermediate results between pipeline stages.
// Each stage reads its inputs from ctx and writes its outputs back.
// This is the single internal intermediate product of the pipeline;
// AnalysisResult is only a DTO mapped at the end.
type PipelineContext struct {
	// --- Front-end outputs ---
	Filepath       string
	Source         string
	AnalysisSource string
	InputType      string
	FASMeta        map[string]interface{}       // FAS file metadata
	VLXMeta        map[string]interface{}       // VLX file metadata
	AST            []*parser.ASTNode            // Raw parser output (pre-normalization)
	Normalized     []*normalizer.NormalizedNode // Normalized AST
	ObfPatterns    []deobfuscation.ObfuscationPattern

	// --- IR outputs ---
	IRResult *ir.IRResult

	// --- Derived from IR (convenience aliases) ---
	CallGraph    map[string][]string
	SemanticTags map[string][]ir.SemanticTag
	EnvChecks    []string

	// --- Formal / graph outputs ---
	FormalAnalyzer      *graph.FormalGraphAnalyzer
	SCCResults          []*graph.SCCResult
	PropagationClosures map[string]*graph.PropagationClosure
	PredicateResults    map[string]*graph.PredicateResult
	Motifs              []*graph.BehaviorMotif
	FormalScoreResult   *scoring.FormalScoreResult

	// --- Detection / scoring outputs ---
	DetectResult *detector.DetectResult
	ScoreResult  *scoring.ScoreResult

	// --- Encoding outputs ---
	LLMEncoding string
	LLMResult   *llm.SemanticAnalysis

	// --- Performance timing (in milliseconds) ---
	StageTiming     map[string]time.Duration
	FrontendTiming  map[string]time.Duration
	IRTiming        map[string]time.Duration
	FormalTiming    map[string]time.Duration
	DetectionTiming map[string]time.Duration
	EncodingTiming  map[string]time.Duration
	ReadTiming      map[string]time.Duration
}

// Stage is a single processing step in the analysis pipeline.
type Stage interface {
	Name() string
	Run(ctx context.Context, pipeCtx *PipelineContext) error
}
