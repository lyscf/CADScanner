package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/deobfuscation"
	"github.com/evilcad/cadscanner/pkg/normalizer"
	"github.com/evilcad/cadscanner/pkg/parser"
)

// FrontendStage handles parsing, normalization, and deobfuscation.
type FrontendStage struct {
	config       *config.Config
	parser       *parser.Parser
	normalizer   *normalizer.Normalizer
	deobfuscator *deobfuscation.PatternMatcher
}

func NewFrontendStage(cfg *config.Config, p *parser.Parser, n *normalizer.Normalizer, d *deobfuscation.PatternMatcher) *FrontendStage {
	return &FrontendStage{config: cfg, parser: p, normalizer: n, deobfuscator: d}
}

func (s *FrontendStage) Name() string { return "frontend" }

func (s *FrontendStage) Run(ctx context.Context, pipeCtx *PipelineContext) error {
	start := time.Now()
	source := convergeSource(pipeCtx.AnalysisSource)
	sourceTime := time.Since(start)

	start = time.Now()
	ast, err := s.parser.ParseSource(source)
	if err != nil {
		return err
	}
	parseTime := time.Since(start)

	rawASTCount := len(ast)
	start = time.Now()
	ast = convergeASTNodes(ast)
	astConvergeTime := time.Since(start)

	pipeCtx.AST = ast

	start = time.Now()
	pipeCtx.Normalized = s.normalizer.Normalize(ast)
	normalizeTime := time.Since(start)

	deobfTime := time.Duration(0)

	if s.config.Analysis.EnableDeobfuscation {
		start = time.Now()
		pipeCtx.ObfPatterns = s.deobfuscator.Analyze(pipeCtx.Normalized)
		deobfTime = time.Since(start)
	}

	if pipeCtx.FrontendTiming != nil {
		pipeCtx.FrontendTiming["source"] = sourceTime
		pipeCtx.FrontendTiming["parse"] = parseTime
		pipeCtx.FrontendTiming["ast_converge"] = astConvergeTime
		pipeCtx.FrontendTiming["normalize"] = normalizeTime
		pipeCtx.FrontendTiming["deobfuscation"] = deobfTime
	}

	totalTime := sourceTime + parseTime + astConvergeTime + normalizeTime + deobfTime
	if debugutil.TimingEnabled() && (totalTime > 500*time.Millisecond || sourceTime > 100*time.Millisecond || parseTime > 100*time.Millisecond || normalizeTime > 100*time.Millisecond) {
		fmt.Fprintf(os.Stderr,
			"  [FRONTEND-TIMING] total=%v source=%v parse=%v ast_conv=%v normalize=%v deobf=%v (source_bytes=%d ast_raw=%d ast_final=%d normalized=%d)\n",
			totalTime, sourceTime, parseTime, astConvergeTime, normalizeTime, deobfTime,
			len(pipeCtx.AnalysisSource), rawASTCount, len(ast), len(pipeCtx.Normalized))
	}
	return nil
}
