package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/ir"
)

// IRStage builds the intermediate representation from normalized AST.
type IRStage struct {
	irBuilder *ir.IRBuilder
}

func NewIRStage(irBuilder *ir.IRBuilder) *IRStage {
	return &IRStage{irBuilder: irBuilder}
}

func (s *IRStage) Name() string { return "ir" }

func (s *IRStage) Run(ctx context.Context, pipeCtx *PipelineContext) error {
	start := time.Now()
	irResult, err := s.irBuilder.Build(pipeCtx.Normalized)
	if err != nil {
		return err
	}
	buildTime := time.Since(start)

	start = time.Now()
	ir.MergeRecoveredFAS(irResult, pipeCtx.FASMeta)
	ir.MergeRecoveredVLXEmbeddedFAS(irResult, pipeCtx.VLXMeta)
	mergeTime := time.Since(start)
	if pipeCtx.IRTiming != nil {
		pipeCtx.IRTiming["build"] = buildTime
		pipeCtx.IRTiming["merge"] = mergeTime
	}

	pipeCtx.IRResult = irResult
	pipeCtx.CallGraph = irResult.CallGraph
	pipeCtx.SemanticTags = irResult.SemanticTags
	pipeCtx.EnvChecks = irResult.EnvChecks

	// Print IR timing breakdown if slow
	if debugutil.TimingEnabled() && (buildTime > 1*time.Second || mergeTime > 500*time.Millisecond) {
		fmt.Fprintf(os.Stderr, "  [IR-TIMING] build=%v merge=%v\n", buildTime, mergeTime)
	}
	return nil
}
