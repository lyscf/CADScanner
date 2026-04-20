package analyzer

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/evilcad/cadscanner/pkg/config"
	"github.com/evilcad/cadscanner/pkg/debugutil"
	"github.com/evilcad/cadscanner/pkg/graph"
	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/scoring"
)

// FormalStage runs formal semantics analysis: SCC, propagation closures,
// formal predicates, motif extraction, and formal scoring.
type FormalStage struct {
	config *config.Config
}

func NewFormalStage(cfg *config.Config) *FormalStage { return &FormalStage{config: cfg} }

func (s *FormalStage) Name() string { return "formal" }

func (s *FormalStage) Run(ctx context.Context, pipeCtx *PipelineContext) error {
	// Skip formal analysis if disabled in config
	if !s.config.Scoring.EnableFormal {
		return nil
	}

	irResult := pipeCtx.IRResult
	callGraph := pipeCtx.CallGraph

	// Formal semantics analysis (SCC detection, propagation closure)
	start := time.Now()
	formalAnalyzer := graph.NewFormalGraphAnalyzer(irResult.Functions, callGraph)
	sccs := formalAnalyzer.DetectSCCs()
	sccTime := time.Since(start)
	pipeCtx.FormalAnalyzer = formalAnalyzer
	pipeCtx.SCCResults = sccs

	// Compute propagation closures for entry points
	start = time.Now()
	propClosures := make(map[string]*graph.PropagationClosure)
	for _, entry := range irResult.PropagationEvidence.EntryPoints {
		closure := formalAnalyzer.ComputePropagationClosure(entry)
		propClosures[entry] = closure
	}
	closureTime := time.Since(start)
	pipeCtx.PropagationClosures = propClosures

	// Formal predicates evaluation
	start = time.Now()
	predicates := graph.NewFormalPredicates()
	pipeCtx.PredicateResults = make(map[string]*graph.PredicateResult)
	pipeCtx.PredicateResults["worm"] = predicates.WormPredicate(sccs, irResult.Functions, callGraph)
	pipeCtx.PredicateResults["stealth_persistence"] = predicates.StealthPersistencePredicate(irResult.Functions, callGraph)
	pipeCtx.PredicateResults["propagation_closure"] = predicates.PropagationClosurePredicate(propClosures, 0.3)
	predicateTime := time.Since(start)

	// Behavior motif extraction
	start = time.Now()
	motifExtractor := graph.NewBehaviorMotifExtractor(irResult.Functions, callGraph)
	pipeCtx.Motifs = motifExtractor.Extract()
	motifTime := time.Since(start)

	// Formal scoring — uses real envChecks count from IR layer
	start = time.Now()
	formalScorer := scoring.NewFormalScorer(0.3, 0.3, 0.2, 0.2)
	effectTypes := make([]ir.EffectType, 0, len(irResult.Effects))
	for _, effect := range irResult.Effects {
		effectTypes = append(effectTypes, effect.EffectType)
	}
	envChecks := len(pipeCtx.EnvChecks)
	pipeCtx.FormalScoreResult = formalScorer.DecomposeScore(sccs, propClosures, effectTypes, envChecks)
	scoreTime := time.Since(start)
	if pipeCtx.FormalTiming != nil {
		pipeCtx.FormalTiming["scc"] = sccTime
		pipeCtx.FormalTiming["closure"] = closureTime
		pipeCtx.FormalTiming["predicates"] = predicateTime
		pipeCtx.FormalTiming["motifs"] = motifTime
		pipeCtx.FormalTiming["score"] = scoreTime
	}

	// Print formal timing breakdown if slow
	if debugutil.TimingEnabled() && (sccTime > 500*time.Millisecond || closureTime > 1*time.Second) {
		fmt.Fprintf(os.Stderr, "  [FORMAL-TIMING] scc=%v closure=%v predicates=%v motifs=%v score=%v (entries=%d)\n",
			sccTime, closureTime, predicateTime, motifTime, scoreTime,
			len(irResult.PropagationEvidence.EntryPoints))
	}

	return nil
}
