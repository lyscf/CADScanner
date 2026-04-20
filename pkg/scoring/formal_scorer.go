package scoring

import (
	"math"

	"github.com/evilcad/cadscanner/pkg/graph"
	"github.com/evilcad/cadscanner/pkg/ir"
)

// FormalScoreResult represents the formal score decomposition result
type FormalScoreResult struct {
	Cycle       float64
	Propagation float64
	Entropy     float64
	EnvRisk     float64
	Weights     map[string]float64
	Final       float64
	Formula     string
}

// FormalScorer provides mathematical scoring based on formal semantics
type FormalScorer struct {
	cycleWeight       float64
	propagationWeight float64
	entropyWeight     float64
	envRiskWeight     float64
}

// NewFormalScorer creates a new formal scorer
func NewFormalScorer(cycleWeight, propagationWeight, entropyWeight, envRiskWeight float64) *FormalScorer {
	return &FormalScorer{
		cycleWeight:       cycleWeight,
		propagationWeight: propagationWeight,
		entropyWeight:     entropyWeight,
		envRiskWeight:     envRiskWeight,
	}
}

// DecomposeScore decomposes score into mathematical components
func (fs *FormalScorer) DecomposeScore(sccResults []*graph.SCCResult, closures map[string]*graph.PropagationClosure, effects []ir.EffectType, envChecks int) *FormalScoreResult {
	// Component 1: Cycle strength (from SCC)
	cycleScore := 0.0
	if len(sccResults) > 0 {
		// Max cycle strength across all SCCs
		for _, scc := range sccResults {
			if scc.CycleStrength > cycleScore {
				cycleScore = scc.CycleStrength
			}
		}
	}

	// Component 2: Propagation coverage (from closure)
	propagationScore := 0.0
	if len(closures) > 0 {
		// Max coverage across all closures
		for _, closure := range closures {
			if closure.Coverage > propagationScore {
				propagationScore = closure.Coverage
			}
		}
	}

	// Component 3: Effect entropy (Shannon entropy)
	entropyScore := fs.computeEntropy(effects)

	// Component 4: Environment risk (normalized)
	envRiskScore := math.Min(1.0, float64(envChecks)/5.0)

	// Final score
	finalScore := fs.cycleWeight*cycleScore +
		fs.propagationWeight*propagationScore +
		fs.entropyWeight*entropyScore +
		fs.envRiskWeight*envRiskScore

	return &FormalScoreResult{
		Cycle:       cycleScore,
		Propagation: propagationScore,
		Entropy:     entropyScore,
		EnvRisk:     envRiskScore,
		Weights: map[string]float64{
			"w1": fs.cycleWeight,
			"w2": fs.propagationWeight,
			"w3": fs.entropyWeight,
			"w4": fs.envRiskWeight,
		},
		Final:   finalScore,
		Formula: "w1·cycle + w2·propagation + w3·entropy + w4·env_risk",
	}
}

// computeEntropy computes Shannon entropy of effect distribution
func (fs *FormalScorer) computeEntropy(effects []ir.EffectType) float64 {
	if len(effects) == 0 {
		return 0.0
	}

	// Count effect types
	counts := make(map[ir.EffectType]int)
	for _, effect := range effects {
		counts[effect]++
	}
	total := len(effects)

	// Compute entropy
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize by max entropy (log₂ of unique effect types)
	maxEntropy := math.Log2(float64(len(counts)))
	if len(counts) <= 1 {
		maxEntropy = 1.0
	}
	normalizedEntropy := entropy / maxEntropy

	return normalizedEntropy
}
