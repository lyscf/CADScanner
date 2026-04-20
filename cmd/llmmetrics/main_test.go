package main

import (
	"math"
	"testing"

	"github.com/evilcad/cadscanner/pkg/llm"
)

func TestLLMMaliciousScoreMapping(t *testing.T) {
	tests := []struct {
		name     string
		analysis *llm.SemanticAnalysis
		want     float64
	}{
		{
			name: "malicious high confidence",
			analysis: &llm.SemanticAnalysis{
				SemanticLabel: llm.LabelMalicious,
				Confidence:    0.8,
			},
			want: 0.9,
		},
		{
			name: "benign high confidence",
			analysis: &llm.SemanticAnalysis{
				SemanticLabel: llm.LabelBenign,
				Confidence:    0.8,
			},
			want: 0.1,
		},
		{
			name: "suspicious stays neutral",
			analysis: &llm.SemanticAnalysis{
				SemanticLabel: llm.LabelSuspicious,
				Confidence:    0.9,
			},
			want: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := llmMaliciousScore(tt.analysis)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Fatalf("llmMaliciousScore() = %.4f, want %.4f", got, tt.want)
			}
		})
	}
}

func TestAccumulateFusion(t *testing.T) {
	metrics := &fusionMetrics{}

	accumulateFusion("examples\\black_test.lsp", 0.8, 0.9, 0.5, metrics)
	accumulateFusion("examples\\black_test2.lsp", 0.2, 0.1, 0.5, metrics)
	accumulateFusion("examples\\white_test.lsp", 0.1, 0.2, 0.5, metrics)
	accumulateFusion("examples\\white_test2.lsp", 0.8, 0.9, 0.5, metrics)

	if metrics.TP != 1 || metrics.FN != 1 || metrics.TN != 1 || metrics.FP != 1 {
		t.Fatalf("unexpected metrics: %+v", *metrics)
	}
}
