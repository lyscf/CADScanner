package analyzer

import (
	"testing"

	"github.com/evilcad/cadscanner/pkg/llm"
)

func TestFuseVerdictsSemanticEscalation(t *testing.T) {
	gotVerdict, gotAgreement, gotSummary := fuseVerdicts(
		"BENIGN",
		0.40,
		0.50,
		&llm.SemanticAnalysis{
			SemanticLabel: llm.LabelMalicious,
			Confidence:    0.95,
		},
		true,
	)

	if gotVerdict != "MALICIOUS" {
		t.Fatalf("verdict = %q, want MALICIOUS", gotVerdict)
	}
	if gotAgreement {
		t.Fatalf("agreement = true, want false")
	}
	if gotSummary != "semantic-escalation" {
		t.Fatalf("summary = %q, want semantic-escalation", gotSummary)
	}
}

func TestFuseVerdictsDisagreementFallsBackToSuspicious(t *testing.T) {
	gotVerdict, gotAgreement, gotSummary := fuseVerdicts(
		"BENIGN",
		0.10,
		0.50,
		&llm.SemanticAnalysis{
			SemanticLabel: llm.LabelMalicious,
			Confidence:    0.70,
		},
		true,
	)

	if gotVerdict != "SUSPICIOUS" {
		t.Fatalf("verdict = %q, want SUSPICIOUS", gotVerdict)
	}
	if gotAgreement {
		t.Fatalf("agreement = true, want false")
	}
	if gotSummary != "rule-llm-disagreement" {
		t.Fatalf("summary = %q, want rule-llm-disagreement", gotSummary)
	}
}

