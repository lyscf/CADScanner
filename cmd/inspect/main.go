// Test single file analyzer
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
)

func main() {
	if len(os.Args) != 2 {
		cliutil.UsageError("inspect", "<file>")
	}
	file := os.Args[1]

	cfg := &config.Config{
		Analysis: config.AnalysisConfig{
			MaxFileSize:         10 * 1024 * 1024,
			Timeout:             30,
			EnableVerbose:       true,
			EnableDeobfuscation: true,
		},
		Detection: config.DetectionConfig{
			Threshold:    0.5,
			EnableRules:  true,
			EnableATTACK: true,
		},
		Scoring: config.ScoringConfig{
			DecisionThreshold: 0.5,
			EnableFormal:      true,
			PrimitiveWeight:   0.5,
			PatternWeight:     0.3,
			ContextWeight:     0.2,
		},
	}

	a, err := analyzer.New(cfg)
	if err != nil {
		cliutil.Failf("inspect: create analyzer: %v", err)
	}

	ctx := context.Background()
	result, err := a.AnalyzeFile(ctx, file, true)
	if err != nil {
		cliutil.Failf("inspect: analyze %s: %v", file, err)
	}

	cliutil.PrintSection("Summary")
	cliutil.PrintKV("File", "%s", file)
	cliutil.PrintKV("Verdict", "%v (confidence: %.4f)", result.IsMalicious, result.MaliciousConfidence)
	cliutil.PrintKV("Risk Score", "%.4f", result.RiskScore)
	cliutil.PrintKV("AST Count", "%d", result.ASTCount)
	cliutil.PrintKV("Normalized Count", "%d", result.NormalizedCount)
	cliutil.PrintSection(fmt.Sprintf("IR Effects (%d)", len(result.AllEffects)))
	for i, e := range result.AllEffects {
		if i >= 15 {
			fmt.Printf("  ... and %d more\n", len(result.AllEffects)-15)
			break
		}
		target := e.Target
		if len(target) > 50 {
			target = target[:50] + "..."
		}
		fmt.Printf("  %d. %s: target=%q source=%q\n", i+1, e.EffectType, target, e.Source)
	}
	cliutil.PrintSection(fmt.Sprintf("Matched Rules (%d)", len(result.MatchedRules)))
	for _, r := range result.MatchedRules {
		fmt.Printf("  - %s: %s (%.2f)\n", r.ID, r.Name, r.Severity)
	}
	if result.AttackResult != nil {
		cliutil.PrintSection(fmt.Sprintf("Attack Techniques (%d)", len(result.AttackResult.Techniques)))
		for _, t := range result.AttackResult.Techniques {
			fmt.Printf("  - %s: %s (%.2f)\n", t.ID, t.Name, t.Confidence)
		}
	}
}
