package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/config"
)

func main() {
	// Parse command line flags
	format := flag.String("format", "text", "Output format (text or json)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	configPath := flag.String("config", "", "Path to config file")
	debugFAS := flag.Bool("debug-fas", false, "Output FAS pseudo-LISP for debugging")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Check if files are provided
	if flag.NArg() == 0 {
		fmt.Println("Usage: cadscanner [options] <files...>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Create analyzer
	a, err := analyzer.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create analyzer: %v", err)
	}

	// Analyze each file
	exitCode := 0
	ctx := context.Background()
	for _, filepath := range flag.Args() {
		result, err := a.AnalyzeFile(ctx, filepath, *verbose)
		if err != nil {
			log.Printf("Error analyzing %s: %v", filepath, err)
			exitCode = 2
			continue
		}

		// Output results
		if *format == "json" {
			outputJSON(result)
		} else {
			outputText(result, *verbose, *debugFAS)
		}

		if result.IsMalicious {
			exitCode = 1
		}
	}

	os.Exit(exitCode)
}

func outputText(result *analyzer.AnalysisResult, verbose bool, debugFAS bool) {
	fmt.Printf("\n%s\n", "========================================")
	fmt.Printf("Complete Analysis: %s\n", result.Filepath)
	fmt.Printf("%s\n\n", "========================================")

	// Verdict
	verdict := result.FinalVerdict
	if verdict == "" {
		verdict = result.RuleVerdict
	}
	fmt.Printf("Verdict: %s\n", verdict)
	if result.RuleVerdict != "" {
		fmt.Printf("Rule Verdict: %s\n", result.RuleVerdict)
	}
	if result.FinalVerdict != "" && result.FinalVerdict != result.RuleVerdict {
		fmt.Printf("Fusion Summary: %s\n", result.FusionSummary)
	}
	fmt.Printf("Risk Score: %.2f\n", result.RiskScore)
	fmt.Printf("Malicious Confidence: %.2f\n", result.MaliciousConfidence)
	if result.LLMAnalysis != nil {
		fmt.Printf("Semantic Verdict: %s", result.LLMAnalysis.SemanticLabel)
		if result.LLMAnalysis.Confidence > 0 {
			fmt.Printf(" (confidence: %.2f)", result.LLMAnalysis.Confidence)
		}
		fmt.Println()
		if result.LLMAnalysis.Model != "" || result.LLMAnalysis.Provider != "" {
			fmt.Printf("LLM Backend: %s / %s\n", result.LLMAnalysis.Provider, result.LLMAnalysis.Model)
		}
		if result.LLMAnalysis.CacheHit {
			fmt.Printf("LLM Cache: hit\n")
		}
		if result.LLMAnalysis.TriageReport.String() != "" {
			fmt.Printf("LLM Report: %s\n", result.LLMAnalysis.TriageReport.String())
		}
		if result.LLMAnalysis.Reason != "" && verbose {
			fmt.Printf("LLM Reason: %s\n", result.LLMAnalysis.Reason)
		}
		if result.LLMAnalysis.Error != "" {
			fmt.Printf("LLM Error: %s\n", result.LLMAnalysis.Error)
		}
	}
	fmt.Println()

	// IR Layer
	fmt.Printf("IR Layer:\n")
	fmt.Printf("  Functions: %d\n", len(result.IRFunctions))
	if len(result.IRFunctions) > 0 {
		fmt.Printf("  Function Names:\n")
		for name := range result.IRFunctions {
			fmt.Printf("    • %s\n", name)
		}
	}
	fmt.Printf("  Raw Effects: %d\n", len(result.AllEffects))
	if len(result.AllEffects) > 0 {
		fmt.Printf("  Raw Effect Details:\n")
		for _, effect := range result.AllEffects {
			fmt.Printf("    • %s: %s -> %s\n", effect.EffectType, effect.Source, effect.Target)
		}
	}
	fmt.Printf("  Lifted Effects: %d\n", len(result.LiftedEffects))
	if len(result.LiftedEffects) > 0 {
		fmt.Printf("  Lifted Effect Details:\n")
		for _, effect := range result.LiftedEffects {
			fmt.Printf("    • [%s] %s (method: %s, severity: %s, conf: %.2f, line: %d)\n", effect.EffectType, effect.Target, effect.Method, effect.Severity, effect.Confidence, effect.SourceLine)
		}
	}
	fmt.Println()

	// Detection results
	if len(result.MatchedRules) > 0 {
		fmt.Printf("Matched Rules (%d):\n", len(result.MatchedRules))
		for _, rule := range result.MatchedRules {
			fmt.Printf("  [%s] %s (severity: %.2f)\n", rule.ID, rule.Name, rule.Severity)
		}
		fmt.Println()
	}

	// ATT&CK techniques
	if result.AttackResult != nil && len(result.AttackResult.Techniques) > 0 {
		fmt.Printf("ATT&CK Techniques (%d):\n", len(result.AttackResult.Techniques))
		for _, tech := range result.AttackResult.Techniques {
			fmt.Printf("  [%s] %s (confidence: %.2f)\n", tech.ID, tech.Name, tech.Confidence)
		}
		fmt.Println()
	}

	// ATT&CK evidence
	if result.AttackResult != nil && len(result.AttackResult.Evidence) > 0 {
		fmt.Printf("ATT&CK Evidence (%d):\n", len(result.AttackResult.Evidence))
		for _, ev := range result.AttackResult.Evidence {
			fmt.Printf("  • %s: %s\n", ev["type"], ev["description"])
			if target, ok := ev["target"]; ok {
				fmt.Printf("    target: %v\n", target)
			}
			if source, ok := ev["source"]; ok {
				fmt.Printf("    source: %v\n", source)
			}
			if function, ok := ev["function"]; ok {
				fmt.Printf("    function: %v\n", function)
			}
			if line, ok := ev["line"]; ok {
				fmt.Printf("    line: %v\n", line)
			}
			if count, ok := ev["count"]; ok {
				fmt.Printf("    count: %v\n", count)
			}
			if object, ok := ev["object"]; ok {
				fmt.Printf("    object: %v\n", object)
			}
		}
		fmt.Println()
	}

	// Motifs (replaces former SynthesizedBehaviors)
	if len(result.Motifs) > 0 {
		fmt.Printf("Behavior Motifs (%d):\n", len(result.Motifs))
		for _, m := range result.Motifs {
			fmt.Printf("  • %s (confidence: %.2f) nodes=%v\n", m.MotifType, m.Confidence, m.Nodes)
		}
		fmt.Println()
	}

	// Deobfuscation patterns
	if len(result.ObfuscationPatterns) > 0 {
		fmt.Printf("Deobfuscation:\n")
		for _, pattern := range result.ObfuscationPatterns {
			fmt.Printf("  • %s: %s\n", pattern.PatternType, pattern.Description)
			if pattern.Deobfuscated != "" {
				fmt.Printf("    → %s\n", pattern.Deobfuscated)
			}
		}
		fmt.Println()
	}

	// Debug FAS pseudo-LISP
	if debugFAS && result.InputType == "fas" && result.Source != "" {
		fmt.Printf("=== FAS Pseudo-LISP ===\n")
		fmt.Println(result.Source)
		fmt.Printf("=== End FAS Pseudo-LISP ===\n\n")
	}

	// Source preview (skip for VLX files in verbose mode to avoid cipher text)
	if verbose && result.Source != "" && result.InputType != "vlx" {
		fmt.Printf("Source:\n")
		fmt.Printf("%s\n", result.Source)
		fmt.Println()
	}

	// VLX metadata (verbose mode)
	if verbose && result.InputType == "vlx" && result.VLXMeta != nil {
		fmt.Printf("VLX Metadata:\n")
		for k, v := range result.VLXMeta {
			fmt.Printf("  %s: %v\n", k, v)
		}
		fmt.Println()
	}

	fmt.Printf("%s\n\n", "========================================")
}

func outputJSON(result *analyzer.AnalysisResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		return
	}
	fmt.Println(string(data))
}
