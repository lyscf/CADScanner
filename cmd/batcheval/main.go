// Batch evaluation tool for CADScanner.
// Go equivalent of tools/batch_eval.py.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/evilcad/cadscanner/pkg/batcheval"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
)

func main() {
	var (
		root         = flag.String("root", "examples", "Sample root directory")
		recursive    = flag.Bool("recursive", false, "Recursively scan sample directory")
		jsonOut      = flag.String("json-out", "", "Optional JSON output file")
		csvOut       = flag.String("csv-out", "", "Optional CSV output file")
		failFast     = flag.Bool("fail-fast", false, "Stop on first analysis error")
		workers      = flag.Int("workers", 1, "Concurrent workers (default: 1)")
		timeout      = flag.Float64("timeout", 10.0, "Per-sample timeout in seconds")
		noProgress   = flag.Bool("no-progress", false, "Disable progress bar")
		configPath   = flag.String("config", "", "Path to config file")
		format       = flag.String("format", "human", "Output format: human or json")
	)
	flag.Parse()

	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("batcheval: %v", err)
	}

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
		cfg = batcheval.MustLoadConfig("")
	}

	// Check root exists
	if _, err := os.Stat(*root); err != nil {
		fmt.Fprintf(os.Stderr, "Sample directory not found: %s\n", *root)
		os.Exit(2)
	}

	// Find samples
	samples, err := batcheval.FindSamples(*root, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to find samples: %v\n", err)
		os.Exit(2)
	}
	if len(samples) == 0 {
		fmt.Fprintf(os.Stderr, "No supported samples found under: %s\n", *root)
		os.Exit(2)
	}

	// Create evaluator with options
	opts := []batcheval.EvaluatorOption{
		batcheval.WithWorkers(*workers),
		batcheval.WithTimeout(time.Duration(*timeout * float64(time.Second))),
		batcheval.WithFailFast(*failFast),
		batcheval.WithProgress(outputFormat == "human" && !*noProgress),
	}

	eval, err := batcheval.NewEvaluator(cfg, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create evaluator: %v\n", err)
		os.Exit(2)
	}

	// Evaluate
	rows, err := eval.EvaluateSamples(samples)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Evaluation failed: %v\n", err)
		os.Exit(2)
	}

	metrics := batcheval.CalculateMetrics(rows)
	timing := batcheval.CalculateTimingStats(rows)

	if outputFormat == "human" {
		fmt.Printf("Found %d samples to evaluate\n\n", len(samples))
		batcheval.PrintReport(rows)
	}

	// Write outputs
	if *jsonOut != "" {
		if err := batcheval.WriteJSON(rows, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write JSON: %v\n", err)
		}
	}

	if *csvOut != "" {
		if err := batcheval.WriteCSV(rows, *csvOut); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write CSV: %v\n", err)
		}
	}

	if outputFormat == "json" {
		cliutil.WriteJSON(map[string]any{
			"command": "batcheval",
			"root": *root,
			"recursive": *recursive,
			"workers": *workers,
			"timeout_seconds": *timeout,
			"samples_found": len(samples),
			"metrics": metrics,
			"timing": timing,
			"rows": rows,
			"json_out": *jsonOut,
			"csv_out": *csvOut,
		})
		return
	}

	if *jsonOut != "" {
		fmt.Printf("\nJSON written: %s\n", *jsonOut)
	}
	if *csvOut != "" {
		fmt.Printf("CSV written: %s\n", *csvOut)
	}
}
