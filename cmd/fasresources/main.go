package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/evilcad/cadscanner/pkg/adapter"
	"github.com/evilcad/cadscanner/pkg/cliutil"
)

func main() {
	limit := flag.Int("limit", 80, "Maximum number of entries to print from each table")
	format := flag.String("format", "json", "Output format: human or json")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: fasresources [-limit N] <file.fas>\n")
		os.Exit(2)
	}
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("fasresources: %v", err)
	}

	path := flag.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}

	debug, err := adapter.NewFASAdapter().DebugResources(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "debug resources: %v\n", err)
		os.Exit(1)
	}

	out := map[string]any{
		"filepath":       path,
		"stream1_length": debug.Stream1Length,
		"stream2_length": debug.Stream2Length,
		"strings_total":  len(debug.Strings),
		"symbols_total":  len(debug.Symbols),
		"resources_total": len(debug.Resources),
		"resources":      sliceEntryLimit(debug.Resources, *limit),
		"strings":        sliceLimit(debug.Strings, *limit),
		"symbols":        sliceLimit(debug.Symbols, *limit),
	}

	if outputFormat == "json" {
		cliutil.WriteJSON(out)
		return
	}

	cliutil.PrintSection("Summary")
	cliutil.PrintKV("File", "%s", path)
	cliutil.PrintKV("Stream1 Length", "%d", debug.Stream1Length)
	cliutil.PrintKV("Stream2 Length", "%d", debug.Stream2Length)
	cliutil.PrintKV("Strings", "%d", len(debug.Strings))
	cliutil.PrintKV("Symbols", "%d", len(debug.Symbols))
	cliutil.PrintKV("Resources", "%d", len(debug.Resources))
	cliutil.PrintSection("Strings")
	for _, item := range sliceLimit(debug.Strings, *limit) {
		fmt.Printf("- %s\n", item)
	}
	cliutil.PrintSection("Symbols")
	for _, item := range sliceLimit(debug.Symbols, *limit) {
		fmt.Printf("- %s\n", item)
	}
}

func sliceLimit(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func sliceEntryLimit(items []adapter.FASResourceEntry, limit int) []adapter.FASResourceEntry {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
