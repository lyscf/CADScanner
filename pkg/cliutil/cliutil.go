package cliutil

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func SetUsage(command string, synopsis string) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s %s\n", command, synopsis)
		flag.PrintDefaults()
	}
}

func UsageError(command string, synopsis string) {
	SetUsage(command, synopsis)
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage()
	os.Exit(2)
}

func Failf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func PrintSection(title string) {
	fmt.Printf("== %s ==\n", title)
}

func PrintKV(key string, format string, args ...interface{}) {
	fmt.Printf("%s: %s\n", key, fmt.Sprintf(format, args...))
}

func Truncate(text string, limit int) string {
	if limit <= 0 || len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}

func ParseFormat(raw string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	switch format {
	case "", "human":
		return "human", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unsupported format %q (want human or json)", raw)
	}
}

func WriteJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		Failf("json encode failed: %v", err)
	}
}
