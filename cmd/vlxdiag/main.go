package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/evilcad/cadscanner/pkg/analyzer"
	"github.com/evilcad/cadscanner/pkg/cliutil"
	"github.com/evilcad/cadscanner/pkg/config"
)

type recordInfo struct {
	Index    int
	Offset   int
	Length   int
	TypeCode int
	Name     string
	Kind     string
}

func main() {
	configPath := flag.String("config", "", "config file path")
	maxSource := flag.Int("max-source", 1600, "max source characters to print")
	format := flag.String("format", "human", "Output format: human or json")
	cliutil.SetUsage("vlxdiag", "[flags] <sample.vlx>")
	flag.Parse()
	if flag.NArg() != 1 {
		cliutil.UsageError("vlxdiag", "[flags] <sample.vlx>")
	}
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("vlxdiag: %v", err)
	}

	path := flag.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		cliutil.Failf("vlxdiag: read %s: %v", path, err)
	}

	records, warnings := parseVLXRecords(data)

	cfg, err := config.Load(*configPath)
	if err != nil {
		cliutil.Failf("vlxdiag: load config: %v", err)
	}
	cfg.LLM.Enabled = false

	a, err := analyzer.New(cfg)
	if err != nil {
		cliutil.Failf("vlxdiag: create analyzer: %v", err)
	}
	result, err := a.AnalyzeFile(context.Background(), path, false)
	if err != nil {
		cliutil.Failf("vlxdiag: analyze %s: %v", path, err)
	}

	attackCount := 0
	if result.AttackResult != nil {
		attackCount = len(result.AttackResult.Techniques)
	}

	if outputFormat == "json" {
		cliutil.WriteJSON(map[string]any{
			"command": "vlxdiag",
			"sample": path,
			"records": records,
			"warnings": warnings,
			"analysis": map[string]any{
				"verdict": result.FinalVerdict,
				"risk": result.RiskScore,
				"effects": result.AllEffects,
				"matched_rules": result.MatchedRules,
				"attack_count": attackCount,
				"attack_result": result.AttackResult,
				"vlx_meta": result.VLXMeta,
				"source_preview": truncate(result.Source, *maxSource),
			},
		})
		return
	}

	cliutil.PrintSection("VLX Records")
	cliutil.PrintKV("Sample", "%s", path)
	cliutil.PrintKV("Records", "%d", len(records))
	if len(warnings) > 0 {
		fmt.Printf("Warnings (%d):\n", len(warnings))
		for _, warning := range warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}
	fmt.Println("Record Summary:")
	for _, rec := range records {
		fmt.Printf("  [%02d] off=%d len=%d type=0x%04X kind=%s name=%q\n",
			rec.Index, rec.Offset, rec.Length, rec.TypeCode, rec.Kind, rec.Name)
	}

	cliutil.PrintSection("Analysis Summary")
	cliutil.PrintKV("Verdict", "%s", result.FinalVerdict)
	cliutil.PrintKV("Risk", "%.4f", result.RiskScore)
	cliutil.PrintKV("Effects", "%d", len(result.AllEffects))
	cliutil.PrintKV("Rules", "%d", len(result.MatchedRules))
	cliutil.PrintKV("ATT&CK", "%d", attackCount)
	for i, effect := range result.AllEffects {
		if i >= 24 {
			fmt.Printf("  ... and %d more effects\n", len(result.AllEffects)-24)
			break
		}
		fmt.Printf("  effect[%02d] %-16s source=%q target=%q\n", i, effect.EffectType, effect.Source, truncate(effect.Target, 100))
	}
	for _, rule := range result.MatchedRules {
		fmt.Printf("  rule %s %.2f %s\n", rule.ID, rule.Severity, rule.Name)
	}

	if result.VLXMeta != nil {
		fmt.Println("\nVLX Meta Keys:")
		for key := range result.VLXMeta {
			fmt.Printf("  - %s\n", key)
		}
		fmt.Println("\nRecovered Behavior Buckets:")
		for key, value := range result.VLXMeta {
			if !strings.HasSuffix(key, "_recovered_behaviors") {
				continue
			}
			fmt.Printf("  %s: %#v\n", key, value)
		}
		fmt.Println("\nResource Summaries:")
		for key, value := range result.VLXMeta {
			if !strings.HasSuffix(key, "_resource_summary") {
				continue
			}
			fmt.Printf("  %s: %#v\n", key, value)
		}
	}

	if result.Source != "" && *maxSource > 0 {
		cliutil.PrintSection(fmt.Sprintf("Source Preview (%d chars max)", *maxSource))
		fmt.Println(truncate(result.Source, *maxSource))
	}
}

func parseVLXRecords(data []byte) ([]recordInfo, []string) {
	loadStart := bytesIndex(data, []byte("LOAD("))
	if loadStart < 0 {
		return nil, []string{"LOAD( section not found"}
	}
	nullPos := bytesIndex(data[loadStart:], []byte{0})
	if nullPos < 0 {
		return nil, []string{"LOAD( terminator not found"}
	}
	start := loadStart + nullPos + 1
	tail := bytesIndex(data, []byte("VRTLIB-1"))
	if tail < 0 {
		tail = len(data)
	}

	var records []recordInfo
	var warnings []string
	pos := start
	idx := 0
	for pos+7 <= tail {
		for pos < tail && data[pos] == 0 {
			pos++
		}
		if pos+7 > tail {
			break
		}
		length := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
		typeCode := int(binary.LittleEndian.Uint16(data[pos+4 : pos+6]))
		nameLen := int(data[pos+6])
		if length <= 0 || pos+length > len(data) {
			warnings = append(warnings, fmt.Sprintf("invalid length at %d: %d", pos, length))
			pos++
			continue
		}
		if nameLen <= 0 || nameLen > 80 || pos+7+nameLen > len(data) {
			warnings = append(warnings, fmt.Sprintf("invalid nameLen at %d: %d", pos, nameLen))
			pos++
			continue
		}
		contentOffset := pos + 7 + nameLen
		contentEnd := pos + length
		if contentOffset > contentEnd || contentEnd > len(data) {
			warnings = append(warnings, fmt.Sprintf("invalid content bounds at %d", pos))
			pos++
			continue
		}
		blob := data[contentOffset:contentEnd]
		name := string(data[pos+7 : pos+7+nameLen])
		records = append(records, recordInfo{
			Index:    idx,
			Offset:   pos,
			Length:   length,
			TypeCode: typeCode,
			Name:     name,
			Kind:     inferKind(blob, typeCode),
		})
		pos += length
		idx++
	}
	return records, warnings
}

func inferKind(blob []byte, typeCode int) string {
	switch typeCode {
	case 0x0532:
		return "fas"
	case 0x0546:
		return "dcl"
	case 0x0537:
		return "raw"
	}
	head := blob
	if len(head) > 512 {
		head = head[:512]
	}
	if bytesIndex(head, []byte("FAS4-FILE")) >= 0 {
		return "fas"
	}
	if bytesIndex(head, []byte("(defun ")) >= 0 || bytesIndex(head, []byte("(setq ")) >= 0 {
		return "lsp"
	}
	if bytesIndex(head, []byte(": dialog{")) >= 0 || bytesIndex(head, []byte(":dialog{")) >= 0 {
		return "dcl"
	}
	return "unknown"
}

func bytesIndex(data, sub []byte) int {
	return strings.Index(string(data), string(sub))
}

func truncate(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
