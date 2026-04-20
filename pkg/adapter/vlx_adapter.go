package adapter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/debugutil"
)

const (
	maxVLXWarnings       = 32
	maxVLXInvalidHeaders = 512
)

// VlxRecord represents a record in a VLX file
type VlxRecord struct {
	Index         int
	Offset        int
	Length        int
	TypeCode      int
	Name          string
	ContentOffset int
	ContentEnd    int
	InferredKind  string
}

// VlxAdaptResult represents the result of VLX adaptation
type VlxAdaptResult struct {
	Source string
	Meta   map[string]interface{}
}

// VLXAdapter adapts VLX files to pseudo-LISP source
type VLXAdapter struct {
	fasAdapter *FASAdapter
}

type cachedFASAdapt struct {
	result *FASAdaptResult
	err    error
}

// NewVLXAdapter creates a new VLX adapter
func NewVLXAdapter() *VLXAdapter {
	return &VLXAdapter{
		fasAdapter: NewFASAdapter(),
	}
}

// Adapt adapts VLX bytes to pseudo-LISP source
func (a *VLXAdapter) Adapt(data []byte) (*VlxAdaptResult, error) {
	totalStart := time.Now()
	// Find LOAD( bounds
	start := time.Now()
	loadStart, _ := a.findLoadBounds(data)
	findBoundsTime := time.Since(start)
	if loadStart == -1 {
		return nil, fmt.Errorf("LOAD( section not found")
	}

	// Guess tail offset
	start = time.Now()
	tailOffset := a.guessTailOffset(data)
	guessTailTime := time.Since(start)
	if tailOffset == -1 {
		tailOffset = len(data)
	}

	// Parse records
	start = time.Now()
	records, warnings := a.parseRecords(data, loadStart, tailOffset)
	parseRecordsTime := time.Since(start)

	// Generate pseudo-LISP from all records
	var source strings.Builder
	source.WriteString(";; Pseudo-LISP generated from VLX file\n")
	source.WriteString(";; This is a simplified representation for static analysis\n\n")

	// Collect metadata
	meta := make(map[string]interface{})
	meta["record_count"] = len(records)
	meta["warnings"] = warnings
	fasCache := make(map[uint64]cachedFASAdapt)
	fasRecords := 0
	fasCacheHits := 0
	fasAdaptTime := time.Duration(0)
	lspBytes := 0
	dclBytes := 0

	// Process each record
	for _, rec := range records {
		if rec.ContentOffset >= rec.ContentEnd {
			continue
		}

		content := data[rec.ContentOffset:rec.ContentEnd]

		// Adapt based on inferred kind
		switch rec.InferredKind {
		case "fas":
			fasRecords++
			key := hashRecordContent(content)
			cached, ok := fasCache[key]
			if ok {
				fasCacheHits++
			} else {
				start = time.Now()
				fasResult, err := a.fasAdapter.Adapt(content)
				fasAdaptTime += time.Since(start)
				cached = cachedFASAdapt{result: fasResult, err: err}
				fasCache[key] = cached
			}
			fasResult, err := cached.result, cached.err
			if err != nil {
				source.WriteString(fmt.Sprintf(";; Failed to adapt FAS record %s: %v\n", rec.Name, err))
				continue
			}
			source.WriteString(fmt.Sprintf(";; FAS Record: %s\n", rec.Name))
			source.WriteString(fasResult.Source)
			source.WriteString("\n")

			// Merge metadata
			for k, v := range fasResult.Meta {
				key := fmt.Sprintf("%s_%s", rec.Name, k)
				meta[key] = v
			}
		case "lsp":
			lspBytes += len(content)
			source.WriteString(fmt.Sprintf(";; LSP Record: %s\n", rec.Name))
			source.WriteString(string(content))
			source.WriteString("\n")
		case "dcl":
			dclBytes += len(content)
			source.WriteString(fmt.Sprintf(";; DCL Record: %s\n", rec.Name))
			source.WriteString(string(content))
			source.WriteString("\n")
		default:
			source.WriteString(fmt.Sprintf(";; Unknown Record: %s (type: 0x%04X)\n", rec.Name, rec.TypeCode))
		}
	}

	totalTime := time.Since(totalStart)
	if debugutil.TimingEnabled() && (totalTime > 500*time.Millisecond || fasAdaptTime > 500*time.Millisecond) {
		fmt.Fprintf(os.Stderr,
			"  [VLX-TIMING] total=%v find=%v tail=%v records=%v fas_adapt=%v (records=%d fas=%d cache_hits=%d lsp_bytes=%d dcl_bytes=%d)\n",
			totalTime, findBoundsTime, guessTailTime, parseRecordsTime, fasAdaptTime,
			len(records), fasRecords, fasCacheHits, lspBytes, dclBytes)
	}

	return &VlxAdaptResult{
		Source: source.String(),
		Meta:   meta,
	}, nil
}

func hashRecordContent(content []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(content)
	return h.Sum64()
}

// findLoadBounds finds the LOAD( section bounds
func (a *VLXAdapter) findLoadBounds(data []byte) (int, int) {
	pos := bytes.Index(data, []byte("LOAD("))
	if pos < 0 {
		return -1, -1
	}
	nullPos := bytes.Index(data[pos:], []byte{0})
	if nullPos < 0 {
		return -1, -1
	}
	end := pos + nullPos
	return end + 1, end
}

// guessTailOffset guesses the tail offset
func (a *VLXAdapter) guessTailOffset(data []byte) int {
	if len(data) >= 12 {
		totalField := int(binary.LittleEndian.Uint32(data[8:12]))
		candidate := totalField + 4
		if candidate >= 0 && candidate < len(data) && bytes.HasPrefix(data[candidate:], []byte("VRTLIB-1")) {
			return candidate
		}
	}
	found := bytes.Index(data, []byte("VRTLIB-1"))
	if found >= 0 {
		return found
	}
	return len(data)
}

// parseRecords parses records from VLX data
func (a *VLXAdapter) parseRecords(data []byte, start, tail int) ([]VlxRecord, []string) {
	records := []VlxRecord{}
	warnings := []string{}

	pos := start
	idx := 0
	invalidHeaders := 0
	appendWarning := func(msg string) {
		if len(warnings) < maxVLXWarnings {
			warnings = append(warnings, msg)
		}
	}

	for pos+7 <= tail {
		// Skip null bytes
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
			appendWarning(fmt.Sprintf("invalid record length at offset %d: %d", pos, length))
			invalidHeaders++
			if invalidHeaders >= maxVLXInvalidHeaders {
				appendWarning(fmt.Sprintf("aborted record scan after %d invalid headers", invalidHeaders))
				break
			}
			pos++
			continue
		}
		if nameLen <= 0 || nameLen > 80 || pos+7+nameLen > len(data) {
			appendWarning(fmt.Sprintf("invalid record name_len at offset %d: %d", pos, nameLen))
			invalidHeaders++
			if invalidHeaders >= maxVLXInvalidHeaders {
				appendWarning(fmt.Sprintf("aborted record scan after %d invalid headers", invalidHeaders))
				break
			}
			pos++
			continue
		}

		nameRaw := data[pos+7 : pos+7+nameLen]
		name := string(nameRaw)

		contentOffset := pos + 7 + nameLen
		contentEnd := pos + length
		// Safety check: ensure content bounds are valid
		if contentOffset > contentEnd || contentEnd > len(data) {
			appendWarning(fmt.Sprintf("invalid content bounds at offset %d: offset=%d, end=%d, data_len=%d", pos, contentOffset, contentEnd, len(data)))
			invalidHeaders++
			if invalidHeaders >= maxVLXInvalidHeaders {
				appendWarning(fmt.Sprintf("aborted record scan after %d invalid headers", invalidHeaders))
				break
			}
			pos++
			continue
		}
		blob := data[contentOffset:contentEnd]

		inferred := a.inferKind(blob, typeCode)
		invalidHeaders = 0

		records = append(records, VlxRecord{
			Index:         idx,
			Offset:        pos,
			Length:        length,
			TypeCode:      typeCode,
			Name:          name,
			ContentOffset: contentOffset,
			ContentEnd:    contentEnd,
			InferredKind:  inferred,
		})

		pos += length
		idx++
	}

	return records, warnings
}

// inferKind infers the kind of record from content and type code
func (a *VLXAdapter) inferKind(blob []byte, typeCode int) string {
	switch typeCode {
	case 0x0532:
		return "fas"
	case 0x0546:
		return "dcl"
	case 0x0537:
		return "raw"
	}

	// Content-based detection
	if len(blob) >= 128 {
		if bytes.Contains(blob[:128], []byte("FAS4-FILE")) {
			return "fas"
		}
	}
	if len(blob) >= 512 {
		if bytes.Contains(blob[:512], []byte("(defun ")) || bytes.Contains(blob[:512], []byte("(setq ")) {
			return "lsp"
		}
		if bytes.Contains(blob[:512], []byte(": dialog{")) || bytes.Contains(blob[:512], []byte(":dialog{")) {
			return "dcl"
		}
	}

	return "unknown"
}
