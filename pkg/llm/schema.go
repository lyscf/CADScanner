package llm

import (
	"bytes"
	"encoding/json"
)

// SemanticLabel is the normalized semantic verdict label.
type SemanticLabel string

const (
	LabelBenign     SemanticLabel = "BENIGN"
	LabelSuspicious SemanticLabel = "SUSPICIOUS"
	LabelMalicious  SemanticLabel = "MALICIOUS"
)

// IOC describes a recovered indicator of compromise.
type IOC struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// FlexibleText accepts either a JSON string or a structured JSON value and
// stores the latter as compact JSON text so downstream callers can keep using
// it as a printable string field.
type FlexibleText string

func (t *FlexibleText) UnmarshalJSON(data []byte) error {
	if t == nil {
		return nil
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*t = ""
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*t = FlexibleText(s)
		return nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return err
	}
	*t = FlexibleText(buf.String())
	return nil
}

func (t FlexibleText) String() string {
	return string(t)
}

// SemanticAnalysis is the normalized LLM output used by the analyzer.
type SemanticAnalysis struct {
	Provider       string        `json:"provider,omitempty"`
	Model          string        `json:"model,omitempty"`
	Sample         string        `json:"sample,omitempty"`
	InputType      string        `json:"input_type,omitempty"`
	CacheKey       string        `json:"cache_key,omitempty"`
	CacheKeyVersion string       `json:"cache_key_version,omitempty"`
	EncodingHash   string        `json:"encoding_hash,omitempty"`
	CacheHit       bool          `json:"cache_hit,omitempty"`
	SemanticLabel  SemanticLabel `json:"semantic_label,omitempty"`
	Confidence     float64       `json:"confidence,omitempty"`
	ThreatPatterns []string      `json:"threat_patterns,omitempty"`
	IOCs           []IOC         `json:"iocs,omitempty"`
	AttackMapping  []string      `json:"attack_mapping,omitempty"`
	Reasoning      string        `json:"reasoning,omitempty"`
	TriageReport   FlexibleText  `json:"triage_report,omitempty"`
	PromptTokens   int           `json:"prompt_tokens,omitempty"`
	CompletionTokens int         `json:"completion_tokens,omitempty"`
	LatencyMs      float64       `json:"latency_ms,omitempty"`
	RawResponse    string        `json:"raw_response,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// Request contains the semantic-analysis request context.
type Request struct {
	Filepath             string
	InputType            string
	RuleVerdict          string
	RiskScore            float64
	MaliciousConfidence  float64
	MatchedRules         []string
	AttackTechniques     []string
	LLMEncoding          string
}
