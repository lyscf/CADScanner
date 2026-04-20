package llm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evilcad/cadscanner/pkg/config"
)

// Client implements an OpenAI-compatible chat completions client.
type Client struct {
	cfg        config.LLMConfig
	httpClient *http.Client
}

// NewClient creates a new semantic-analysis client.
func NewClient(cfg config.LLMConfig) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Analyze sends a semantic-analysis request to the configured model.
func (c *Client) Analyze(ctx context.Context, req Request) (*SemanticAnalysis, error) {
	apiKey := c.cfg.APIKey
	if apiKey == "" && c.cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(c.cfg.APIKeyEnv)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("missing API key for LLM provider")
	}
	if c.cfg.Model == "" {
		return nil, fmt.Errorf("missing llm.model configuration")
	}

	start := time.Now()
	systemPrompt := c.cfg.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = defaultSystemPrompt
	}

	cacheKey := c.cacheKey(systemPrompt, req)
	if cached, ok := c.loadCache(cacheKey); ok {
		if c.hydrateCachedAnalysis(cached, cacheKey, req) {
			c.storeCache(cacheKey, cached)
		}
		cached.CacheHit = true
		return cached, nil
	}

	payload := chatCompletionsRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(req)},
		},
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxOutputTokens,
		ResponseFormat: &responseFormat{
			Type: "json_object",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm api error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var completion chatCompletionsResponse
	if err := json.Unmarshal(respBody, &completion); err != nil {
		return nil, fmt.Errorf("decode llm completion: %w", err)
	}
	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("llm api returned no choices")
	}

	content := completion.Choices[0].Message.Content
	content = extractJSONObject(content)
	var analysis SemanticAnalysis
	if err := json.Unmarshal([]byte(content), &analysis); err != nil {
		return nil, fmt.Errorf("decode llm semantic analysis: %w", err)
	}

	analysis.Provider = c.cfg.Provider
	analysis.Model = c.cfg.Model
	analysis.Sample = req.Filepath
	analysis.InputType = req.InputType
	analysis.CacheKey = cacheKey
	analysis.CacheKeyVersion = "v2-semantic-only"
	analysis.EncodingHash = hashText(req.LLMEncoding)
	analysis.PromptTokens = completion.Usage.PromptTokens
	analysis.CompletionTokens = completion.Usage.CompletionTokens
	analysis.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	analysis.RawResponse = completion.Choices[0].Message.Content
	c.storeCache(cacheKey, &analysis)
	return &analysis, nil
}

const defaultSystemPrompt = `You are an AutoCAD malware analyst.
You receive recovered semantic context from a static analysis pipeline.
Return only valid JSON.

Required JSON fields:
- semantic_label: BENIGN | SUSPICIOUS | MALICIOUS
- confidence: number in [0,1]
- threat_patterns: string array
- iocs: array of objects with type and value
- attack_mapping: string array
- reasoning: short string
- triage_report: analyst-facing short report
`

func buildUserPrompt(req Request) string {
	return fmt.Sprintf(`Analyze the following AutoCAD script analysis context.

File: %s
Type: %s

Recovered semantic context:
%s
`, req.Filepath, req.InputType, req.LLMEncoding)
}

func extractJSONObject(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

// ResolveSystemPrompt returns the effective system prompt for the config.
func ResolveSystemPrompt(cfg config.LLMConfig) string {
	systemPrompt := cfg.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = defaultSystemPrompt
	}
	return systemPrompt
}

// ComputeCacheKey returns the deterministic cache key for a request.
func ComputeCacheKey(cfg config.LLMConfig, req Request) string {
	return computeCacheKey(cfg, ResolveSystemPrompt(cfg), req)
}

func (c *Client) cacheKey(systemPrompt string, req Request) string {
	return computeCacheKey(c.cfg, systemPrompt, req)
}

func computeCacheKey(cfg config.LLMConfig, systemPrompt string, req Request) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		cfg.Provider,
		cfg.BaseURL,
		cfg.Model,
		systemPrompt,
		req.Filepath,
		req.InputType,
		req.LLMEncoding,
	}, "\n")))
	return hex.EncodeToString(sum[:])
}

func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (c *Client) cachePath(key string) string {
	dir := c.cfg.CacheDir
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	return filepath.Join(dir, key+".json")
}

func (c *Client) loadCache(key string) (*SemanticAnalysis, bool) {
	path := c.cachePath(key)
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var analysis SemanticAnalysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return nil, false
	}
	if analysis.CacheKey == "" {
		analysis.CacheKey = key
	}
	if analysis.CacheKeyVersion == "" {
		analysis.CacheKeyVersion = "legacy"
	}
	return &analysis, true
}

func (c *Client) hydrateCachedAnalysis(analysis *SemanticAnalysis, cacheKey string, req Request) bool {
	if analysis == nil {
		return false
	}
	changed := false
	if analysis.Provider == "" && c.cfg.Provider != "" {
		analysis.Provider = c.cfg.Provider
		changed = true
	}
	if analysis.Model == "" && c.cfg.Model != "" {
		analysis.Model = c.cfg.Model
		changed = true
	}
	if analysis.Sample == "" && req.Filepath != "" {
		analysis.Sample = req.Filepath
		changed = true
	}
	if analysis.InputType == "" && req.InputType != "" {
		analysis.InputType = req.InputType
		changed = true
	}
	if analysis.CacheKey == "" {
		analysis.CacheKey = cacheKey
		changed = true
	}
	if analysis.CacheKeyVersion == "" {
		analysis.CacheKeyVersion = "legacy"
		changed = true
	}
	if analysis.EncodingHash == "" && req.LLMEncoding != "" {
		analysis.EncodingHash = hashText(req.LLMEncoding)
		changed = true
	}
	return changed
}

func (c *Client) storeCache(key string, analysis *SemanticAnalysis) {
	path := c.cachePath(key)
	if path == "" || analysis == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

type chatCompletionsRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float64         `json:"temperature,omitempty"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatCompletionsResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}
