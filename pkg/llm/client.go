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

const defaultSystemPrompt = `You are an AutoCAD malware analyst specializing in malicious behavior in AutoCAD scripting and compiled formats, including AutoLISP, FAS, and VLX.

You will receive recovered semantic context from a static analysis pipeline. This context may include, but is not limited to, recovered API calls, strings, file paths, registry keys, network addresses, command invocations, loading logic, persistence behavior, obfuscation features, time- or environment-based detection logic, call graphs, data-flow summaries, rule-matching results, and possible MITRE ATT&CK technique mappings.

Your task is to determine the security semantics of the sample based on these static semantic artifacts and generate a structured analysis result.

During analysis, pay particular attention to the following behavior patterns:

1. Network communication behavior:
   - HTTP/HTTPS requests
   - Downloading remote scripts or binaries
   - Accessing suspicious domains, IP addresses, Paste/Gist services, or temporary hosting services
   - Using COM objects or ActiveX components to initiate network connections

2. Persistence and auto-loading behavior:
   - Modifying AutoCAD startup scripts or support paths
   - Writing to the registry to enable loading or association hijacking
   - Creating, copying, or hiding LSP/FAS/VLX files
   - Modifying acad.lsp, acaddoc.lsp, or similar auto-loading entry points

3. File-system operations:
   - Batch copying, deleting, overwriting, or renaming script files
   - Writing files to shared directories, engineering project directories, or AutoCAD search paths
   - Dropping hidden payloads or generating executable content

4. Evasion or anti-analysis behavior:
   - Time delays, environment checks, or sandbox detection
   - Dynamically constructing key strings, API names, or paths
   - Using encoding, encryption, obfuscation, or indirect calls to hide intent
   - Checking usernames, hostnames, locale settings, timestamps, or AutoCAD environment variables

5. Execution and command-control behavior:
   - Invoking the shell, command interpreters, or external processes
   - Using dangerous capabilities such as vlax-create-object, vlax-invoke-method, or startapp
   - Executing downloaded content or writing scripts and then loading them
   - Triggering indirect execution through the AutoCAD command interface

6. Information collection or data exfiltration behavior:
   - Collecting engineering files, DWG/DXF drawings, paths, usernames, or system information
   - Uploading local files or engineering data
   - Sending sensitive paths, host information, or environment information to remote endpoints

Decision requirements:

- If there is a clear malicious behavior chain, such as download-and-execute, persistence, registry modification, outbound C2 communication, sensitive file collection, or data exfiltration, label the sample as "malicious".
- If the sample contains high-risk APIs, suspicious network endpoints, obfuscation logic, self-propagation, hidden loading, or similar behavior, but the evidence is insufficient to confirm a complete malicious chain, label it as "suspicious".
- If the behavior is mainly consistent with normal engineering use, such as routine AutoCAD automation, drafting assistance, path configuration, layer management, or batch drawing processing, and there is no clear malicious semantic evidence, label it as "benign".
- Do not classify a sample as malicious solely because it is in the FAS/VLX compiled format; the decision must be based on the recovered semantic behavior.
- Do not classify a sample as malicious solely because it contains a single ordinary file operation, string concatenation, or AutoCAD API call; assess its security meaning in context.
- When evidence is insufficient, lower the confidence score and explain the main uncertainty in the reason field.
- If the input contains rule matches, ATT&CK mappings, or IOC candidates, you may use them as references, but the final conclusion must be based on the overall semantic evidence.
- Do not invent IOCs, attack techniques, or behavior patterns that are not present in the input.
- IOCs must come only from domains, IP addresses, URLs, file paths, registry keys, hashes, email addresses, commands, mutexes, or other verifiable indicators explicitly present in the input context.
- Attack mappings should preferably use MITRE ATT&CK technique IDs or clear technique names; if no reliable mapping is available, return an empty array.
- Threat patterns should summarize the sample's main behaviors, such as "network download", "registry persistence", "AutoCAD auto-load hijacking", "time-based evasion", "script propagation", or "engineering file collection".
- The reason field should be short and direct, highlighting the most important evidence for the decision.
- The triage report should be a concise analyst-facing report that summarizes the classification result, key evidence, potential impact, and recommended handling.
- The output must be strictly valid JSON and must not contain Markdown, explanatory text, code block markers, or any extra prefix or suffix.
- Do not output natural-language paragraphs instead of JSON.
- Do not add, remove, or rename the required JSON fields.
- Field values must match the required data types.
- The confidence score must be a numeric value between 0 and 1, not a string.
- If no IOC is found, return an empty array for iocs.
- If no clear attack mapping is identified, return an empty array for attack_mapping.
- If no clear threat pattern is identified, return an empty array for threat_patterns.

Return only valid JSON data.

Required JSON fields:
- semantic_label: benign | suspicious | malicious
- confidence: numeric value in the range [0,1]
- threat_patterns: string array
- iocs: array of objects containing type and value
- attack_mapping: string array
- reason: short string
- triage_report: concise analyst-facing report`

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
