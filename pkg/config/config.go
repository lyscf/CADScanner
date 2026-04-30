package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Analysis  AnalysisConfig  `yaml:"analysis"`
	Detection DetectionConfig `yaml:"detection"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	LLM       LLMConfig       `yaml:"llm"`
}

// AnalysisConfig contains analysis-related configuration
// Note: MaxFileSize and Timeout are reserved for future per-file limits
// (currently controlled at batch eval layer)
type AnalysisConfig struct {
	MaxFileSize         int64 `yaml:"max_file_size"` // Reserved: per-file size limit
	Timeout             int   `yaml:"timeout"`       // Reserved: per-analysis timeout seconds
	EnableVerbose       bool  `yaml:"enable_verbose"`
	EnableDeobfuscation bool  `yaml:"enable_deobfuscation"`
}

// DetectionConfig contains detection-related configuration
type DetectionConfig struct {
	RulePath     string  `yaml:"rule_path"`
	AttackPath   string  `yaml:"attack_path"`
	Threshold    float64 `yaml:"threshold"`
	EnableRules  bool    `yaml:"enable_rules"`
	EnableATTACK bool    `yaml:"enable_attack"`
}

// ScoringConfig contains scoring-related configuration
// Note: AttackWeights are reserved for future ATT&CK technique weighting
type ScoringConfig struct {
	DecisionThreshold float64            `yaml:"decision_threshold"`
	EnableFormal      bool               `yaml:"enable_formal"`
	PrimitiveWeight   float64            `yaml:"primitive_weight"`
	PatternWeight     float64            `yaml:"pattern_weight"`
	ContextWeight     float64            `yaml:"context_weight"`
	RuleWeight        float64            `yaml:"rule_weight"`
	AttackWeight      float64            `yaml:"attack_weight"`
	FeatureWeight     float64            `yaml:"feature_weight"`
	FormalWeight      float64            `yaml:"formal_weight"`
	SigmoidSlope      float64            `yaml:"sigmoid_slope"`
	ContextComponents map[string]float64 `yaml:"context_components"`
	AttackWeights     map[string]float64 `yaml:"attack_weights"` // Reserved: per-technique scoring weights
	RiskFloors        map[string]float64 `yaml:"risk_floors"`
	RuleMultipliers   map[string]float64 `yaml:"rule_multipliers"`
}

// LLMConfig contains optional LLM semantic-analysis configuration.
type LLMConfig struct {
	Enabled         bool    `yaml:"enabled"`
	Provider        string  `yaml:"provider"`
	BaseURL         string  `yaml:"base_url"`
	Model           string  `yaml:"model"`
	APIKey          string  `yaml:"api_key"`
	APIKeyEnv       string  `yaml:"api_key_env"`
	Temperature     float64 `yaml:"temperature"`
	MaxOutputTokens int     `yaml:"max_output_tokens"`
	TimeoutSeconds  int     `yaml:"timeout_seconds"`
	EnableFusion    bool    `yaml:"enable_fusion"`
	SystemPrompt    string  `yaml:"system_prompt"`
	CacheDir        string  `yaml:"cache_dir"`
}

// Load loads configuration from a YAML file
func Load(configPath string) (*Config, error) {
	cfg := &Config{}

	// Default configuration
	setDefaults(cfg)

	// Load from file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(cfg *Config) {
	cfg.Analysis = AnalysisConfig{
		MaxFileSize:         10 * 1024 * 1024, // 10MB
		Timeout:             30,
		EnableVerbose:       false,
		EnableDeobfuscation: true,
	}

	cfg.Detection = DetectionConfig{
		RulePath:     "",
		AttackPath:   "",
		Threshold:    0.5,
		EnableRules:  true,
		EnableATTACK: true,
	}

	cfg.Scoring = ScoringConfig{
		DecisionThreshold: 0.5,
		EnableFormal:      true,
		PrimitiveWeight:   0.5,
		PatternWeight:     0.3,
		ContextWeight:     0.2,
		RuleWeight:        0.30,
		AttackWeight:      0.25,
		FeatureWeight:     0.25,
		FormalWeight:      0.20,
		SigmoidSlope:      4.0,
		ContextComponents: map[string]float64{
			"env_awareness": 0.3,
			"persistence":   0.35,
			"execution":     0.35,
		},
		AttackWeights: map[string]float64{
			"T1547.001": 0.90,
			"T1059.003": 0.85,
			"T1059.005": 0.88,
			"T1059.007": 0.80,
			"T1105":     0.95,
			"T1106":     0.85,
			"T1112":     0.80,
			"T1218.010": 0.95,
			"T1027":     0.70,
			"T1140":     0.65,
			"T1082":     0.60,
			"T1083":     0.55,
			"T1070.004": 0.80,
			"T1564.001": 0.85,
			"T1071.001": 0.90,
			"T1543":     0.85,
			"T1055":     0.95,
		},
		RiskFloors: map[string]float64{
			"STARTUP_LOAD_001":     0.72,
			"STARTUP_REWRITE_001":  0.72,
			"WORM_REPL_001":        0.68,
			"WORM_001":             0.62,
			"DESTRUCT_001":         0.62,
			"NET_DROPPER_001":      0.74,
			"PROC_EXEC_001":        0.76,
			"STARTUP_HOOK_001":     0.70,
			"COM_DROPPER_001":      0.72,
			"SCRIPTCTRL_001":       0.76,
			"EXFIL_STUB_001":       0.70,
			"DESTRUCT_STUB_001":    0.70,
			"STARTUP_INFECT_001":   0.71,
			"REACT_PROP_001":       0.74,
			"REC_FAS_PROP_001":     0.70,
			"NET_STUB_001":         0.68,
			"FINDCOPY_001":         0.68,
			"STARTUP_COPY_STR_001": 0.66,
			"REGISTRY_001":         0.62,
			"BOOTDAT_CHAIN_001":    0.60,
		},
		RuleMultipliers: map[string]float64{
			"COM_DROPPER_001":  1.0,
			"FINDCOPY_001":     1.0,
			"NETWORK_001":      1.0,
			"NET_DROPPER_001":  1.0,
			"NET_STUB_001":     1.0,
			"REC_FAS_PROP_001": 1.0,
			"REGISTRY_001":     1.0,
		},
	}

	cfg.LLM = LLMConfig{
		Enabled:         false,
		Provider:        "openai_compatible",
		BaseURL:         "https://api.openai.com/v1",
		Model:           "",
		APIKey:          "",
		APIKeyEnv:       "OPENAI_API_KEY",
		Temperature:     0.0,
		MaxOutputTokens: 1200,
		TimeoutSeconds:  60,
		EnableFusion:    true,
		SystemPrompt:    "",
		CacheDir:        ".cadscanner-cache/llm",
	}
}

// GetConfigPath returns the default config file path
func GetConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".cadscanner", "config.yaml")
}
