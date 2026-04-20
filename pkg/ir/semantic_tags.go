package ir

// SemanticTag represents a semantic tag for IR effects
type SemanticTag string

const (
	// Environment check tags
	TAG_ENV_CHECK  SemanticTag = "ENV_CHECK"
	TAG_MAC_CHECK  SemanticTag = "MAC_CHECK"
	TAG_DATE_CHECK SemanticTag = "DATE_CHECK"
	TAG_HOST_ID    SemanticTag = "HOST_ID"
	TAG_FILE_CTX   SemanticTag = "FILE_CONTEXT"
	TAG_APP_CTX    SemanticTag = "APP_CONTEXT"
	TAG_SYS_CTX    SemanticTag = "SYSTEM_CONTEXT"

	// Persistence tags
	TAG_STARTUP_HOOK     SemanticTag = "STARTUP_HOOK"
	TAG_REGISTRY_MOD     SemanticTag = "REGISTRY_MOD"
	TAG_FILE_PERSISTENCE SemanticTag = "FILE_PERSISTENCE"
	TAG_SELF_REPLICATION SemanticTag = "SELF_REPLICATION"
	TAG_AUTOLOAD         SemanticTag = "AUTOLOAD"

	// Execution tags
	TAG_SHELL_EXEC   SemanticTag = "SHELL_EXEC"
	TAG_PROCESS_EXEC SemanticTag = "PROCESS_EXEC"
	TAG_COM_INVOKE   SemanticTag = "COM_INVOKE"
	TAG_CODE_EXEC    SemanticTag = "CODE_EXEC"
	TAG_DYNAMIC_EVAL SemanticTag = "DYNAMIC_EVAL"

	// Stealth tags
	TAG_FILE_HIDDEN     SemanticTag = "FILE_HIDDEN"
	TAG_REGISTRY_HIDDEN SemanticTag = "REGISTRY_HIDDEN"
	TAG_OBFUSCATION     SemanticTag = "OBFUSCATION"

	// Network tags
	TAG_NETWORK_CONNECT SemanticTag = "NETWORK_CONNECT"
	TAG_HTTP_REQUEST    SemanticTag = "HTTP_REQUEST"
	TAG_DOWNLOAD        SemanticTag = "DOWNLOAD"
	TAG_EXFILTRATION    SemanticTag = "EXFILTRATION"

	// Data tags
	TAG_DATA_DESTROY    SemanticTag = "DATA_DESTROY"
	TAG_DATA_EXFILTRATE SemanticTag = "DATA_EXFILTRATE"
	TAG_FILE_MODIFY     SemanticTag = "FILE_MODIFY"
)

// SemanticTagger assigns semantic tags to IR effects
type SemanticTagger struct {
	effectTypeToTags map[EffectType][]SemanticTag
}

// NewSemanticTagger creates a new semantic tagger
func NewSemanticTagger() *SemanticTagger {
	tagger := &SemanticTagger{
		effectTypeToTags: make(map[EffectType][]SemanticTag),
	}
	tagger.initializeMapping()
	return tagger
}

// initializeMapping initializes the effect type to tags mapping
func (st *SemanticTagger) initializeMapping() {
	// Environment checks
	st.effectTypeToTags[ENV_CHECK] = []SemanticTag{
		TAG_ENV_CHECK, TAG_MAC_CHECK, TAG_DATE_CHECK, TAG_HOST_ID, TAG_FILE_CTX, TAG_APP_CTX, TAG_SYS_CTX,
	}

	// Generic file writes are not persistence by default. More specific
	// path- or rule-based logic should assign persistence semantics.
	st.effectTypeToTags[FILE_WRITE] = []SemanticTag{
		TAG_FILE_MODIFY,
	}
	st.effectTypeToTags[REGISTRY_MODIFY] = []SemanticTag{
		TAG_REGISTRY_MOD, TAG_STARTUP_HOOK,
	}

	// Execution
	st.effectTypeToTags[PROCESS_CREATE] = []SemanticTag{
		TAG_PROCESS_EXEC, TAG_SHELL_EXEC,
	}
	st.effectTypeToTags[COM_CREATE] = []SemanticTag{
		TAG_COM_INVOKE,
	}
	st.effectTypeToTags[COM_INVOKE] = []SemanticTag{
		TAG_COM_INVOKE,
	}

	// Stealth
	st.effectTypeToTags[FILE_HIDDEN] = []SemanticTag{
		TAG_FILE_HIDDEN,
	}
	st.effectTypeToTags[REGISTRY_DELETE] = []SemanticTag{
		TAG_REGISTRY_HIDDEN,
	}

	// Network
	st.effectTypeToTags[NETWORK_CONNECT] = []SemanticTag{
		TAG_NETWORK_CONNECT, TAG_HTTP_REQUEST, TAG_DOWNLOAD,
	}

	// Data
	st.effectTypeToTags[DATA_EXFILTRATE] = []SemanticTag{
		TAG_EXFILTRATION,
	}
	st.effectTypeToTags[DATA_DESTROY] = []SemanticTag{
		TAG_DATA_DESTROY,
	}
	st.effectTypeToTags[FILE_DELETE] = []SemanticTag{
		TAG_FILE_MODIFY,
	}
}

// TagEffect assigns semantic tags to an IR effect
func (st *SemanticTagger) TagEffect(effect IREffect) []SemanticTag {
	tags, ok := st.effectTypeToTags[effect.EffectType]
	if !ok {
		return []SemanticTag{}
	}
	return tags
}

// TagEffects assigns semantic tags to multiple IR effects
func (st *SemanticTagger) TagEffects(effects []IREffect) map[string][]SemanticTag {
	result := make(map[string][]SemanticTag)
	for _, effect := range effects {
		effectKey := string(effect.EffectType) + ":" + effect.Target
		tags := st.TagEffect(effect)
		if len(tags) > 0 {
			result[effectKey] = tags
		}
	}
	return result
}

// GetTagsForType returns tags for a specific effect type
func (st *SemanticTagger) GetTagsForType(effectType EffectType) []SemanticTag {
	tags, ok := st.effectTypeToTags[effectType]
	if !ok {
		return []SemanticTag{}
	}
	return tags
}
