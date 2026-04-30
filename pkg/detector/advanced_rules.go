package detector

import (
	"regexp"
	"strings"

	"github.com/evilcad/cadscanner/pkg/ir"
)

var advancedStartupPattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx)\b`)

func isAdvancedStartupTarget(target string) bool {
	lower := strings.ToLower(target)
	return strings.Contains(lower, "acad.lsp") ||
		strings.Contains(lower, "acaddoc.lsp") ||
		strings.Contains(lower, "acad.fas") ||
		strings.Contains(lower, "acad.vlx") ||
		strings.Contains(lower, ".mnl") ||
		strings.Contains(lower, "startup") ||
		advancedStartupPattern.MatchString(lower)
}

func isLikelyPayloadWriteTarget(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	if lower == "" {
		return false
	}
	if isAdvancedStartupTarget(lower) {
		return true
	}

	// Ignore short symbolic fragments frequently emitted by recovered VLX/FAS
	// metadata; they are not credible payload destinations.
	noiseTokens := []string{
		"/", "\\", ":", ":\\", "t", "nil", "true", "false", "found", "xml",
		"unknown", "error", "http", "https",
	}
	for _, token := range noiseTokens {
		if lower == token {
			return false
		}
	}
	if strings.HasPrefix(lower, "sym_") || strings.HasPrefix(lower, "fn_") || strings.HasPrefix(lower, "block_") {
		return false
	}
	if len(lower) <= 3 && !strings.Contains(lower, ".") && !strings.Contains(lower, "\\") && !strings.Contains(lower, "/") {
		return false
	}

	suspiciousPathHints := []string{
		"\\appdata\\", "\\startup\\", "\\start menu\\", "\\programdata\\", "\\windows\\",
		"/appdata/", "/startup/", "/programdata/", "/windows/",
	}
	for _, hint := range suspiciousPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}

	for _, ext := range []string{".exe", ".dll", ".scr", ".hta", ".js", ".vbs", ".wsf", ".bat", ".cmd", ".ps1", ".vbe", ".jar"} {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}

func isRecoveredSummaryEffect(effect ir.IREffect) bool {
	if effect.Metadata == nil {
		return false
	}
	if from, _ := effect.Metadata["recovered_from"].(string); from == "resource_summary" {
		return true
	}
	_, hasSummaryField := effect.Metadata["summary_field"]
	return hasSummaryField
}

func isConcretePayloadWriteEffect(effect ir.IREffect) bool {
	if effect.EffectType != ir.FILE_WRITE {
		return false
	}
	lower := lowerEffect(effect)
	if !(isLikelyPayloadWriteTarget(lower.target) || isLikelyPayloadWriteTarget(lower.source) || hasDownloadedContentHint(effect)) {
		return false
	}
	if !isRecoveredSummaryEffect(effect) {
		return true
	}
	return isAdvancedStartupTarget(lower.target) || isLikelyPayloadWriteTarget(lower.target)
}

func isDropperPayloadWriteEffect(effect ir.IREffect) bool {
	if !isConcretePayloadWriteEffect(effect) {
		return false
	}
	lower := lowerEffect(effect)
	text := lower.target + " " + lower.source
	if isAdvancedStartupTarget(lower.target) || isAdvancedStartupTarget(lower.source) {
		return true
	}
	for _, ext := range []string{".exe", ".dll", ".scr", ".hta", ".js", ".vbs", ".wsf", ".bat", ".cmd", ".ps1", ".vbe", ".jar", ".lsp", ".fas", ".vlx", ".mnl"} {
		if strings.Contains(text, ext) {
			return true
		}
	}
	return hasDownloadedContentHint(effect)
}

func hasStartupArtifactText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return isAdvancedStartupTarget(lower) ||
		strings.Contains(lower, "acaddoc") ||
		strings.Contains(lower, "acad.lsp") ||
		strings.Contains(lower, "acad.fas") ||
		strings.Contains(lower, "acad.vlx")
}

// DetectionRule represents a detection rule
type DetectionRule interface {
	Match(effects []ir.IREffect) bool
	GetID() string
	GetName() string
	GetDescription() string
	GetSeverity() float64
	GetTags() []string
}

// WormLikeRule detects worm-like self-replication behavior
type WormLikeRule struct{}

// Match checks if the effects match worm-like behavior
func (r *WormLikeRule) Match(effects []ir.IREffect) bool {
	hasStartupWrite := false
	hasFileCopy := false
	startupWriteCount := 0
	fileWriteCount := 0
	fileReadCount := 0
	hasWildcardLsp := false
	hasStartupVar := false

	for _, effect := range effects {
		lower := lowerEffect(effect)
		// Check for startup file writes
		if effect.EffectType == ir.FILE_WRITE {
			fileWriteCount++

			// Check for AutoCAD startup file patterns in target
			if isAdvancedStartupTarget(lower.target) {
				hasStartupWrite = true
				startupWriteCount++
			}

			// Check for wildcard patterns that suggest startup file enumeration
			if strings.Contains(lower.target, "*.lsp") ||
				strings.Contains(lower.target, "*.fas") ||
				strings.Contains(lower.target, "*.mnl") {
				hasWildcardLsp = true
			}

			// Check for variable names suggesting startup file operations
			// (e.g., "wnewacad", "newacad", "woldacad" used for startup file writes)
			if (strings.Contains(lower.target, "acad") && (strings.Contains(lower.target, "new") || strings.Contains(lower.target, "old"))) ||
				strings.Contains(lower.source, "newacad") ||
				strings.Contains(lower.source, "oldacad") ||
				strings.Contains(lower.source, "acaddoc") {
				hasStartupVar = true
			}

			// Check for FAS disassembly output containing startup file references
			// (e.g., ";; 016E: CALL ... 'acaddoc.fas ...")
			if strings.Contains(lower.target, "acaddoc.fas") ||
				strings.Contains(lower.target, "acad.fas") ||
				(strings.Contains(lower.target, ";;") && strings.Contains(lower.target, ".fas")) {
				hasStartupWrite = true
				startupWriteCount++
			}
		}

		// Check for file reads (potential source of copy)
		if effect.EffectType == ir.FILE_READ {
			fileReadCount++
		}

		// Check for writelsp usage (known malicious pattern)
		if effect.Source == "writelsp" {
			hasFileCopy = true
		}

		// Check for vl-file-copy in source
		if strings.Contains(lower.source, "vl-file-copy") {
			hasFileCopy = true
		}

		// Check for vl-directory-files (enumeration of LSP files)
		if strings.Contains(lower.source, "vl-directory-files") {
			if strings.Contains(lower.target, ".lsp") ||
				strings.Contains(lower.target, ".fas") {
				hasWildcardLsp = true
			}
		}
	}

	// Worm pattern: writes to startup files + has file copy behavior
	// Either: (1) startup write + explicit copy operation, or (2) multiple startup writes
	if hasStartupWrite && hasFileCopy {
		return true
	}

	// Multiple startup file writes is strong worm indicator
	if startupWriteCount >= 2 {
		return true
	}

	// Startup write + file read + multiple writes = self-replication pattern
	if hasStartupWrite && fileReadCount > 0 && fileWriteCount >= 2 {
		return true
	}

	// Wildcard LSP enumeration + file operations suggests worm behavior
	if hasWildcardLsp && fileWriteCount >= 2 {
		return true
	}

	// Startup variable patterns + file operations
	if hasStartupVar && fileWriteCount >= 2 && fileReadCount > 0 {
		return true
	}

	// FAS file pattern: disassembly comments containing startup file references
	// This indicates a compiled FAS file that references startup files
	if startupWriteCount >= 1 && fileWriteCount >= 2 {
		// Check if any target looks like FAS disassembly output
		for _, effect := range effects {
			if effect.EffectType == ir.FILE_WRITE {
				target := strings.ToLower(effect.Target)
				if strings.Contains(target, ";;") && strings.Contains(target, ".fas") {
					return true
				}
			}
		}
	}

	return false
}

func (r *WormLikeRule) GetID() string {
	return "WORM_001"
}

func (r *WormLikeRule) GetName() string {
	return "Worm-like LISP"
}

func (r *WormLikeRule) GetDescription() string {
	return "Self-replicating script with startup hook"
}

func (r *WormLikeRule) GetSeverity() float64 {
	return 0.95
}

func (r *WormLikeRule) GetTags() []string {
	return []string{"persistence", "replication"}
}

// CommandHijackRule detects command hijacking
type CommandHijackRule struct{}

// Match checks if the effects match command hijacking
func (r *CommandHijackRule) Match(effects []ir.IREffect) bool {
	undefinedCommands := make(map[string]bool)
	redefinedCommands := make(map[string]bool)

	for _, effect := range effects {
		// Check for command undefine
		if effect.EffectType == ir.COMMAND_UNDEFINE {
			cmd := effect.Target
			undefinedCommands[cmd] = true
		}

		// Check for command redefine (c: prefix commands)
		if effect.EffectType == ir.FILE_WRITE || effect.EffectType == ir.COM_CREATE {
			source := strings.ToLower(effect.Source)
			target := strings.ToLower(effect.Target)
			if strings.HasPrefix(source, "defun") && strings.HasPrefix(target, "c:") {
				cmd := strings.TrimPrefix(target, "c:")
				redefinedCommands[cmd] = true
			}
		}
	}

	// Check for overlap
	for cmd := range undefinedCommands {
		if redefinedCommands[cmd] {
			return true
		}
	}

	return false
}

func (r *CommandHijackRule) GetID() string {
	return "HIJACK_001"
}

func (r *CommandHijackRule) GetName() string {
	return "Command Hijacking"
}

func (r *CommandHijackRule) GetDescription() string {
	return "Redefines critical AutoCAD commands"
}

func (r *CommandHijackRule) GetSeverity() float64 {
	return 0.90
}

func (r *CommandHijackRule) GetTags() []string {
	return []string{"command_hook", "persistence"}
}

// StealthPersistenceRule detects stealth persistence mechanisms
type StealthPersistenceRule struct{}

// Match checks if the effects match stealth persistence
func (r *StealthPersistenceRule) Match(effects []ir.IREffect) bool {
	hasRegistryHide := false
	hasPersistence := false

	for _, effect := range effects {
		// Check for registry hiding
		if effect.EffectType == ir.FILE_HIDDEN || effect.EffectType == ir.REGISTRY_MODIFY {
			if strings.Contains(strings.ToLower(effect.Target), "hide") {
				hasRegistryHide = true
			}
		}
		if strings.Contains(strings.ToLower(effect.Target), "hide") && effect.EffectType == ir.REGISTRY_MODIFY {
			hasRegistryHide = true
		}

		// Check for persistence
		if effect.EffectType == ir.FILE_WRITE {
			target := strings.ToLower(effect.Target)
			if strings.Contains(target, "startup") || strings.Contains(target, "acaddoc") {
				hasPersistence = true
			}
		}
	}

	return hasRegistryHide && hasPersistence
}

func (r *StealthPersistenceRule) GetID() string {
	return "STEALTH_001"
}

func (r *StealthPersistenceRule) GetName() string {
	return "Stealth Persistence"
}

func (r *StealthPersistenceRule) GetDescription() string {
	return "Persistence with registry hiding"
}

func (r *StealthPersistenceRule) GetSeverity() float64 {
	return 0.92
}

func (r *StealthPersistenceRule) GetTags() []string {
	return []string{"persistence", "stealth", "registry"}
}

// EnvironmentAwareRule detects environment-aware malware
type EnvironmentAwareRule struct{}

// Match checks if the effects match environment-aware behavior
func (r *EnvironmentAwareRule) Match(effects []ir.IREffect) bool {
	hasEnvCheck := false
	hasDelayedExecution := false

	for _, effect := range effects {
		// Check for environment checks
		if effect.EffectType == ir.ENV_CHECK {
			hasEnvCheck = true
		}

		// Check for delayed execution indicators
		source := strings.ToLower(effect.Source)
		if strings.Contains(source, "time") || strings.Contains(source, "date") {
			hasDelayedExecution = true
		}
	}

	return hasEnvCheck && hasDelayedExecution
}

func (r *EnvironmentAwareRule) GetID() string {
	return "ENVAWARE_001"
}

func (r *EnvironmentAwareRule) GetName() string {
	return "Environment-Aware Malware"
}

func (r *EnvironmentAwareRule) GetDescription() string {
	return "Checks environment before executing payload"
}

func (r *EnvironmentAwareRule) GetSeverity() float64 {
	return 0.85
}

func (r *EnvironmentAwareRule) GetTags() []string {
	return []string{"evasion", "targeted"}
}

// NetworkActivityRule detects network-based malicious activity
// This rule triggers when multiple network COM objects are created
// indicating potential C2 communication or data exfiltration
type NetworkActivityRule struct{}

// Match checks if the effects match network-based malicious activity
func (r *NetworkActivityRule) Match(effects []ir.IREffect) bool {
	hasNetworkConnect := false
	hasPayloadWrite := false
	hasProcessExec := false
	hasSuspiciousURLShape := false
	hasConcreteXMLHTTP := false
	hasConcreteADODB := false
	hasConcreteShell := false
	hasConcreteNetwork := false

	for _, effect := range effects {
		switch effect.EffectType {
		case ir.COM_CREATE, ir.COM_INVOKE:
			cleanText := cleanLowerEffectText(effect)
			if strings.Contains(cleanText, "xmlhttp") ||
				strings.Contains(cleanText, "serverxmlhttp") ||
				strings.Contains(cleanText, "msxml") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteXMLHTTP = true
				}
			}
			if strings.Contains(cleanText, "adodb.stream") || strings.Contains(cleanText, "adodb.connection") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteADODB = true
				}
			}
			if strings.Contains(cleanText, "shell.application") || strings.Contains(cleanText, "wscript.shell") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteShell = true
				}
			}
		case ir.NETWORK_CONNECT:
			hasNetworkConnect = true
			if !isRecoveredSummaryEffect(effect) {
				hasConcreteNetwork = true
			}
			lower := lowerEffect(effect)
			if strings.Contains(lower.target, "?") || strings.Contains(lower.target, "%") {
				hasSuspiciousURLShape = true
			}
		case ir.FILE_WRITE:
			if isDropperPayloadWriteEffect(effect) {
				hasPayloadWrite = true
			}
		case ir.PROCESS_CREATE:
			if IsSuspiciousProcessCommand(effect.Target) {
				hasProcessExec = true
			}
		}
	}

	// XMLHTTP paired with a file sink or execution pivot is suspicious.
	if hasConcreteXMLHTTP && hasNetworkConnect && (hasPayloadWrite || hasProcessExec || (hasConcreteShell && hasSuspiciousURLShape)) {
		return true
	}

	// Real network activity becomes high risk only when followed by disk write or execution.
	if hasConcreteNetwork && (hasPayloadWrite || hasProcessExec || (hasConcreteADODB && hasConcreteShell && hasSuspiciousURLShape)) {
		return true
	}

	// Explicit COM download chain.
	if hasConcreteXMLHTTP && hasNetworkConnect && hasPayloadWrite {
		return true
	}

	return false
}

func (r *NetworkActivityRule) GetID() string {
	return "NETWORK_001"
}

func (r *NetworkActivityRule) GetName() string {
	return "Network Activity"
}

func (r *NetworkActivityRule) GetDescription() string {
	return "Creates network COM objects for potential C2 or data exfiltration"
}

func (r *NetworkActivityRule) GetSeverity() float64 {
	return 0.90
}

func (r *NetworkActivityRule) GetTags() []string {
	return []string{"network", "c2", "exfiltration"}
}

// VBACodeInjectionRule detects VBA macro virus code injection behavior
// This rule triggers when VBA code uses InsertLines/AddFromString to inject
// malicious code into AutoCAD documents via VBProject/CodeModule
type VBACodeInjectionRule struct{}

// Match checks if the effects match VBA code injection patterns
func (r *VBACodeInjectionRule) Match(effects []ir.IREffect) bool {
	hasCodeInject := false
	hasVBProjectAccess := false
	hasAcaddocRef := false
	hasFilePropagation := false
	hasReactorHook := false

	for _, effect := range effects {
		lower := lowerEffect(effect)

		// Check for COM invoke with InsertLines or AddFromString
		// These are VBA methods used for code injection
		if effect.EffectType == ir.COM_INVOKE {
			// Direct method name match
			if strings.Contains(lower.source, "insertlines") ||
				strings.Contains(lower.source, "addfromstring") ||
				strings.Contains(lower.target, "insertlines") ||
				strings.Contains(lower.target, "addfromstring") {
				hasCodeInject = true
			}
			// vlax-invoke-method is the VBA adapter's COM invoke pattern
			if strings.Contains(lower.source, "vlax-invoke") {
				hasCodeInject = true
			}
		}

		// Check for VBProject/CodeModule access (COM_CREATE for _code object)
		if effect.EffectType == ir.COM_CREATE || effect.EffectType == ir.COM_INVOKE {
			if strings.Contains(lower.source, "vbproject") ||
				strings.Contains(lower.source, "codemodule") ||
				strings.Contains(lower.target, "vbproject") ||
				strings.Contains(lower.target, "codemodule") {
				hasVBProjectAccess = true
			}
			// vlax-get-property for VBProject/CodeModule access
			if strings.Contains(lower.source, "vlax-get") {
				hasVBProjectAccess = true
			}
		}

		// Check for acaddoc.lsp references (persistence target)
		if strings.Contains(lower.source, "acaddoc") || strings.Contains(lower.target, "acaddoc") {
			hasAcaddocRef = true
		}

		// Check for file propagation (vl-file-copy to acaddoc)
		if effect.EffectType == ir.FILE_WRITE || effect.EffectType == ir.FILE_READ {
			if strings.Contains(lower.source, "vl-file-copy") ||
				strings.Contains(lower.source, "vlax-invoke") {
				hasFilePropagation = true
			}
			// Check target for acaddoc in file operations
			if strings.Contains(lower.target, "acaddoc") {
				hasAcaddocRef = true
			}
		}

		// Check for reactor hooks (vlr-dwg-reactor pattern)
		if effect.EffectType == ir.ENV_CHECK || effect.EffectType == ir.COM_INVOKE {
			if strings.Contains(lower.source, "reactor") || strings.Contains(lower.target, "reactor") ||
				strings.Contains(lower.source, "vlr-") || strings.Contains(lower.target, "vlr-") {
				hasReactorHook = true
			}
		}
	}

	// VBA macro virus pattern: code injection + persistence target
	if hasCodeInject && hasAcaddocRef {
		return true
	}

	// VBProject access + file propagation suggests macro virus
	if hasVBProjectAccess && hasFilePropagation {
		return true
	}

	// Acaddoc reference + vl-file-copy (classic VBA propagation)
	if hasAcaddocRef && hasFilePropagation {
		return true
	}

	// vlax-invoke + acaddoc (VBA adapter pattern)
	if hasCodeInject && hasAcaddocRef {
		return true
	}

	// All four indicators present (strong confidence)
	if hasCodeInject && hasVBProjectAccess && hasAcaddocRef && hasReactorHook {
		return true
	}

	return false
}

func (r *VBACodeInjectionRule) GetID() string {
	return "VBA_INJECT_001"
}

func (r *VBACodeInjectionRule) GetName() string {
	return "VBA Code Injection"
}

func (r *VBACodeInjectionRule) GetDescription() string {
	return "VBA macro virus injecting code via VBProject/CodeModule"
}

func (r *VBACodeInjectionRule) GetSeverity() float64 {
	return 0.95
}

func (r *VBACodeInjectionRule) GetTags() []string {
	return []string{"vba", "macro", "code_injection", "persistence"}
}

// WormSelfReplicationRule detects worm-like self-replication behavior
// This rule catches files that copy themselves to multiple targets using app functions
// and perform bidirectional propagation (infecting both source and target)
type WormSelfReplicationRule struct{}

func (r *WormSelfReplicationRule) Match(effects []ir.IREffect) bool {
	hasFileCopyFunc := false
	hasAcaddocTarget := false
	hasSourceTargetPattern := false
	fileWriteCount := 0
	fileReadCount := 0
	commandHijackCount := 0

	for _, effect := range effects {
		source := strings.ToLower(effect.Source)
		target := strings.ToLower(effect.Target)

		// Check for file write operations
		if effect.EffectType == ir.FILE_WRITE {
			fileWriteCount++
			if strings.Contains(source, "app") || strings.Contains(source, "copy") ||
				strings.Contains(source, "open") || strings.Contains(source, "write") {
				hasFileCopyFunc = true
			}
			// Check for source/target pattern (common in copy functions)
			if target == "source" || target == "target" {
				hasSourceTargetPattern = true
			}
			// Check for acaddoc.lsp target
			if strings.Contains(target, "acaddoc") {
				hasAcaddocTarget = true
			}
		}

		// Check for file read (source of copy)
		if effect.EffectType == ir.FILE_READ {
			fileReadCount++
			if strings.Contains(source, "app") || strings.Contains(source, "copy") ||
				strings.Contains(source, "read") {
				hasFileCopyFunc = true
			}
		}

		// Count command hijacks (malicious behavior indicator)
		if effect.EffectType == ir.COMMAND_HIJACK {
			commandHijackCount++
		}

		// Check for acaddoc.lsp target in any effect
		if strings.Contains(target, "acaddoc") || strings.Contains(source, "acaddoc") {
			hasAcaddocTarget = true
		}
	}

	// Strong worm indicator: file copy pattern + multiple command hijacks
	if hasFileCopyFunc && commandHijackCount >= 3 {
		return true
	}

	// Source/target pattern with file operations (copy function params)
	if hasSourceTargetPattern && fileWriteCount >= 2 && fileReadCount >= 1 {
		return true
	}

	// Multiple file operations + command hijacks (propagation + sabotage)
	if fileWriteCount >= 2 && fileReadCount >= 1 && commandHijackCount >= 2 {
		return true
	}

	// Self-replication with acaddoc target
	if hasFileCopyFunc && hasAcaddocTarget {
		return true
	}

	return false
}

func (r *WormSelfReplicationRule) GetID() string {
	return "WORM_REPL_001"
}

func (r *WormSelfReplicationRule) GetName() string {
	return "Worm Self-Replication"
}

func (r *WormSelfReplicationRule) GetDescription() string {
	return "Worm virus copying itself to multiple startup files"
}

func (r *WormSelfReplicationRule) GetSeverity() float64 {
	return 0.92
}

func (r *WormSelfReplicationRule) GetTags() []string {
	return []string{"worm", "self_replication", "acaddoc", "propagation"}
}

// DataDestructionRule detects data destruction behavior
// This rule catches files that erase content or corrupt backup files
type DataDestructionRule struct{}

func (r *DataDestructionRule) Match(effects []ir.IREffect) bool {
	hasEraseAll := false
	hasCorruptBackup := false
	hasMassDelete := false

	for _, effect := range effects {
		target := strings.ToLower(effect.Target)

		// Check for erase all command via COMMAND_HIJACK or OS_EXEC
		if effect.EffectType == ir.COMMAND_HIJACK || effect.EffectType == ir.PROCESS_CREATE {
			if strings.Contains(target, "erase") && strings.Contains(target, "all") {
				hasEraseAll = true
			}
		}

		// Check for command hijack targeting destructive commands
		if effect.EffectType == ir.COMMAND_HIJACK {
			if strings.Contains(target, "erase") || strings.Contains(target, "delete") {
				hasMassDelete = true
			}
		}

		// Check for writing to backup files (.bak)
		if effect.EffectType == ir.FILE_WRITE {
			if strings.Contains(target, ".bak") || strings.Contains(target, "backup") {
				hasCorruptBackup = true
			}
			// Writing garbage content (short strings like "ja ja ja")
			if strings.Contains(target, "ja") || strings.Contains(target, "universidad") {
				hasCorruptBackup = true
			}
		}

		// Check for process create with destructive intent
		if effect.EffectType == ir.PROCESS_CREATE {
			if strings.Contains(target, "erase") || strings.Contains(target, "delete") {
				hasMassDelete = true
			}
		}
	}

	// Data destruction: erase all content
	if hasEraseAll {
		return true
	}

	// Corrupting backup files (writing garbage to .bak files)
	if hasCorruptBackup {
		return true
	}

	// Mass delete operations
	if hasMassDelete {
		return true
	}

	return false
}

func (r *DataDestructionRule) GetID() string {
	return "DESTRUCT_001"
}

func (r *DataDestructionRule) GetName() string {
	return "Data Destruction"
}

func (r *DataDestructionRule) GetDescription() string {
	return "Malicious code destroying or corrupting data and backups"
}

func (r *DataDestructionRule) GetSeverity() float64 {
	return 0.90
}

func (r *DataDestructionRule) GetTags() []string {
	return []string{"destruction", "erase", "corrupt", "backup", "sabotage"}
}

// DirectoryTraversalInfectionRule detects directory traversal + infection patterns
// This rule catches files that scan directories and infect all found files
type DirectoryTraversalInfectionRule struct{}

func (r *DirectoryTraversalInfectionRule) Match(effects []ir.IREffect) bool {
	hasDirTraversal := false
	hasFileIteration := false
	hasInfectionPattern := false

	for _, effect := range effects {
		source := strings.ToLower(effect.Source)
		target := strings.ToLower(effect.Target)

		// Check for directory file listing (vl-directory-files)
		if strings.Contains(source, "vl-directory-files") ||
			strings.Contains(target, "vl-directory-files") ||
			strings.Contains(source, "directory") ||
			strings.Contains(target, "*.lsp") ||
			strings.Contains(target, "*.mnl") {
			hasDirTraversal = true
		}

		// Check for while loop with file operations (iteration pattern)
		if strings.Contains(source, "while") || strings.Contains(source, "repeat") {
			hasFileIteration = true
		}

		// Check for file operations combined with iteration
		if effect.EffectType == ir.FILE_WRITE || effect.EffectType == ir.FILE_READ {
			if strings.Contains(source, "app") ||
				strings.Contains(source, "nth") ||
				strings.Contains(source, "strcat") {
				hasInfectionPattern = true
			}
		}
	}

	// Directory traversal + infection = worm spreading
	if hasDirTraversal && hasInfectionPattern {
		return true
	}

	// Multiple indicators
	if hasDirTraversal && hasFileIteration && hasInfectionPattern {
		return true
	}

	return false
}

func (r *DirectoryTraversalInfectionRule) GetID() string {
	return "DIR_TRAV_001"
}

func (r *DirectoryTraversalInfectionRule) GetName() string {
	return "Directory Traversal Infection"
}

func (r *DirectoryTraversalInfectionRule) GetDescription() string {
	return "Worm scanning directories and infecting multiple files"
}

func (r *DirectoryTraversalInfectionRule) GetSeverity() float64 {
	return 0.88
}

func (r *DirectoryTraversalInfectionRule) GetTags() []string {
	return []string{"worm", "directory", "traversal", "infection", "mass_propagation"}
}

// StartupLoadRule detects execution of sensitive AutoCAD startup-chain files.
// Loading these files directly is a strong malicious indicator in this corpus,
// even when the sample is just a launcher stub.
type StartupLoadRule struct{}

func (r *StartupLoadRule) Match(effects []ir.IREffect) bool {
	for _, effect := range effects {
		if effect.EffectType != ir.FILE_READ {
			continue
		}
		if !strings.EqualFold(effect.Source, "load") {
			continue
		}
		if isAdvancedStartupTarget(effect.Target) {
			return true
		}
	}
	return false
}

func (r *StartupLoadRule) GetID() string {
	return "STARTUP_LOAD_001"
}

func (r *StartupLoadRule) GetName() string {
	return "Sensitive Startup LISP Load"
}

func (r *StartupLoadRule) GetDescription() string {
	return "Loads AutoCAD startup-chain code such as acad*.lsp/acaddoc*.lsp"
}

func (r *StartupLoadRule) GetSeverity() float64 {
	return 0.96
}

func (r *StartupLoadRule) GetTags() []string {
	return []string{"execution", "startup_chain", "autoload", "lisp"}
}

// NetworkDropperRule detects download-and-write behavior.
type NetworkDropperRule struct{}

func (r *NetworkDropperRule) Match(effects []ir.IREffect) bool {
	hasNetwork := false
	hasPayloadWrite := false
	hasConcreteNetwork := false
	for _, effect := range effects {
		switch effect.EffectType {
		case ir.NETWORK_CONNECT:
			hasNetwork = true
			if !isRecoveredSummaryEffect(effect) {
				hasConcreteNetwork = true
			}
		case ir.FILE_WRITE:
			if isDropperPayloadWriteEffect(effect) {
				hasPayloadWrite = true
			}
		}
	}
	return hasNetwork && hasPayloadWrite && hasConcreteNetwork
}

func hasDownloadedContentHint(effect ir.IREffect) bool {
	if effect.Metadata == nil {
		return false
	}
	content, _ := effect.Metadata["content"].(string)
	content = strings.ToLower(strings.TrimSpace(content))
	if strings.HasPrefix(content, "http://") || strings.HasPrefix(content, "https://") {
		return true
	}
	if inferred, _ := effect.Metadata["inferred_from"].(string); inferred == "unknown_call_args" {
		target := strings.ToLower(strings.TrimSpace(effect.Target))
		return strings.HasSuffix(target, ".dcl") || strings.HasSuffix(target, ".lsp") || strings.HasSuffix(target, ".fas")
	}
	return false
}

func (r *NetworkDropperRule) GetID() string {
	return "NET_DROPPER_001"
}

func (r *NetworkDropperRule) GetName() string {
	return "Network Downloader Dropper"
}

func (r *NetworkDropperRule) GetDescription() string {
	return "Downloads content from network and writes it to disk"
}

func (r *NetworkDropperRule) GetSeverity() float64 {
	return 0.96
}

func (r *NetworkDropperRule) GetTags() []string {
	return []string{"network", "dropper", "download", "file_write"}
}

// SuspiciousProcessExecRule detects dangerous OS command execution.
type SuspiciousProcessExecRule struct{}

func (r *SuspiciousProcessExecRule) Match(effects []ir.IREffect) bool {
	for _, effect := range effects {
		if effect.EffectType != ir.PROCESS_CREATE {
			continue
		}
		if IsSuspiciousProcessCommand(effect.Target) {
			return true
		}
	}
	return false
}

func (r *SuspiciousProcessExecRule) GetID() string {
	return "PROC_EXEC_001"
}

func (r *SuspiciousProcessExecRule) GetName() string {
	return "Suspicious Process Execution"
}

func (r *SuspiciousProcessExecRule) GetDescription() string {
	return "Executes suspicious system commands such as regedit or net user/share"
}

func (r *SuspiciousProcessExecRule) GetSeverity() float64 {
	return 0.97
}

func (r *SuspiciousProcessExecRule) GetTags() []string {
	return []string{"execution", "os_command", "persistence", "system"}
}

// COMDropperRule detects a typical COM-based download chain.
type COMDropperRule struct{}

func (r *COMDropperRule) Match(effects []ir.IREffect) bool {
	hasSuspiciousProcess := false
	hasPayloadWrite := false
	hasConcreteChain := false
	hasConcreteShell := false
	hasConcreteXMLHTTP := false
	hasConcreteADODB := false
	hasConcreteNetwork := false
	for _, effect := range effects {
		switch effect.EffectType {
		case ir.COM_CREATE, ir.COM_INVOKE:
			lower := lowerEffect(effect)
			if strings.Contains(lower.text, "shell.application") || strings.Contains(lower.text, "wscript.shell") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteChain = true
					hasConcreteShell = true
				}
			}
			if strings.Contains(lower.text, "xmlhttp") || strings.Contains(lower.text, "msxml") || strings.Contains(lower.text, "serverxmlhttp") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteChain = true
					hasConcreteXMLHTTP = true
				}
			}
			if strings.Contains(lower.text, "adodb.stream") || strings.Contains(lower.text, "adodb.connection") {
				if !isRecoveredSummaryEffect(effect) {
					hasConcreteChain = true
					hasConcreteADODB = true
				}
			}
		case ir.NETWORK_CONNECT:
			if !isRecoveredSummaryEffect(effect) {
				hasConcreteChain = true
				hasConcreteNetwork = true
			}
		case ir.PROCESS_CREATE:
			if IsSuspiciousProcessCommand(effect.Target) {
				hasSuspiciousProcess = true
				hasConcreteChain = true
			}
		case ir.FILE_WRITE:
			if isDropperPayloadWriteEffect(effect) {
				hasPayloadWrite = true
				hasConcreteChain = true
			}
		}
	}
	return hasConcreteChain && ((hasConcreteXMLHTTP && hasConcreteADODB && (hasPayloadWrite || hasSuspiciousProcess)) ||
		(hasConcreteADODB && hasConcreteShell && (hasPayloadWrite || hasSuspiciousProcess)) ||
		(hasConcreteXMLHTTP && hasConcreteShell && (hasPayloadWrite || hasSuspiciousProcess)) ||
		(hasConcreteXMLHTTP && hasSuspiciousProcess) ||
		(hasConcreteNetwork && hasConcreteADODB && (hasPayloadWrite || hasSuspiciousProcess)))
}

func (r *COMDropperRule) GetID() string {
	return "COM_DROPPER_001"
}

func (r *COMDropperRule) GetName() string {
	return "COM Downloader Dropper"
}

func (r *COMDropperRule) GetDescription() string {
	return "Uses Shell/XMLHTTP/ADODB style COM chain for download and execution"
}

func (r *COMDropperRule) GetSeverity() float64 {
	return 0.96
}

func (r *COMDropperRule) GetTags() []string {
	return []string{"com", "download", "dropper", "execution"}
}

// ScriptControlDropperRule detects ScriptControl-based payload staging chains.
// This focuses on high-signal combinations seen in malicious FAS samples:
// ScriptControl paired with ADODB.Stream, WSF output, or WSH warning suppression.
type ScriptControlDropperRule struct{}

func (r *ScriptControlDropperRule) Match(effects []ir.IREffect) bool {
	hasScriptControl := false
	hasADODB := false
	hasWSFWrite := false
	hasWSHSettingsWrite := false

	for _, effect := range effects {
		lower := lowerEffect(effect)

		switch effect.EffectType {
		case ir.COM_CREATE, ir.COM_INVOKE:
			if strings.Contains(lower.text, "scriptcontrol") || strings.Contains(lower.text, "msscriptcontrol") {
				hasScriptControl = true
			}
			if strings.Contains(lower.text, "adodb.stream") || strings.Contains(lower.text, "adodb.connection") {
				hasADODB = true
			}
		case ir.FILE_WRITE:
			if strings.Contains(lower.target, ".wsf") || strings.Contains(lower.source, ".wsf") {
				hasWSFWrite = true
			}
		case ir.REGISTRY_MODIFY:
			if strings.Contains(lower.text, "windows script host\\settings") ||
				strings.Contains(lower.text, "windows script host/settings") {
				hasWSHSettingsWrite = true
			}
		}
	}

	if !hasScriptControl {
		return false
	}

	return hasADODB || hasWSFWrite || hasWSHSettingsWrite
}

func (r *ScriptControlDropperRule) GetID() string {
	return "SCRIPTCTRL_001"
}

func (r *ScriptControlDropperRule) GetName() string {
	return "ScriptControl Payload Stager"
}

func (r *ScriptControlDropperRule) GetDescription() string {
	return "Uses ScriptControl with COM/script staging artifacts such as ADODB.Stream or WSF output"
}

func (r *ScriptControlDropperRule) GetSeverity() float64 {
	return 0.97
}

func (r *ScriptControlDropperRule) GetTags() []string {
	return []string{"scriptcontrol", "com", "dropper", "wsh", "payload_staging"}
}

// StartupInfectorRule detects bulk file-rewrite startup infector patterns.
type StartupInfectorRule struct{}

func (r *StartupInfectorRule) Match(effects []ir.IREffect) bool {
	fileOps := 0
	hasStartupArtifact := false
	for _, effect := range effects {
		if effect.EffectType == ir.FILE_WRITE || effect.EffectType == ir.FILE_READ {
			fileOps++
		}
		target := strings.ToLower(effect.Target)
		if strings.Contains(target, "acadisa.lin") ||
			strings.Contains(target, "base.dcl") ||
			strings.Contains(target, "acad.lsp") ||
			strings.Contains(target, "acaddoc") {
			hasStartupArtifact = true
		}
	}
	return hasStartupArtifact && fileOps >= 8
}

func (r *StartupInfectorRule) GetID() string {
	return "STARTUP_INFECT_001"
}

func (r *StartupInfectorRule) GetName() string {
	return "Startup File Infector"
}

func (r *StartupInfectorRule) GetDescription() string {
	return "Performs repeated file rewrite operations against AutoCAD startup-chain artifacts"
}

func (r *StartupInfectorRule) GetSeverity() float64 {
	return 0.95
}

func (r *StartupInfectorRule) GetTags() []string {
	return []string{"startup", "infector", "file_rewrite", "persistence"}
}

// ReactorPropagationRule detects reactor-driven propagation chains recovered
// from obfuscated FAS samples: reactor hook + file discovery/copy behavior.
type ReactorPropagationRule struct{}

func (r *ReactorPropagationRule) Match(effects []ir.IREffect) bool {
	hasReactor := false
	hasFindfile := false
	hasFileCopy := false
	hasStartupArtifact := false

	for _, effect := range effects {
		lower := lowerEffect(effect)

		if effect.EffectType == ir.COM_INVOKE || effect.EffectType == ir.ENV_CHECK {
			if strings.Contains(lower.text, "reactor") || strings.Contains(lower.text, "vlr-") {
				hasReactor = true
			}
		}

		if effect.EffectType == ir.FILE_READ || effect.EffectType == ir.FILE_WRITE {
			if strings.Contains(lower.text, "findfile") {
				hasFindfile = true
			}
			if strings.Contains(lower.text, "vl-file-copy") {
				hasFileCopy = true
			}
			if isAdvancedStartupTarget(lower.target) || isAdvancedStartupTarget(lower.source) ||
				strings.Contains(lower.text, "acaddoc") || strings.Contains(lower.text, "acad.lsp") {
				hasStartupArtifact = true
			}
		}
	}

	return hasReactor && hasFileCopy && (hasFindfile || hasStartupArtifact)
}

func (r *ReactorPropagationRule) GetID() string {
	return "REACT_PROP_001"
}

func (r *ReactorPropagationRule) GetName() string {
	return "Reactor-Driven Propagation"
}

func (r *ReactorPropagationRule) GetDescription() string {
	return "Combines reactor persistence with file discovery/copy propagation into startup-chain artifacts"
}

func (r *ReactorPropagationRule) GetSeverity() float64 {
	return 0.96
}

func (r *ReactorPropagationRule) GetTags() []string {
	return []string{"reactor", "propagation", "startup_chain", "persistence"}
}

// RecoveredFASPropagationRule detects the synthetic findfile/vl-file-copy
// propagation pair emitted by recovered FAS behavior analysis.
type RecoveredFASPropagationRule struct{}

func (r *RecoveredFASPropagationRule) Match(effects []ir.IREffect) bool {
	hasFindfile := false
	hasFileCopy := false
	hasRecoveredSource := false
	hasStartupArtifact := false

	for _, effect := range effects {
		lower := lowerEffect(effect)

		if strings.Contains(lower.text, "recovered_fas_module") {
			hasRecoveredSource = true
		}
		if effect.EffectType == ir.FILE_READ && strings.Contains(lower.text, "findfile") {
			hasFindfile = true
		}
		if effect.EffectType == ir.FILE_WRITE && strings.Contains(lower.text, "vl-file-copy") {
			hasFileCopy = true
		}
		if hasStartupArtifactText(lower.text) || isAdvancedStartupTarget(lower.target) || isAdvancedStartupTarget(lower.source) {
			hasStartupArtifact = true
		}
	}

	return hasRecoveredSource && hasFindfile && hasFileCopy && hasStartupArtifact
}

func (r *RecoveredFASPropagationRule) GetID() string {
	return "REC_FAS_PROP_001"
}

func (r *RecoveredFASPropagationRule) GetName() string {
	return "Recovered FAS Propagation Stub"
}

func (r *RecoveredFASPropagationRule) GetDescription() string {
	return "Recovered FAS behavior shows file discovery followed by vl-file-copy propagation"
}

func (r *RecoveredFASPropagationRule) GetSeverity() float64 {
	return 0.91
}

func (r *RecoveredFASPropagationRule) GetTags() []string {
	return []string{"fas", "recovered_behavior", "propagation", "file_copy"}
}

// FindfileCopyPropagationRule detects direct file discovery + copy patterns
// that survive into IR without full target recovery.
type FindfileCopyPropagationRule struct{}

func (r *FindfileCopyPropagationRule) Match(effects []ir.IREffect) bool {
	hasFindfile := false
	hasFileCopy := false
	hasSuspiciousArtifact := false

	for _, effect := range effects {
		lower := lowerEffect(effect)

		if effect.EffectType == ir.FILE_READ && strings.Contains(lower.text, "findfile") {
			hasFindfile = true
		}
		if effect.EffectType == ir.FILE_WRITE && strings.Contains(lower.text, "vl-file-copy") {
			hasFileCopy = true
		}
		if strings.Contains(lower.text, "helper-dwgprefix") ||
			strings.Contains(lower.text, "modemacro") ||
			strings.Contains(lower.text, "&{symbol afas") ||
			hasStartupArtifactText(lower.text) {
			hasSuspiciousArtifact = true
		}
	}

	return hasFindfile && hasFileCopy && hasSuspiciousArtifact
}

func (r *FindfileCopyPropagationRule) GetID() string {
	return "FINDCOPY_001"
}

func (r *FindfileCopyPropagationRule) GetName() string {
	return "Findfile Copy Propagation"
}

func (r *FindfileCopyPropagationRule) GetDescription() string {
	return "Uses findfile followed by vl-file-copy in a suspicious startup-propagation helper"
}

func (r *FindfileCopyPropagationRule) GetSeverity() float64 {
	return 0.89
}

func (r *FindfileCopyPropagationRule) GetTags() []string {
	return []string{"findfile", "file_copy", "propagation", "startup_chain"}
}

// ObfuscatedNetworkStubRule detects sparse FAS network loaders where the
// payload is reduced to low-level control-flow artifacts plus raw HTTP beacons.
type ObfuscatedNetworkStubRule struct{}

func (r *ObfuscatedNetworkStubRule) Match(effects []ir.IREffect) bool {
	httpCount := 0
	hasLowLevelSource := false
	hasSuspiciousURLShape := false
	hasConcreteNetwork := false

	for _, effect := range effects {
		if effect.EffectType != ir.NETWORK_CONNECT {
			continue
		}

		lower := lowerEffect(effect)
		if strings.HasPrefix(lower.target, "http://") || strings.HasPrefix(lower.target, "https://") {
			httpCount++
		}
		if isObfuscatedNetworkSource(lower.source, effect.Metadata) {
			hasLowLevelSource = true
		}
		if strings.Contains(lower.target, "?") || strings.Contains(lower.target, "%") {
			hasSuspiciousURLShape = true
		}
		if !isRecoveredSummaryEffect(effect) {
			hasConcreteNetwork = true
		}
	}

	// This rule is meant for sparse recovered stubs, not large benign URL tables.
	if httpCount > 8 {
		return false
	}
	if !hasConcreteNetwork {
		return false
	}
	if httpCount >= 2 && hasLowLevelSource {
		return true
	}
	return httpCount >= 1 && hasLowLevelSource && hasSuspiciousURLShape
}

func isObfuscatedNetworkSource(source string, metadata map[string]interface{}) bool {
	switch source {
	case "goto", "push-symbol", "push-token", "recovered_fas_module", "__toplevel__":
		return true
	}
	if strings.HasPrefix(source, "fn_") || strings.HasPrefix(source, "sym_") || strings.HasPrefix(source, "block_") {
		return true
	}
	if inferredFrom, ok := metadata["inferred_from"].(string); ok && inferredFrom == "unknown_call_args" {
		return strings.HasPrefix(source, "fn_") || strings.HasPrefix(source, "sym_") || source == "__toplevel__"
	}
	return false
}

func (r *ObfuscatedNetworkStubRule) GetID() string {
	return "NET_STUB_001"
}

func (r *ObfuscatedNetworkStubRule) GetName() string {
	return "Obfuscated Network Stub"
}

func (r *ObfuscatedNetworkStubRule) GetDescription() string {
	return "Sparse FAS stub still exposes raw HTTP beaconing through low-level control-flow remnants"
}

func (r *ObfuscatedNetworkStubRule) GetSeverity() float64 {
	return 0.90
}

func (r *ObfuscatedNetworkStubRule) GetTags() []string {
	return []string{"network", "stub", "fas", "obfuscated", "beacon"}
}

// AdvancedRulesRegistry manages advanced detection rules
type AdvancedRulesRegistry struct {
	rules []DetectionRule
}

// NewAdvancedRulesRegistry creates a new advanced rules registry
func NewAdvancedRulesRegistry() *AdvancedRulesRegistry {
	return &AdvancedRulesRegistry{
		rules: []DetectionRule{
			&WormLikeRule{},
			&CommandHijackRule{},
			&StealthPersistenceRule{},
			&EnvironmentAwareRule{},
			&NetworkActivityRule{},
			&VBACodeInjectionRule{},
			&WormSelfReplicationRule{},
			&DataDestructionRule{},
			&DirectoryTraversalInfectionRule{},
			&StartupLoadRule{},
			&NetworkDropperRule{},
			&SuspiciousProcessExecRule{},
			&COMDropperRule{},
			&ScriptControlDropperRule{},
			&StartupInfectorRule{},
			&ReactorPropagationRule{},
			&RecoveredFASPropagationRule{},
			&FindfileCopyPropagationRule{},
			&ObfuscatedNetworkStubRule{},
		},
	}
}

// Evaluate evaluates all advanced rules against the effects
func (reg *AdvancedRulesRegistry) Evaluate(effects []ir.IREffect) []DetectionRule {
	var matched []DetectionRule

	for _, rule := range reg.rules {
		if rule.Match(effects) {
			matched = append(matched, rule)
		}
	}

	return matched
}
