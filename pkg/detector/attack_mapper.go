package detector

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/evilcad/cadscanner/pkg/ir"
	"github.com/evilcad/cadscanner/pkg/normalizer"
)

// AttackMapper maps behavior patterns to ATT&CK techniques
type AttackMapper struct {
	detectedTechniques map[string]float64
	evidence           []map[string]interface{}
}

var versionedStartupPattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx)\b`)

func isAutoCADStartupArtifact(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "acaddoc.lsp") ||
		strings.Contains(lower, "acad.fas") ||
		strings.Contains(lower, "acad.lsp") ||
		strings.Contains(lower, "acad.vlx") ||
		strings.Contains(lower, ".mnl") ||
		strings.Contains(lower, "startup") ||
		versionedStartupPattern.MatchString(lower)
}

func isAutoCADStartupLoadTarget(path string) bool {
	lower := strings.ToLower(path)
	return versionedStartupPattern.MatchString(lower) ||
		strings.Contains(lower, "acaddoc") ||
		strings.Contains(lower, "acad")
}

// NewAttackMapper creates a new attack mapper
func NewAttackMapper() *AttackMapper {
	return &AttackMapper{
		detectedTechniques: make(map[string]float64),
		evidence:           make([]map[string]interface{}, 0),
	}
}

// Analyze analyzes IR effects and normalized nodes to map to ATT&CK
func (am *AttackMapper) Analyze(effects []ir.IREffect, normalized []*normalizer.NormalizedNode) (*AttackResult, float64) {
	am.detectedTechniques = make(map[string]float64)
	am.evidence = make([]map[string]interface{}, 0)

	// Analyze patterns
	am.detectPersistence(effects, normalized)
	am.detectExecution(effects, normalized)
	am.detectObfuscation(normalized)
	am.detectRegistryModification(effects)
	am.detectCOMUsage(effects)
	am.detectShellExec(effects)
	am.detectNetworkActivity(effects)
	am.detectEnvironmentAwareness(effects, normalized)
	am.detectCommandHijack(effects, normalized)

	// Calculate risk score
	riskScore := am.calculateRiskScore()

	// Build technique list
	techniques := make([]AttackTechnique, 0)
	for techID, confidence := range am.detectedTechniques {
		if techInfo, ok := techniquesDB[techID]; ok {
			techniques = append(techniques, AttackTechnique{
				ID:         techID,
				Name:       techInfo.Name,
				Confidence: confidence,
			})
		}
	}

	return &AttackResult{
		Techniques: techniques,
		Evidence:   am.evidence,
	}, riskScore
}

// detectPersistence detects persistence mechanisms
func (am *AttackMapper) detectPersistence(effects []ir.IREffect, normalized []*normalizer.NormalizedNode) {
	hasStartupFunc := false
	hasFileWrite := false

	for _, effect := range effects {
		target := strings.ToLower(effect.Target)
		source := strings.ToLower(effect.Source)

		// Check for file operations on startup files
		if effect.EffectType == ir.FILE_WRITE || effect.EffectType == ir.FILE_READ {
			isStartupFile := false

			// Direct startup file patterns
			if isAutoCADStartupArtifact(target) {
				isStartupFile = true
			}

			// Wildcard patterns suggesting startup file enumeration
			if strings.Contains(target, "*.lsp") ||
				strings.Contains(target, "*.fas") ||
				strings.Contains(target, "*.mnl") ||
				strings.Contains(source, "vl-directory-files") {
				isStartupFile = true
			}

			// Variable names suggesting startup file operations
			// (e.g., "wnewacad", "newacad", "woldacad", "acaddoc")
			if (strings.Contains(target, "acad") && (strings.Contains(target, "new") || strings.Contains(target, "old"))) ||
				strings.Contains(source, "newacad") ||
				strings.Contains(source, "oldacad") ||
				strings.Contains(source, "acaddoc") ||
				strings.Contains(target, "acaddoc") ||
				versionedStartupPattern.MatchString(target) {
				isStartupFile = true
			}

			if isStartupFile {
				hasFileWrite = true
				am.addTechnique("T1547.001", 0.95)
				am.addEvidence(map[string]interface{}{
					"type":        "file_operation",
					"description": "Accesses AutoCAD startup file",
					"target":      target,
				})
			}
		}
	}

	// Check for startup function definition
	for _, node := range normalized {
		nodeText := lowerNodeArgumentsText(node.Arguments)
		if strings.Contains(nodeText, "acad.mnl") || strings.Contains(nodeText, "acaddoc") ||
			versionedStartupPattern.MatchString(nodeText) {
			am.addTechnique("T1547.001", 0.82)
			am.addEvidence(map[string]interface{}{
				"type":        "startup_reference",
				"description": "References AutoCAD startup-chain file in code",
				"function":    node.FunctionName,
				"line":        node.Line,
			})
		}
		if node.Operation == normalizer.DEFUN {
			funcName := strings.ToLower(node.FunctionName)
			if len(node.Arguments) > 0 {
				if name, ok := node.Arguments[0].(string); ok {
					funcName = strings.ToLower(name)
				}
			}
			if strings.Contains(funcName, "startup") || strings.Contains(funcName, "s::startup") {
				hasStartupFunc = true
				am.addTechnique("T1547.001", 0.85)
				am.addEvidence(map[string]interface{}{
					"type":        "function_def",
					"description": "Defines startup hook function",
					"function":    node.FunctionName,
					"line":        node.Line,
				})
			}
		}
	}

	// Check for reactor hooks
	for _, effect := range effects {
		if strings.Contains(strings.ToLower(effect.Source), "vlr-") {
			hasStartupFunc = true
			am.addTechnique("T1543", 0.88)
			am.addTechnique("T1547.001", 0.82)
			am.addEvidence(map[string]interface{}{
				"type":        "reactor",
				"description": "Creates AutoCAD reactor hook",
				"source":      effect.Source,
			})
		}
	}

	// Combination is more suspicious
	if hasStartupFunc && hasFileWrite {
		am.addTechnique("T1547.001", 1.0)
	}
}

func (am *AttackMapper) detectNetworkActivity(effects []ir.IREffect) {
	hasNetwork := false
	hasFileWrite := false
	hasProcessExec := false

	for _, effect := range effects {
		if effect.EffectType == ir.FILE_WRITE {
			if !isRecoveredSummaryEffect(effect) {
				hasFileWrite = true
			}
		}
		if effect.EffectType == ir.PROCESS_CREATE && IsSuspiciousProcessCommand(effect.Target) {
			if !isRecoveredSummaryEffect(effect) {
				hasProcessExec = true
			}
		}
		if effect.EffectType != ir.NETWORK_CONNECT {
			continue
		}
		if isRecoveredSummaryEffect(effect) {
			continue
		}
		hasNetwork = true
		target := strings.ToLower(effect.Target)
		confidence := 0.88
		techID := "T1071.001"
		description := "HTTP/network communication detected"
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			confidence = 0.93
			description = "HTTP C2/download endpoint detected"
		}
		am.addTechnique(techID, confidence)
		am.addEvidence(map[string]interface{}{
			"type":        "network",
			"description": description,
			"target":      effect.Target,
			"source":      effect.Source,
		})
	}

	if hasNetwork && (hasFileWrite || hasProcessExec) {
		am.addTechnique("T1105", 0.86)
	}
}

// detectExecution detects execution techniques
func (am *AttackMapper) detectExecution(effects []ir.IREffect, normalized []*normalizer.NormalizedNode) {
	hasEval := false
	hasRemoteLoad := false

	for _, node := range normalized {
		// Dynamic evaluation
		if node.Operation == normalizer.EVAL {
			hasEval = true
			am.addTechnique("T1059.007", 0.90)
			am.addEvidence(map[string]interface{}{
				"type":        "eval",
				"description": "Uses dynamic code evaluation",
				"line":        node.Line,
			})
		}

		// Code loading - distinguish local vs remote
		if node.Operation == normalizer.LOAD {
			loadTarget := ""
			if len(node.Arguments) > 0 {
				if arg, ok := node.Arguments[0].(string); ok {
					loadTarget = strings.ToLower(arg)
				}
			}

			if isRemoteLoad(loadTarget) {
				hasRemoteLoad = true
				am.addTechnique("T1059.007", 0.85)
				am.addEvidence(map[string]interface{}{
					"type":        "remote_load",
					"description": "Loads code from remote/URL source",
					"target":      loadTarget,
					"line":        node.Line,
				})
			} else if isLocalLoad(loadTarget) {
				confidence := 0.30
				description := "Loads local LISP file"
				if isAutoCADStartupLoadTarget(loadTarget) {
					confidence = 0.78
					description = "Loads AutoCAD startup-chain LISP file"
					am.addTechnique("T1547.001", 0.72)
				}
				// Local file loading - low unless it targets AutoCAD startup chain
				am.addTechnique("T1059.007", confidence)
				am.addEvidence(map[string]interface{}{
					"type":        "local_load",
					"description": description,
					"target":      loadTarget,
					"line":        node.Line,
				})
			} else {
				// Unknown load target - low confidence (likely benign local file without extension)
				// Many legitimate AutoCAD plugins use (load "filename") without extension
				am.addTechnique("T1059.007", 0.20)
				am.addEvidence(map[string]interface{}{
					"type":        "load",
					"description": "Loads external code (unknown target, likely local)",
					"line":        node.Line,
				})
			}
		}
	}

	for _, effect := range effects {
		if effect.EffectType == ir.FILE_READ && strings.EqualFold(effect.Source, "load") {
			loadTarget := strings.ToLower(effect.Target)
			confidence := 0.30
			description := "Reads local code for load execution"
			if isAutoCADStartupLoadTarget(loadTarget) {
				confidence = 0.78
				description = "Reads AutoCAD startup-chain code for load execution"
				am.addTechnique("T1547.001", 0.72)
			}
			am.addTechnique("T1059.007", confidence)
			am.addEvidence(map[string]interface{}{
				"type":        "load_effect",
				"description": description,
				"target":      effect.Target,
			})
		}

		// OS execution
		if effect.EffectType == ir.PROCESS_CREATE {
			if isRecoveredSummaryEffect(effect) {
				continue
			}
			target := strings.ToLower(effect.Target)
			if isBenignApplication(target) {
				// Benign GUI application launch - lower confidence
				am.addTechnique("T1059.007", 0.35)
				am.addEvidence(map[string]interface{}{
					"type":        "exec",
					"description": "Launches benign application",
					"target":      effect.Target,
				})
			} else if IsSuspiciousProcessCommand(target) {
				am.addTechnique("T1059.007", 0.95)
				am.addEvidence(map[string]interface{}{
					"type":        "exec",
					"description": "Executes suspicious OS commands",
					"target":      effect.Target,
				})
			} else {
				am.addTechnique("T1059.007", 0.40)
				am.addEvidence(map[string]interface{}{
					"type":        "exec",
					"description": "Executes local helper command",
					"target":      effect.Target,
				})
			}
		}
	}

	// Combined eval + remote load is more suspicious
	if hasEval && hasRemoteLoad {
		am.addTechnique("T1059.007", 1.0)
	}
}

// isRemoteLoad checks if the load target appears to be remote
func isRemoteLoad(target string) bool {
	if target == "" {
		return false
	}

	// Check for URL patterns
	if strings.HasPrefix(target, "http://") ||
		strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "ftp://") ||
		strings.HasPrefix(target, "//") {
		return true
	}

	// Check for network paths
	if strings.HasPrefix(target, "\\\\") || strings.Contains(target, "://") {
		return true
	}

	return false
}

// isLocalLoad checks if the load target is clearly a local file
func isLocalLoad(target string) bool {
	if target == "" {
		return false
	}

	// Common local file patterns
	localPatterns := []string{
		".lsp", ".fas", ".vlx", ".mnl", ".dcl",
	}

	for _, pattern := range localPatterns {
		if strings.HasSuffix(target, pattern) {
			// Ensure it's not a URL
			if !strings.Contains(target, "://") && !strings.HasPrefix(target, "//") {
				return true
			}
		}
	}

	// Relative path indicators
	if strings.Contains(target, "\\") || strings.Contains(target, "/") {
		if !strings.Contains(target, "://") {
			return true
		}
	}

	// Bare filename without extension (e.g., "utils", "mylib")
	// Common in legitimate AutoCAD plugins that load supporting files
	if !strings.Contains(target, ".") && !strings.Contains(target, "://") &&
		!strings.HasPrefix(target, "//") && !strings.HasPrefix(target, "\\") {
		// Check it looks like a simple identifier (letters, numbers, underscore, hyphen)
		isSimpleName := true
		for _, c := range target {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_' || c == '-') {
				isSimpleName = false
				break
			}
		}
		if isSimpleName && len(target) > 0 {
			return true
		}
	}

	return false
}

// detectObfuscation detects obfuscation techniques
func (am *AttackMapper) detectObfuscation(normalized []*normalizer.NormalizedNode) {
	stringDecodeCount := 0

	for _, node := range normalized {
		if node.Operation == normalizer.STRING_DECODE {
			stringDecodeCount++
		}
	}

	// Multiple string decoding suggests obfuscation
	if stringDecodeCount > 3 {
		am.addTechnique("T1140", 0.85)
		am.addEvidence(map[string]interface{}{
			"type":        "pattern",
			"description": "Multiple string decode operations",
			"count":       stringDecodeCount,
		})
	}

	if stringDecodeCount > 10 {
		am.addTechnique("T1027", 0.90)
	}
}

// detectRegistryModification detects registry modification
func (am *AttackMapper) detectRegistryModification(effects []ir.IREffect) {
	for _, effect := range effects {
		if (effect.EffectType == ir.REGISTRY_MODIFY || effect.EffectType == ir.REGISTRY_DELETE) &&
			IsSuspiciousRegistryPath(effect.Target) {
			am.addTechnique("T1112", 0.90)
			am.addEvidence(map[string]interface{}{
				"type":        "registry",
				"description": "Modifies Windows registry",
				"target":      effect.Target,
			})
		}
	}
}

// detectCOMUsage detects COM object usage
func (am *AttackMapper) detectCOMUsage(effects []ir.IREffect) {
	hasXMLHTTP := false
	hasADODB := false
	hasShell := false

	for _, effect := range effects {
		if effect.EffectType == ir.COM_CREATE || effect.EffectType == ir.COM_INVOKE {
			if isRecoveredSummaryEffect(effect) {
				continue
			}
			funcName := strings.ToLower(effect.Source)
			objName := strings.ToLower(effect.Target)

			// Check if this is AutoCAD internal VLA operation (benign)
			if isAutoCADInternalOperation(funcName, objName) {
				// Skip or use very low confidence for AutoCAD internal VLA operations
				continue
			}

			// Clean object name for matching (remove binary artifacts)
			cleanObjName := strings.ToLower(strings.TrimRight(objName, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"))

			if strings.Contains(cleanObjName, "wscript.shell") || strings.Contains(cleanObjName, "shell.application") {
				hasShell = true
				am.addTechnique("T1059.003", 0.95)
				am.addTechnique("T1106", 0.90)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates shell COM",
					"object":      objName,
				})
			} else if strings.Contains(cleanObjName, "xmlhttp") || strings.Contains(cleanObjName, "msxml") ||
				strings.Contains(cleanObjName, "serverxmlhttp") {
				hasXMLHTTP = true
				am.addTechnique("T1071.001", 0.55)
				am.addTechnique("T1106", 0.55)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates XMLHTTP COM for web communication",
					"object":      objName,
				})
			} else if strings.Contains(cleanObjName, "adodb") {
				hasADODB = true
				am.addTechnique("T1105", 0.90)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates ADODB COM",
					"object":      objName,
				})
			} else if strings.Contains(cleanObjName, "vbscript") || strings.Contains(cleanObjName, "scriptlet") {
				am.addTechnique("T1059.005", 0.93)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates VBScript COM",
					"object":      objName,
				})
			} else if strings.Contains(cleanObjName, "scripting.filesystemobject") || strings.Contains(cleanObjName, "filesystemobject") {
				am.addTechnique("T1106", 0.75)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates FileSystemObject via COM",
					"object":      objName,
				})
			} else if strings.Contains(cleanObjName, "wbemscripting") || strings.Contains(cleanObjName, "swbemlocator") {
				am.addTechnique("T1082", 0.85)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates WMI COM for system info discovery",
					"object":      objName,
				})
			} else if effect.EffectType == ir.COM_INVOKE {
				if strings.Contains(objName, "insertlines") ||
					strings.Contains(objName, "codemodule") ||
					strings.Contains(objName, "addfromstring") {
					am.addTechnique("T1055", 0.95)     // Process Injection
					am.addTechnique("T1547.001", 0.90) // Persistence via code injection
					am.addEvidence(map[string]interface{}{
						"type":        "code_injection",
						"description": "Code injection via COM Invoke (VBA macro virus)",
						"target":      objName,
						"source":      funcName,
					})
				}
			} else if objName != "" && !isBenignCOMAction(funcName, objName) {
				// Only add generic T1106 for non-benign COM actions
				am.addTechnique("T1106", 0.50)
				am.addEvidence(map[string]interface{}{
					"type":        "com",
					"description": "Creates COM object",
					"object":      objName,
				})
			}
		}
	}

	// Only explicit download chains should escalate XMLHTTP into ingress transfer.
	if hasXMLHTTP && (hasADODB || hasShell) {
		am.addTechnique("T1105", 0.95)
		am.addEvidence(map[string]interface{}{
			"type":        "combined_network_com",
			"description": "XMLHTTP paired with execution or stream staging COM",
		})
	}
}

// isAutoCADInternalOperation checks if this is benign AutoCAD VLA operation
func isAutoCADInternalOperation(source, target string) bool {
	sourceLower := strings.ToLower(source)

	// VLA prefix functions are AutoCAD internal ActiveX methods
	if strings.HasPrefix(sourceLower, "vla-") {
		return true
	}

	// Benign VLAX getters (property access on AutoCAD objects)
	benignVLAXOps := []string{
		"vlax-get-property", "vlax-get",
		"vlax-ename->vla-object", "vlax-ename->vla",
	}
	for _, op := range benignVLAXOps {
		if sourceLower == op || strings.HasPrefix(sourceLower, op) {
			return true
		}
	}

	// Benign COM initialization (not actual COM object creation)
	benignCOMInit := []string{
		"vl-load-com", // Just initializes AutoLISP-COM bridge
	}
	for _, init := range benignCOMInit {
		if sourceLower == init || strings.Contains(sourceLower, init) {
			return true
		}
	}

	// Common benign VLA method names
	benignVLAMethods := []string{
		"getattributes", "gettextstring", "insertionpoint", "effectivename",
		"getboundingbox", "getpoint", "getentity", "getselection",
		"addline", "addcircle", "addtext", "addmtext",
		"get", "put", "invoke",
	}

	for _, method := range benignVLAMethods {
		if strings.Contains(target, method) {
			return true
		}
	}

	return false
}

// isBenignCOMAction checks if the COM action is likely benign
func isBenignCOMAction(source, target string) bool {
	sourceLower := strings.ToLower(source)

	// Explicitly benign VLAX operations (property getters, type conversions)
	benignVLAXExact := []string{
		"vlax-get-property", "vlax-get",
		"vlax-ename->vla-object", "vlax-ename->vla",
		"vlax-variant-value", "vlax-variant-type",
		"vlax-make-variant", "vlax-make-safearray",
	}
	for _, op := range benignVLAXExact {
		if sourceLower == op || strings.HasPrefix(sourceLower, op+" ") {
			return true
		}
	}

	// Check for AutoCAD entity object operations (non-create-object VLAX)
	if strings.Contains(sourceLower, "vlax-") && !strings.Contains(sourceLower, "vlax-create-object") {
		// vlax-get, vlax-invoke on entity objects are typically benign
		if strings.Contains(target, "ent") || strings.Contains(target, "obj") {
			return true
		}
	}

	return false
}

// isBenignApplication checks if the target is a known benign GUI application
func isBenignApplication(target string) bool {
	benignApps := []string{
		"notepad", "calc", "mspaint", "wordpad", "explorer",
		"iexplore", "chrome", "firefox", "excel", "winword",
		"powershell_ise", "devenv", "code", "sublime",
	}
	targetLower := strings.ToLower(target)
	for _, app := range benignApps {
		if strings.Contains(targetLower, app) {
			return true
		}
	}
	return false
}

// detectShellExec detects shell/command execution
func (am *AttackMapper) detectShellExec(effects []ir.IREffect) {
	for _, effect := range effects {
		if effect.EffectType == ir.PROCESS_CREATE {
			target := strings.ToLower(effect.Target)
			if strings.Contains(target, "rundll32") ||
				strings.Contains(target, "setupapi") ||
				strings.Contains(target, "installhinfsection") {
				am.addTechnique("T1218.010", 0.99)
				am.addEvidence(map[string]interface{}{
					"type":        "shell",
					"description": "rundll32/setupapi proxy",
					"target":      target,
				})
			} else if strings.Contains(target, "regsvr32") {
				am.addTechnique("T1218.010", 0.95)
				am.addTechnique("T1112", 0.90)
				am.addEvidence(map[string]interface{}{
					"type":        "shell",
					"description": "regsvr32 COM registration",
					"target":      target,
				})
			} else if strings.Contains(target, "cmd.exe") || strings.Contains(target, "wscript") {
				am.addTechnique("T1059.003", 0.92)
				am.addEvidence(map[string]interface{}{
					"type":        "shell",
					"description": "Shell exec",
					"target":      target,
				})
			} else if strings.Contains(target, "powershell") {
				if IsLikelyMaliciousPowerShell(target) {
					am.addTechnique("T1059.003", 0.90)
					am.addEvidence(map[string]interface{}{
						"type":        "shell",
						"description": "High-risk PowerShell execution",
						"target":      target,
					})
				} else {
					am.addTechnique("T1059.003", 0.35)
					am.addEvidence(map[string]interface{}{
						"type":        "shell",
						"description": "Benign/administrative PowerShell usage",
						"target":      target,
					})
				}
			} else if isBenignApplication(target) {
				// Benign GUI applications (notepad, calc, etc.) - low risk
				am.addTechnique("T1059.003", 0.30)
				am.addEvidence(map[string]interface{}{
					"type":        "shell",
					"description": "Benign app launch",
					"target":      target,
				})
			} else {
				am.addTechnique("T1059.003", 0.80)
				am.addEvidence(map[string]interface{}{
					"type":        "shell",
					"description": "OS exec",
					"target":      target,
				})
			}
		}
	}
}

// detectEnvironmentAwareness detects environment-aware / targeted attack behaviors
func (am *AttackMapper) detectEnvironmentAwareness(effects []ir.IREffect, normalized []*normalizer.NormalizedNode) {
	hasMACCheck := false
	hasDateCheck := false
	hasDateComparison := false

	for _, effect := range effects {
		objName := strings.ToLower(effect.Source)
		// Check for MAC address collection
		if strings.Contains(objName, "wbemscripting") || strings.Contains(objName, "swbemlocator") {
			hasMACCheck = true
		}
	}

	for _, node := range normalized {
		argsStr := lowerNodeArgumentsText(node.Arguments)

		// Check for date/time checks
		if node.Operation == normalizer.SETQ || node.Operation == normalizer.SETVAR {
			if strings.Contains(argsStr, "cdate") {
				hasDateCheck = true
			}
		}

		// Check for date comparisons in conditionals
		if node.Operation == normalizer.IF || node.Operation == normalizer.COND {
			if strings.Contains(argsStr, "cdate") {
				hasDateCheck = true
			}
			// Check for numeric date comparisons
			for year := 2000; year < 2030; year++ {
				if strings.Contains(argsStr, strconv.Itoa(year)) {
					hasDateComparison = true
					break
				}
			}
		}

		// Check for MAC address function usage
		if strings.Contains(strings.ToLower(node.FunctionName), "macaddr") {
			hasMACCheck = true
		}
	}

	// MAC check = System Information Discovery
	if hasMACCheck {
		am.addTechnique("T1082", 0.85)
		am.addEvidence(map[string]interface{}{
			"type":        "pattern",
			"description": "MAC address collection for targeted execution",
		})
	}

	// Date check + MAC check = Time-based sandbox evasion
	if hasDateCheck && hasMACCheck {
		am.addTechnique("T1497.001", 0.90)
		am.addEvidence(map[string]interface{}{
			"type":        "pattern",
			"description": "Time-based execution with MAC targeting (time bomb)",
		})
	} else if hasDateComparison && hasMACCheck {
		am.addTechnique("T1497.001", 0.85)
		am.addEvidence(map[string]interface{}{
			"type":        "pattern",
			"description": "Date-comparison based conditional execution",
		})
	} else if hasDateCheck {
		am.addTechnique("T1497.001", 0.70)
		am.addEvidence(map[string]interface{}{
			"type":        "pattern",
			"description": "Time-based execution delay detected",
		})
	}
}

// addTechnique adds or updates technique detection
func (am *AttackMapper) addTechnique(techID string, confidence float64) {
	if existing, ok := am.detectedTechniques[techID]; ok {
		// Take maximum confidence
		if confidence > existing {
			am.detectedTechniques[techID] = confidence
		}
	} else {
		am.detectedTechniques[techID] = confidence
	}
}

// addEvidence adds evidence for detection
func (am *AttackMapper) addEvidence(evidence map[string]interface{}) {
	am.evidence = append(am.evidence, evidence)
}

// calculateRiskScore calculates overall risk score
func (am *AttackMapper) calculateRiskScore() float64 {
	if len(am.detectedTechniques) == 0 {
		return 0.0
	}

	defaultWeights := map[string]float64{
		"T1547.001": 0.90, // AutoCAD persistence
		"T1059.003": 0.85, // cmd.exe
		"T1059.005": 0.88, // VBScript
		"T1059.007": 0.80, // AutoLISP execution
		"T1105":     0.95, // XMLHTTP download
		"T1106":     0.85, // COM/Native API
		"T1112":     0.80, // Registry mod
		"T1218.010": 0.95, // rundll32/regsvr32 proxy
		"T1027":     0.70, // Obfuscation
		"T1140":     0.65, // Deobfuscation
		"T1082":     0.75, // Sysinfo discovery
		"T1083":     0.55, // File discovery
		"T1070.004": 0.80, // File deletion
		"T1564.001": 0.85, // Hide files
		"T1071.001": 0.90, // HTTP C2
		"T1543":     0.85, // VLR reactor
		"T1055":     0.95, // Process injection
		"T1497.001": 0.88, // Time-based sandbox evasion
		"T1569":     0.90, // Command hijacking
	}

	totalScore := 0.0
	totalWeight := 0.0

	for techID, confidence := range am.detectedTechniques {
		weight := defaultWeights[techID]
		if weight == 0 {
			weight = 0.5
		}
		totalScore += weight * confidence
		totalWeight += weight
	}

	if totalWeight <= 0 {
		return 0.0
	}
	score := totalScore / totalWeight
	if score > 1.0 {
		return 1.0
	}
	return score
}

// TechniqueInfo represents ATT&CK technique information
type TechniqueInfo struct {
	Name        string
	Description string
}

// techniquesDB is the ATT&CK technique definitions database
var techniquesDB = map[string]TechniqueInfo{
	"T1547.001": {
		Name:        "Boot/Logon Autostart: AutoCAD startup file",
		Description: "Persistence via acad.fas, acad.vlx, acaddoc.lsp, [S::STARTUP reactor",
	},
	"T1059.007": {
		Name:        "Command and Scripting Interpreter: AutoLISP",
		Description: "Execution via AutoLISP scripting",
	},
	"T1059.003": {
		Name:        "Command and Scripting Interpreter: Windows Command Shell",
		Description: "cmd.exe execution from AutoLISP via STARTAPP or COM",
	},
	"T1059.005": {
		Name:        "Command and Scripting Interpreter: Visual Basic Script",
		Description: "VBScript execution via wscript.shell or vbscript.encode",
	},
	"T1105": {
		Name:        "Ingress Tool Transfer",
		Description: "Download via Microsoft.XMLHTTP + ADODB.Stream",
	},
	"T1106": {
		Name:        "Native API",
		Description: "Execution via COM/Windows API (vlax-create-object)",
	},
	"T1112": {
		Name:        "Modify Registry",
		Description: "Registry modification via vl-registry-write or regsvr32",
	},
	"T1218.010": {
		Name:        "Signed Binary Proxy Execution: Regsvr32",
		Description: "rundll32 setupapi,InstallHinfSection or regsvr32 /s to register COM",
	},
	"T1027": {
		Name:        "Obfuscated Files or Information",
		Description: "VBScript.Encode, chr-list encoding, flagx padding",
	},
	"T1140": {
		Name:        "Deobfuscate/Decode Files or Information",
		Description: "vl-list->string ASCII decode, string reconstruction",
	},
	"T1082": {
		Name:        "System Information Discovery",
		Description: "MAC address, GETVAR, GETENV, WMI queries",
	},
	"T1497.001": {
		Name:        "Virtualization/Sandbox Evasion: Time Based",
		Description: "Delayed execution via date/time checks or time bombs",
	},
	"T1083": {
		Name:        "File and Directory Discovery",
		Description: "FINDFILE to locate AutoCAD installation paths",
	},
	"T1070.004": {
		Name:        "Indicator Removal: File Deletion",
		Description: "VL-FILE-DELETE to remove evidence",
	},
	"T1564.001": {
		Name:        "Hide Artifacts: Hidden Files and Directories",
		Description: "attrib +h +r to hide malicious files",
	},
	"T1071.001": {
		Name:        "Application Layer Protocol: Web Protocols",
		Description: "HTTP C2 communication via XMLHTTP",
	},
	"T1543": {
		Name:        "Create/Modify System Process: AutoCAD VLR Reactor",
		Description: "VLR-SysVar-Reactor / VLR-DWG-Reactor for persistent hooks",
	},
	"T1055": {
		Name:        "Process Injection",
		Description: "Code injection via COM",
	},
	"T1569": {
		Name:        "System Services: Command Hijacking",
		Description: "Command undefine/redirection to disable or hijack AutoCAD commands",
	},
}

// detectCommandHijack detects command hijacking (undefine, rename commands, and defun c:)
func (am *AttackMapper) detectCommandHijack(effects []ir.IREffect, normalized []*normalizer.NormalizedNode) {
	hasCommandHijack := false
	undefinedOrRedirected := make(map[string]bool)

	// Check for COMMAND_HIJACK effects (from command "undefine")
	for _, effect := range effects {
		if effect.EffectType == ir.COMMAND_HIJACK {
			hasCommandHijack = true
			target := strings.ToLower(effect.Target)
			if target != "" {
				undefinedOrRedirected[target] = true
			}
			am.addTechnique("T1569", 0.90)
			am.addEvidence(map[string]interface{}{
				"type":        "command_hijack",
				"description": "Command undefine/redirection detected",
				"target":      effect.Target,
				"source":      effect.Source,
			})
		}
	}

	// Check for defun c: command hijacking
	criticalCommands := map[string]bool{
		"save": true, "qsave": true, "saveas": true, "quit": true, "exit": true,
		"close": true, "open": true, "line": true, "copy": true, "move": true,
		"erase": true, "trim": true, "extend": true, "explode": true, "undo": true,
		"ucs": true, "layer": true, "plot": true, "purge": true,
	}
	for _, node := range normalized {
		if node.Operation == normalizer.DEFUN {
			// Function name is in Arguments[0], FunctionName is "defun"
			funcName := ""
			if len(node.Arguments) > 0 {
				switch v := node.Arguments[0].(type) {
				case string:
					funcName = strings.ToLower(v)
				case *normalizer.NormalizedNode:
					funcName = strings.ToLower(v.FunctionName)
				}
			}

			// Check for c: prefix command definitions (command hijacking)
			if strings.HasPrefix(funcName, "c:") {
				cmd := strings.TrimPrefix(funcName, "c:")
				isCritical := criticalCommands[cmd]
				isRedirected := undefinedOrRedirected[cmd]
				if !isCritical && !isRedirected {
					continue
				}

				hasCommandHijack = true
				if isCritical || isRedirected {
					am.addTechnique("T1548.001", 0.95) // Hijack Execution Flow
					am.addEvidence(map[string]interface{}{
						"type":        "command_hijack",
						"description": fmt.Sprintf("Hijacks critical AutoCAD command: %s", cmd),
						"function":    funcName,
						"command":     cmd,
						"line":        node.Line,
					})
				}
			}
		}
	}

	// Multiple command hijacks increase confidence
	if hasCommandHijack {
		am.addTechnique("T1569", 0.95)
	}
}
