package adapter

import (
	"regexp"
	"strings"
)

const maxVBADetectionSample = 256 * 1024

// VBAAdaptResult represents the result of VBA adaptation
type VBAAdaptResult struct {
	Source string
	Meta   map[string]interface{}
}

// VBABehavior holds extracted behavioral signals from VBA code
type VBABehavior struct {
	ShellCommands     []string
	COMObjects        []string
	FileWrites        []string
	FileReads         []string
	RegistryWrites    []string
	NetworkURLs       []string
	PropagationHooks  []string
	AutoloadTargets   []string
	UndefineCommands  []string
	WMIQueries        []string
	CodeInject        bool // Code injection via InsertLines/AddFromString
	MacHarvest        bool
	TemplateInfection bool
}

// VBAAdapter adapts VBA/VBScript embedded in .lsp files to pseudo-LISP
type VBAAdapter struct {
	vbaSignatures  []*regexp.Regexp
	lispSignatures []*regexp.Regexp

	// Behavioral extraction patterns
	reShell      *regexp.Regexp
	reCreateObj  *regexp.Regexp
	reOpenWrite  *regexp.Regexp
	reOpenRead   *regexp.Regexp
	reRegistry   *regexp.Regexp
	reURL        *regexp.Regexp
	reHook       *regexp.Regexp
	reTemplate   *regexp.Regexp
	reAcaddoc    *regexp.Regexp
	reUndefine   *regexp.Regexp
	reWMI        *regexp.Regexp
	reMAC        *regexp.Regexp
	reSaveAs     *regexp.Regexp
	reCodeInject *regexp.Regexp
}

// NewVBAAdapter creates a new VBA adapter
func NewVBAAdapter() *VBAAdapter {
	return &VBAAdapter{
		// VBA detection signatures
		vbaSignatures: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bSub\s+\w+\s*\(`),
			regexp.MustCompile(`(?i)\bEnd\s+Sub\b`),
			regexp.MustCompile(`(?i)\bPrivate\s+Sub\b`),
			regexp.MustCompile(`(?i)\bPublic\s+Sub\b`),
			regexp.MustCompile(`(?i)\bFunction\s+\w+\s*\(`),
			regexp.MustCompile(`(?i)\bDim\s+\w+\s+As\b`),
			regexp.MustCompile(`(?i)\bSet\s+\w+\s*=\s*\w+`),
			regexp.MustCompile(`(?i)\bCreateObject\s*\(`),
			regexp.MustCompile(`(?i)\bGetObject\s*\(`),
		},
		// LISP detection signatures (for comparison)
		lispSignatures: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\(\s*defun\b`),
			regexp.MustCompile(`(?i)\(\s*setq\b`),
			regexp.MustCompile(`(?i)\(\s*command\b`),
			regexp.MustCompile(`(?i)\(\s*if\b`),
		},
		// Behavioral extraction patterns
		reShell:      regexp.MustCompile(`(?i)\bShell\s+"([^"]+)"|\bShell\s+([^\n,]+)`),
		reCreateObj:  regexp.MustCompile(`(?i)(?:CreateObject|GetObject)\s*\(\s*["']?\s*"?([^"(),\s]+)"?`),
		reOpenWrite:  regexp.MustCompile(`(?i)\bOpen\s+"([^"]+)"\s+For\s+Output`),
		reOpenRead:   regexp.MustCompile(`(?i)\bOpen\s+"([^"]+)"\s+For\s+Input`),
		reRegistry:   regexp.MustCompile(`(?i)(HKEY_[A-Z_]+\\[^\n"]+)`),
		reURL:        regexp.MustCompile(`(?i)https?://[^\s"'()]+`),
		reHook:       regexp.MustCompile(`(?i)Private\s+Sub\s+(AcadDocument_\w+|ACADApp_\w+)\s*\(`),
		reTemplate:   regexp.MustCompile(`(?i)\.dwt\b|acad\.dwt|acadiso\.dwt`),
		reAcaddoc:    regexp.MustCompile(`(?i)acaddoc\.lsp`),
		reUndefine:   regexp.MustCompile(`(?i)command\s+["']undefine["']\s*,?\s*["']([^"']+)["']`),
		reWMI:        regexp.MustCompile(`(?i)winmgmts|WMIobj|SELECT\s+\*\s+FROM\s+\w+`),
		reMAC:        regexp.MustCompile(`(?i)MACAddress|NetConnectionID`),
		reSaveAs:     regexp.MustCompile(`(?i)\.SaveAs\b`),
		reCodeInject: regexp.MustCompile(`(?i)InsertLines|AddFromString|CodeModule`),
	}
}

// IsVBASource returns true if source looks like VBA/VBScript rather than AutoLISP
func (a *VBAAdapter) IsVBASource(source string) bool {
	source = sampleVBADetectionSource(source)
	if source == "" || strings.TrimSpace(source) == "" {
		return false
	}

	vbaHits := 0
	for _, p := range a.vbaSignatures {
		if p.MatchString(source) {
			vbaHits++
		}
	}

	lispHits := 0
	for _, p := range a.lispSignatures {
		if p.MatchString(source) {
			lispHits++
		}
	}

	return vbaHits >= 2 && vbaHits > lispHits
}

func sampleVBADetectionSource(source string) string {
	if len(source) <= maxVBADetectionSample {
		return source
	}
	return source[:maxVBADetectionSample]
}

// ExtractBehaviors extracts behavioral signals from VBA code
func (a *VBAAdapter) ExtractBehaviors(source string) *VBABehavior {
	b := &VBABehavior{}

	// Shell commands
	for _, m := range a.reShell.FindAllStringSubmatch(source, -1) {
		cmd := ""
		if m[1] != "" {
			cmd = strings.Trim(strings.TrimSpace(m[1]), `"`)
		} else if len(m) > 2 && m[2] != "" {
			cmd = strings.Trim(strings.TrimSpace(m[2]), `"`)
		}
		if cmd != "" {
			b.ShellCommands = append(b.ShellCommands, cmd)
		}
	}

	// COM objects
	for _, m := range a.reCreateObj.FindAllStringSubmatch(source, -1) {
		if m[1] != "" {
			obj := strings.ToLower(strings.TrimSpace(m[1]))
			if obj != "" {
				b.COMObjects = append(b.COMObjects, obj)
			}
		}
	}

	// File writes
	for _, m := range a.reOpenWrite.FindAllStringSubmatch(source, -1) {
		if m[1] != "" {
			b.FileWrites = append(b.FileWrites, m[1])
		}
	}

	// File reads
	for _, m := range a.reOpenRead.FindAllStringSubmatch(source, -1) {
		if m[1] != "" {
			b.FileReads = append(b.FileReads, m[1])
		}
	}

	// Registry writes
	for _, m := range a.reRegistry.FindAllStringSubmatch(source, -1) {
		if m[1] != "" {
			key := m[1]
			if len(key) > 120 {
				key = key[:120]
			}
			b.RegistryWrites = append(b.RegistryWrites, key)
		}
	}

	// Network URLs
	for _, m := range a.reURL.FindAllString(source, -1) {
		b.NetworkURLs = append(b.NetworkURLs, m)
	}

	// Propagation hooks
	for _, m := range a.reHook.FindAllStringSubmatch(source, -1) {
		if len(m) > 1 && m[1] != "" {
			b.PropagationHooks = append(b.PropagationHooks, m[1])
		}
	}

	// Undefine commands
	for _, m := range a.reUndefine.FindAllStringSubmatch(source, -1) {
		if len(m) > 1 && m[1] != "" {
			b.UndefineCommands = append(b.UndefineCommands, m[1])
		}
	}

	// WMI queries
	if a.reWMI.MatchString(source) {
		b.WMIQueries = append(b.WMIQueries, "WMI enumeration detected")
	}

	// MAC harvest
	if a.reMAC.MatchString(source) {
		b.MacHarvest = true
	}

	// Template infection
	if a.reTemplate.MatchString(source) {
		b.TemplateInfection = true
		// Collect .dwt paths
		reDWT := regexp.MustCompile(`"([^"]*\.dwt)"`)
		for _, m := range reDWT.FindAllStringSubmatch(source, -1) {
			if len(m) > 1 {
				b.AutoloadTargets = append(b.AutoloadTargets, m[1])
			}
		}
	}

	// acaddoc.lsp references
	if a.reAcaddoc.MatchString(source) {
		b.AutoloadTargets = append(b.AutoloadTargets, "acaddoc.lsp")
	}

	// SaveAs indicates template infection
	if a.reSaveAs.MatchString(source) {
		b.TemplateInfection = true
	}

	// Code injection via InsertLines/AddFromString
	if a.reCodeInject.MatchString(source) {
		b.CodeInject = true
	}

	return b
}

// ToPseudoLisp translates VBA behavioral signals into pseudo-AutoLISP
func (a *VBAAdapter) ToPseudoLisp(source string, behavior *VBABehavior) string {
	if behavior == nil {
		behavior = a.ExtractBehaviors(source)
	}

	lines := []string{
		"; vba_adapter: translated from VBA/VBScript",
		"(defun s::startup ()",
	}

	// Propagation hooks -> reactor registration equivalent
	for _, hook := range behavior.PropagationHooks {
		hookLower := strings.ToLower(hook)
		if strings.Contains(hookLower, "beginclose") ||
			strings.Contains(hookLower, "deactivate") ||
			strings.Contains(hookLower, "activate") {
			lines = append(lines, `  (vlr-dwg-reactor nil (list (cons :vlr-beginClose (function vba-payload))))`)
			lines = append(lines, `  (vlr-dwg-reactor nil (list (cons :vlr-saveComplete (function vba-payload))))`)
		}
	}

	// COM object creation
	for _, obj := range behavior.COMObjects {
		lines = append(lines, `  (vlax-create-object "`+escapeString(obj)+`")`)
	}

	// Shell execution
	for _, cmd := range behavior.ShellCommands {
		lines = append(lines, `  (command "shell" "`+escapeString(cmd)+`")`)
		if strings.Contains(strings.ToLower(cmd), "regedit") {
			lines = append(lines, `  (vl-registry-write "HKEY_CURRENT_USER\\Software\\Autodesk" "AutoEmbedding" 1)`)
		}
	}

	// Registry writes (limit to 8)
	limit := 8
	if len(behavior.RegistryWrites) < limit {
		limit = len(behavior.RegistryWrites)
	}
	for i := 0; i < limit; i++ {
		reg := behavior.RegistryWrites[i]
		lines = append(lines, `  (vl-registry-write "`+escapeString(reg)+`" "value" 1)`)
	}

	// File writes (limit to 8)
	limit = 8
	if len(behavior.FileWrites) < limit {
		limit = len(behavior.FileWrites)
	}
	for i := 0; i < limit; i++ {
		fw := behavior.FileWrites[i]
		lines = append(lines, `  (setq _f (open "`+escapeString(fw)+`" "w"))`)
		lines = append(lines, `  (close _f)`)
	}

	// File reads (limit to 4)
	limit = 4
	if len(behavior.FileReads) < limit {
		limit = len(behavior.FileReads)
	}
	for i := 0; i < limit; i++ {
		fr := behavior.FileReads[i]
		lines = append(lines, `  (setq _f (open "`+escapeString(fr)+`" "r"))`)
		lines = append(lines, `  (close _f)`)
	}

	// Network URLs (limit to 4)
	limit = 4
	if len(behavior.NetworkURLs) < limit {
		limit = len(behavior.NetworkURLs)
	}
	for i := 0; i < limit; i++ {
		url := behavior.NetworkURLs[i]
		lines = append(lines, `  (vlax-invoke-method _http "Open" "GET" "`+escapeString(url)+`" nil)`)
	}

	// WMI / MAC harvest
	if behavior.MacHarvest || len(behavior.WMIQueries) > 0 {
		lines = append(lines, `  (vlax-create-object "WbemScripting.SWbemLocator")`)
		lines = append(lines, `  (vlax-invoke-method _wmi "ExecQuery" "SELECT * FROM Win32_NetworkAdapter")`)
	}

	// Template / acaddoc infection (propagation)
	if behavior.TemplateInfection {
		lines = append(lines, `  (vl-file-copy (findfile "acaddoc.lsp") (strcat (getvar "roamablerootprefix") "acaddoc.lsp"))`)
		tgtLimit := 4
		if len(behavior.AutoloadTargets) < tgtLimit {
			tgtLimit = len(behavior.AutoloadTargets)
		}
		for i := 0; i < tgtLimit; i++ {
			tgt := behavior.AutoloadTargets[i]
			lines = append(lines, `  (vl-file-copy _src "`+escapeString(tgt)+`")`)
		}
	}

	// Undefine commands (sabotage, limit to 8)
	limit = 8
	if len(behavior.UndefineCommands) < limit {
		limit = len(behavior.UndefineCommands)
	}
	for i := 0; i < limit; i++ {
		cmd := behavior.UndefineCommands[i]
		lines = append(lines, `  (command "undefine" "`+escapeString(cmd)+`")`)
	}

	// Code injection (macro virus behavior)
	if behavior.CodeInject {
		lines = append(lines, `  (setq _doc (vlax-get-property (vlax-get-acad-object) "ActiveDocument"))`)
		lines = append(lines, `  (setq _vbe (vlax-get-property _doc "VBProject"))`)
		lines = append(lines, `  (setq _code (vlax-get-property _vbe "CodeModule"))`)
		lines = append(lines, `  (vlax-invoke-method _code "InsertLines" 1 "(setq flag t)")`)
		lines = append(lines, `  (vlax-invoke-method _code "AddFromString" "(load \"acaddoc.lsp\")")`)
		lines = append(lines, `  (vl-file-copy (findfile "acaddoc.lsp") (strcat (getvar "roamablerootprefix") "acaddoc.lsp"))`)
	}

	lines = append(lines, ")")

	// Payload function (called by reactor hooks)
	if len(behavior.PropagationHooks) > 0 {
		lines = append(lines, "(defun vba-payload (/ _src _dst)")
		if behavior.TemplateInfection {
			lines = append(lines, `  (setq _src (findfile "acaddoc.lsp"))`)
			lines = append(lines, `  (vl-file-copy _src (strcat (getvar "roamablerootprefix") "acaddoc.lsp"))`)
		}
		tgtLimit := 4
		if len(behavior.AutoloadTargets) < tgtLimit {
			tgtLimit = len(behavior.AutoloadTargets)
		}
		for i := 0; i < tgtLimit; i++ {
			tgt := behavior.AutoloadTargets[i]
			lines = append(lines, `  (vl-file-copy _src "`+escapeString(tgt)+`")`)
		}
		lines = append(lines, ")")
	}

	return strings.Join(lines, "\n")
}

// Adapt adapts VBA source to pseudo-LISP source
func (a *VBAAdapter) Adapt(source string, filepath string) *VBAAdaptResult {
	behavior := a.ExtractBehaviors(source)
	pseudoLisp := a.ToPseudoLisp(source, behavior)

	meta := map[string]interface{}{
		"original_type":      "vba",
		"filepath":           filepath,
		"shell_commands":     len(behavior.ShellCommands),
		"com_objects":        behavior.COMObjects,
		"file_writes":        len(behavior.FileWrites),
		"registry_writes":    len(behavior.RegistryWrites),
		"network_urls":       behavior.NetworkURLs,
		"propagation_hooks":  behavior.PropagationHooks,
		"template_infection": behavior.TemplateInfection,
		"mac_harvest":        behavior.MacHarvest,
		"undefine_commands":  behavior.UndefineCommands,
	}

	return &VBAAdaptResult{
		Source: pseudoLisp,
		Meta:   meta,
	}
}

// escapeString escapes a string for LSP embedding
func escapeString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
