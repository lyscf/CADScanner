package ir

import (
	"regexp"
	"strings"
)

var startupFilePattern = regexp.MustCompile(`(?i)\bacad(?:doc)?(?:\d{4}(?:doc)?)?\.(?:lsp|fas|vlx)\b`)

// PathResolver resolves file paths and classifies ENV_CHECK effects
type PathResolver struct {
	functions map[string]*IRFunction
	effects   []IREffect
}

// NewPathResolver creates a new path resolver
func NewPathResolver(functions map[string]*IRFunction, effects []IREffect) *PathResolver {
	return &PathResolver{
		functions: functions,
		effects:   effects,
	}
}

// ResolvePath resolves a file path with metadata
func (r *PathResolver) ResolvePath(path string, origin string) *ResolvedPath {
	lowerPath := strings.ToLower(path)

	resolved := &ResolvedPath{
		Path:            path,
		Origin:          origin,
		PathType:        "unknown",
		Severity:        "medium",
		Components:      []string{},
		ResolutionLevel: "unresolved",
	}

	// Determine resolution level
	if path == "unknown" {
		resolved.ResolutionLevel = "unresolved"
	} else if strings.Contains(path, "<") {
		resolved.ResolutionLevel = "partial"
	} else {
		resolved.ResolutionLevel = "full"
	}

	// Classify path type
	if r.isStartupFile(lowerPath) {
		resolved.PathType = "startup_file"
		resolved.Severity = "high"
	} else if r.isMenuFile(lowerPath) {
		resolved.PathType = "menu_file"
		resolved.Severity = "medium"
	} else if r.isDataFile(lowerPath) {
		resolved.PathType = "data_file"
		resolved.Severity = "low"
	}

	return resolved
}

// ResolveEnvCheck resolves and classifies an environment check
func (r *PathResolver) ResolveEnvCheck(source string, checkType string) *ResolvedEnvCheck {
	envCheck := &ResolvedEnvCheck{
		Source:   source,
		Severity: "medium",
		Purpose:  "unknown",
	}

	// Classify check type
	switch strings.ToUpper(checkType) {
	case "CDATE", "DATE":
		envCheck.CheckType = EnvCheckTime
		envCheck.Purpose = "delayed_execution"
	case "MACADDR", "HOSTNAME":
		envCheck.CheckType = EnvCheckHostID
		envCheck.Purpose = "targeting"
	case "DWGPREFIX", "DWGNAME":
		envCheck.CheckType = EnvCheckFileContext
		envCheck.Purpose = "propagation"
	case "MENUNAME", "ACADVER":
		envCheck.CheckType = EnvCheckAppContext
		envCheck.Purpose = "detection"
	case "PLATFORM", "VERSION":
		envCheck.CheckType = EnvCheckSystem
		envCheck.Purpose = "detection"
	default:
		envCheck.CheckType = EnvCheckSystem
		envCheck.Purpose = "unknown"
	}

	// Assess severity based on purpose
	if envCheck.Purpose == "delayed_execution" || envCheck.Purpose == "targeting" {
		envCheck.Severity = "high"
	}

	return envCheck
}

// isStartupFile checks if a path is a startup file
func (r *PathResolver) isStartupFile(path string) bool {
	return strings.Contains(path, "acaddoc.lsp") ||
		strings.Contains(path, "acad.fas") ||
		strings.Contains(path, "acad.lsp") ||
		strings.Contains(path, "s::startup") ||
		strings.Contains(path, "startup") ||
		startupFilePattern.MatchString(path)
}

// isMenuFile checks if a path is a menu file
func (r *PathResolver) isMenuFile(path string) bool {
	return strings.Contains(path, ".mnl") ||
		strings.Contains(path, ".mnu") ||
		strings.Contains(path, "menu") ||
		strings.Contains(path, "cui")
}

// isDataFile checks if a path is a data file
func (r *PathResolver) isDataFile(path string) bool {
	return strings.Contains(path, ".dwg") ||
		strings.Contains(path, ".dxf") ||
		strings.Contains(path, ".bak") ||
		strings.Contains(path, ".tmp")
}
