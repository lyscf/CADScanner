package detector

import "strings"

func IsSuspiciousRegistryPath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}

	suspiciousPatterns := []string{
		`\currentversion\run`,
		`\currentversion\runonce`,
		`\currentversion\policies\explorer\run`,
		`\windows script host\settings`,
		`\windows nt\currentversion\winlogon`,
		`\image file execution options\`,
		`\command processor\autorun`,
		`\shell\open\command`,
		`\exefile\shell\open\command`,
		`\firewallpolicy\`,
		`\services\`,
		`\startupapproved\`,
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

func IsSuspiciousProcessCommand(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	if lower == "" {
		return false
	}

	directPatterns := []string{
		" net user", " net share", "regedit", "rundll32", "regsvr32",
		"mshta", "cscript", "wscript", "cmd.exe /c", "cmd /c",
		"installhinfsection", "setupapi",
	}
	for _, pattern := range directPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	if strings.Contains(lower, "powershell") {
		return IsLikelyMaliciousPowerShell(lower)
	}

	return false
}

func IsLikelyMaliciousPowerShell(command string) bool {
	lower := strings.ToLower(strings.TrimSpace(command))
	if !strings.Contains(lower, "powershell") {
		return false
	}

	highRiskIndicators := []string{
		"-enc", "-encodedcommand", "invoke-expression", "iex ",
		"downloadstring", "downloadfile", "invoke-webrequest",
		"start-bitstransfer", "net.webclient", "frombase64string",
		"http://", "https://", "new-object system.net.webclient",
	}
	for _, indicator := range highRiskIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	// Hidden/bypass alone is noisy for licensing scripts. Keep it suspicious
	// only when paired with script staging or explicit shell chaining.
	if (strings.Contains(lower, "-executionpolicy bypass") || strings.Contains(lower, "-windowstyle hidden")) &&
		(strings.Contains(lower, ".ps1") || strings.Contains(lower, "start-process") || strings.Contains(lower, "cmd.exe")) {
		return true
	}

	return false
}
