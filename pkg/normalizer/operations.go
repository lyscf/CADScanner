package normalizer

// OperationType represents canonical operation types
type OperationType string

const (
	// File operations
	FILE_OPEN   OperationType = "FILE_OPEN"
	FILE_READ   OperationType = "FILE_READ"
	FILE_WRITE  OperationType = "FILE_WRITE"
	FILE_CLOSE  OperationType = "FILE_CLOSE"
	FILE_DELETE OperationType = "FILE_DELETE"

	// String operations
	STRING_CONCAT OperationType = "STRING_CONCAT"
	STRING_DECODE OperationType = "STRING_DECODE"

	// COM operations
	COM_CREATE OperationType = "COM_CREATE"
	COM_INVOKE OperationType = "COM_INVOKE"
	COM_GET    OperationType = "COM_GET"
	COM_PUT    OperationType = "COM_PUT"

	// Registry operations
	REG_READ   OperationType = "REG_READ"
	REG_WRITE  OperationType = "REG_WRITE"
	REG_DELETE OperationType = "REG_DELETE"

	// Execution operations
	OS_EXEC        OperationType = "OS_EXEC"
	CAD_COMMAND    OperationType = "CAD_COMMAND"    // AutoCAD internal command execution (benign)
	COMMAND_HIJACK OperationType = "COMMAND_HIJACK" // Command undefine/redirection (malicious)
	EVAL           OperationType = "EVAL"
	LOAD           OperationType = "LOAD"

	// Function definition
	DEFUN  OperationType = "DEFUN"
	LAMBDA OperationType = "LAMBDA"

	// Variable operations
	SETQ   OperationType = "SETQ"
	SETVAR OperationType = "SETVAR"

	// Control flow
	IF    OperationType = "IF"
	COND  OperationType = "COND"
	WHILE OperationType = "WHILE"

	// List operations
	LIST  OperationType = "LIST"
	APPLY OperationType = "APPLY"

	// Other
	UNKNOWN OperationType = "UNKNOWN"
)

// FunctionMapping maps AutoLISP functions to canonical operations
var FunctionMapping = map[string]OperationType{
	// File operations
	"open":           FILE_OPEN,
	"close":          FILE_CLOSE,
	"read-line":      FILE_READ,
	"read-char":      FILE_READ,
	"write-line":     FILE_WRITE,
	"write-char":     FILE_WRITE,
	"princ":          FILE_WRITE,
	"print":          FILE_WRITE,
	"vl-file-delete": FILE_DELETE,
	"vl-file-copy":   FILE_WRITE,
	"vl-file-rename": FILE_WRITE,

	// String operations
	"strcat":          STRING_CONCAT,
	"strcase":         STRING_CONCAT,
	"vl-string-subst": STRING_CONCAT,
	"chr":             STRING_DECODE,
	"vl-list->string": STRING_DECODE,

	// COM operations
	"vlax-create-object":        COM_CREATE,
	"vlax-get-or-create-object": COM_CREATE,
	"vlax-invoke-method":        COM_INVOKE,
	"vlax-invoke":               COM_INVOKE,
	"vlax-get-property":         COM_GET,
	"vlax-get":                  COM_GET,
	"vlax-put-property":         COM_PUT,
	"vlax-put":                  COM_PUT,

	// Registry operations
	"vl-registry-read":   REG_READ,
	"vl-registry-write":  REG_WRITE,
	"vl-registry-delete": REG_DELETE,

	// Execution operations
	"command":  CAD_COMMAND, // AutoCAD internal command - benign
	"eval":     EVAL,
	"load":     LOAD, // Loading external code - potentially dangerous
	"startapp": OS_EXEC,

	// COM initialization (benign - just initializes COM interface)
	"vl-load-com": COM_CREATE, // Initialize AutoLISP-COM bridge (not code loading)

	// Function definition
	"defun":  DEFUN,
	"lambda": LAMBDA,

	// Variable operations
	"setq":   SETQ,
	"setvar": SETVAR,
	"set":    SETQ,

	// Control flow
	"if":    IF,
	"cond":  COND,
	"while": WHILE,

	// List operations
	"list":  LIST,
	"apply": APPLY,
}

// GetOperationType returns the canonical operation type for a function
func GetOperationType(functionName string) OperationType {
	if functionName == "" {
		return UNKNOWN
	}

	// Normalize function name
	fn := normalizeFunctionName(functionName)

	if op, ok := FunctionMapping[fn]; ok {
		return op
	}

	return UNKNOWN
}

// normalizeFunctionName normalizes a function name
func normalizeFunctionName(name string) string {
	// Convert to lowercase and strip quotes
	fn := name
	if len(fn) > 0 && (fn[0] == '"' || fn[0] == '\'') {
		fn = fn[1:]
	}
	if len(fn) > 0 && (fn[len(fn)-1] == '"' || fn[len(fn)-1] == '\'') {
		fn = fn[:len(fn)-1]
	}

	// Convert to lowercase
	fn = toLower(fn)

	// Handle FAS-adapted call names with prefixes/suffixes noise
	// Example: "ACAD:vlax-invoke-method" or "Microsoft.XMLHTTP[VIAX-IXMDX"
	if len(fn) > 5 && fn[:5] == "acad:" {
		fn = fn[5:]
	}

	// Split on bracket
	if idx := indexOf(fn, "["); idx != -1 {
		fn = fn[:idx]
	}

	// Remove trailing non-alphanumeric characters
	fn = cleanTrailing(fn)

	return fn
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

// indexOf returns the index of a substring, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// cleanTrailing removes trailing non-alphanumeric characters
func cleanTrailing(s string) string {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '<' || c == '>' {
			break
		}
		end--
	}
	return s[:end]
}
