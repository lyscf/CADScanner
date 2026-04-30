package ir

import (
	"strings"
)

// TypeKind represents type categories
type TypeKind string

const (
	TypeUnknown    TypeKind = "unknown"
	TypeString     TypeKind = "string"
	TypeNumber     TypeKind = "number"
	TypeBoolean    TypeKind = "boolean"
	TypeFileHandle TypeKind = "file_handle"
	TypeCOMObject  TypeKind = "com_object"
	TypeList       TypeKind = "list"
	TypeFunction   TypeKind = "function"
)

// IRType represents a type in the IR type system
type IRType struct {
	TypeKind TypeKind
}

// String returns string representation of the type
func (t *IRType) String() string {
	return string(t.TypeKind)
}

// NewUnknownType creates a new unknown type
func NewUnknownType() *IRType {
	return &IRType{TypeKind: TypeUnknown}
}

// NewStringType creates a new string type
func NewStringType() *IRType {
	return &IRType{TypeKind: TypeString}
}

// NewNumberType creates a new number type
func NewNumberType() *IRType {
	return &IRType{TypeKind: TypeNumber}
}

// NewBooleanType creates a new boolean type
func NewBooleanType() *IRType {
	return &IRType{TypeKind: TypeBoolean}
}

// FileHandleType represents a file handle type with mode
type FileHandleType struct {
	*IRType
	Mode string // "r", "w", "a"
}

// NewFileHandleType creates a new file handle type
func NewFileHandleType(mode string) *FileHandleType {
	return &FileHandleType{
		IRType: &IRType{TypeKind: TypeFileHandle},
		Mode:   mode,
	}
}

// String returns string representation of the file handle type
func (t *FileHandleType) String() string {
	if t.Mode != "" {
		return "file_handle(" + t.Mode + ")"
	}
	return "file_handle"
}

// COMObjectType represents a COM object type with object name
type COMObjectType struct {
	*IRType
	ObjectName string
}

// NewCOMObjectType creates a new COM object type
func NewCOMObjectType(objectName string) *COMObjectType {
	return &COMObjectType{
		IRType:     &IRType{TypeKind: TypeCOMObject},
		ObjectName: objectName,
	}
}

// String returns string representation of the COM object type
func (t *COMObjectType) String() string {
	return "com_object(" + t.ObjectName + ")"
}

// ListType represents a list type with element type
type ListType struct {
	*IRType
	ElementType *IRType
}

// NewListType creates a new list type
func NewListType(elementType *IRType) *ListType {
	if elementType == nil {
		elementType = NewUnknownType()
	}
	return &ListType{
		IRType:      &IRType{TypeKind: TypeList},
		ElementType: elementType,
	}
}

// String returns string representation of the list type
func (t *ListType) String() string {
	return "list(" + t.ElementType.String() + ")"
}

// TypeInference provides type inference for IR instructions
type TypeInference struct {
	typeMap map[string]TypeInterface
}

// TypeInterface represents the interface for all types
type TypeInterface interface {
	String() string
	GetKind() TypeKind
}

// GetKind returns the kind of the type
func (t *IRType) GetKind() TypeKind {
	return t.TypeKind
}

// GetKind returns the kind of the file handle type
func (t *FileHandleType) GetKind() TypeKind {
	return t.TypeKind
}

// GetKind returns the kind of the COM object type
func (t *COMObjectType) GetKind() TypeKind {
	return t.TypeKind
}

// GetKind returns the kind of the list type
func (t *ListType) GetKind() TypeKind {
	return t.TypeKind
}

// NewTypeInference creates a new type inference instance
func NewTypeInference() *TypeInference {
	ti := &TypeInference{
		typeMap: make(map[string]TypeInterface),
	}
	ti.initializeTypeMap()
	return ti
}

// initializeTypeMap initializes the function return type mapping
func (ti *TypeInference) initializeTypeMap() {
	// String operations
	ti.typeMap["strcat"] = NewStringType()
	ti.typeMap["itoa"] = NewStringType()
	ti.typeMap["atoi"] = NewNumberType()
	ti.typeMap["strlen"] = NewNumberType()
	ti.typeMap["substr"] = NewStringType()

	// File operations
	ti.typeMap["open"] = NewFileHandleType("r")
	ti.typeMap["close"] = NewBooleanType()
	ti.typeMap["findfile"] = NewStringType()

	// COM operations
	ti.typeMap["vlax-load"] = NewCOMObjectType("vlx")
	ti.typeMap["create-object"] = NewCOMObjectType("unknown")

	// List operations
	ti.typeMap["list"] = NewListType(nil)
	ti.typeMap["car"] = NewUnknownType()
	ti.typeMap["cdr"] = NewListType(nil)
}

// InferType infers the type of a function call
func (ti *TypeInference) InferType(funcName string) TypeInterface {
	if t, ok := ti.typeMap[funcName]; ok {
		return t
	}
	return NewUnknownType()
}

// InferCallType infers the type of a function call with arguments (matches Python version)
func (ti *TypeInference) InferCallType(funcName string, args []interface{}) TypeInterface {
	// Normalize function name
	normalizedFunc := normalizeFunc(funcName)

	// Check type map first
	if t, ok := ti.typeMap[normalizedFunc]; ok {
		return t
	}

	// Special cases based on function name patterns
	if normalizedFunc == "create-object" || normalizedFunc == "vlax-create" {
		if len(args) > 0 {
			if comName, ok := args[0].(string); ok {
				return NewCOMObjectType(comName)
			}
		}
		return NewCOMObjectType("unknown")
	}

	if normalizedFunc == "open" || normalizedFunc == "findfile" {
		return NewFileHandleType("r")
	}

	if normalizedFunc == "strcat" || normalizedFunc == "vl-string-subst" {
		return NewStringType()
	}

	return NewUnknownType()
}

// normalizeFunc normalizes a function name (matches Python version)
func normalizeFunc(funcName string) string {
	if funcName == "" {
		return ""
	}

	f := strings.ToLower(strings.TrimSpace(funcName))
	f = strings.Trim(f, "\"")
	f = strings.Trim(f, "'")

	// Remove acad: prefix
	if strings.HasPrefix(f, "acad:") {
		parts := strings.SplitN(f, ":", 2)
		if len(parts) > 1 {
			f = parts[1]
		}
	}

	// Remove stream2 pollution suffixes
	if strings.Contains(f, "[") {
		parts := strings.SplitN(f, "[", 2)
		f = parts[0]
	}

	// Remove non-alphanumeric characters except hyphens and colons
	result := ""
	for _, c := range f {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '<' || c == '>' {
			result += string(c)
		}
	}

	return result
}

// InferTypeFromValue infers type from a literal value
func (ti *TypeInference) InferTypeFromValue(value interface{}) *IRType {
	switch value.(type) {
	case string:
		return NewStringType()
	case int, int32, int64, float32, float64:
		return NewNumberType()
	case bool:
		return NewBooleanType()
	default:
		return NewUnknownType()
	}
}

// AddTypeMapping adds a custom type mapping
func (ti *TypeInference) AddTypeMapping(funcName string, irType *IRType) {
	ti.typeMap[funcName] = irType
}
