// decompile converts FAS/VLX files into pseudo-LSP source output.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/evilcad/cadscanner/pkg/adapter"
	"github.com/evilcad/cadscanner/pkg/cliutil"
)

func normalizeFlagArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	flagsWithValue := map[string]bool{
		"-o": true, "--o": true,
		"-d": true, "--d": true,
	}
	booleanFlags := map[string]bool{
		"-r": true, "--r": true,
		"-v": true, "--v": true,
		"-extract-separate": true, "--extract-separate": true,
		"-list-only": true, "--list-only": true,
	}

	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if flagsWithValue[arg] {
			flags = append(flags, arg)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		if booleanFlags[arg] {
			flags = append(flags, arg)
			continue
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...)
}

// DecompileResult stores the result of a decompile operation.
type DecompileResult struct {
	InputPath  string
	OutputPath string
	Format     string
	Success    bool
	Message    string
	SourceCode string
	Modules    []ModuleInfo
}

// ModuleInfo describes an extracted module.
type ModuleInfo struct {
	Name string
	Type string
	Size int
}

func main() {
	var (
		output     = flag.String("o", "", "Output file path for single-file mode")
		outputDir  = flag.String("d", "", "Output directory for batch mode")
		recursive  = flag.Bool("r", false, "Recursively scan subdirectories")
		verbose    = flag.Bool("v", false, "Print verbose details")
		extractSep = flag.Bool("extract-separate", false, "Extract each VLX module into a separate file")
		listOnly   = flag.Bool("list-only", false, "List matching files only, without decompiling")
		format     = flag.String("format", "human", "Output format: human or json")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CAD decompiler for FAS/VLX to LSP-style source output\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <input file or pattern>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Decompile a single FAS file\n")
		fmt.Fprintf(os.Stderr, "  %s input.fas\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Decompile and set an explicit output path\n")
		fmt.Fprintf(os.Stderr, "  %s input.fas -o output.lsp\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Batch decompile all FAS/VLX files in the current directory\n")
		fmt.Fprintf(os.Stderr, "  %s \"*.fas\" -d ./decompiled/\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Recursive batch decompile\n")
		fmt.Fprintf(os.Stderr, "  %s \"samples/**/*.vlx\" -d ./decompiled/ -r\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Extract each VLX module separately\n")
		fmt.Fprintf(os.Stderr, "  %s input.vlx -d ./output/ --extract-separate\n", os.Args[0])
	}

	_ = flag.CommandLine.Parse(normalizeFlagArgs(os.Args[1:]))
	outputFormat, err := cliutil.ParseFormat(*format)
	if err != nil {
		cliutil.Failf("decompile: %v", err)
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	input := flag.Arg(0)

	// List matching files only.
	if *listOnly {
		files := findFiles(input, *recursive)
		if outputFormat == "json" {
			cliutil.WriteJSON(map[string]any{
				"command": "decompile",
				"mode": "list",
				"input": input,
				"recursive": *recursive,
				"files": files,
			})
			return
		}
		fmt.Printf("[*] Found %d files:\n", len(files))
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil {
				continue
			}
			ext := strings.ToUpper(filepath.Ext(f))
			fmt.Printf("    [%s] %s (%d bytes)\n", ext, f, info.Size())
		}
		return
	}

	// Detect single-file or batch mode.
	isPattern := strings.Contains(input, "*") || strings.Contains(input, "?")
	isDir := isDirectory(input)

	if isPattern || isDir || *recursive {
		// Batch mode.
		if *outputDir == "" {
			fmt.Fprintf(os.Stderr, "[!] Batch mode requires an output directory via -d\n")
			os.Exit(1)
		}

		results := batchDecompile(input, *outputDir, *recursive, *verbose && outputFormat == "human", outputFormat == "human")

		failCount := 0
		for _, r := range results {
			if !r.Success {
				failCount++
			}
		}
		if outputFormat == "json" {
			cliutil.WriteJSON(map[string]any{
				"command": "decompile",
				"mode": "batch",
				"input": input,
				"output_dir": *outputDir,
				"results": results,
				"success_count": len(results) - failCount,
				"fail_count": failCount,
			})
		}

		if failCount > 0 {
			os.Exit(1)
		}
		return
	}

	// Single-file mode.
	ext := strings.ToLower(filepath.Ext(input))
	var result DecompileResult

	switch ext {
	case ".fas":
		result = decompileFAS(input, *output, *verbose && outputFormat == "human")
	case ".vlx":
		result = decompileVLX(input, *output, *extractSep, *outputDir, *verbose && outputFormat == "human")
	case ".lsp":
		result = copyLSP(input, *output, *outputDir)
	default:
		result = DecompileResult{
			InputPath: input,
			Format:    "unknown",
			Success:   false,
			Message:   fmt.Sprintf("unsupported file type: %s", ext),
		}
	}

	if result.Success {
		if outputFormat == "json" {
			cliutil.WriteJSON(map[string]any{
				"command": "decompile",
				"mode": "single",
				"result": result,
			})
			return
		}
		fmt.Printf("[+] Success: %s\n", result.Message)
		fmt.Printf("    Output: %s\n", result.OutputPath)
	} else {
		if outputFormat == "json" {
			cliutil.WriteJSON(map[string]any{
				"command": "decompile",
				"mode": "single",
				"result": result,
			})
		}
		fmt.Fprintf(os.Stderr, "[X] Failed: %s\n", result.Message)
		os.Exit(1)
	}
}

// decompileFAS decompiles a FAS file.
func decompileFAS(inputFile, outPath string, verbose bool) DecompileResult {
	// Ensure the file exists.
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "fas",
			Success:   false,
			Message:   fmt.Sprintf("file does not exist: %s", inputFile),
		}
	}

	// Read the file.
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "fas",
			Success:   false,
			Message:   fmt.Sprintf("failed to read file: %v", err),
		}
	}

	// Decompile with the adapter.
	fasAdapter := adapter.NewFASAdapter()
	result, err := fasAdapter.Adapt(data)
	if err != nil {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "fas",
			Success:   false,
			Message:   fmt.Sprintf("decompile failed: %v", err),
		}
	}

	// Resolve the output path.
	outputPath := outPath
	if outputPath == "" {
		outputPath = generateOutputPath(inputFile, ".lsp")
	}

	// Write the output file.
	err = ioutil.WriteFile(outputPath, []byte(result.Source), 0644)
	if err != nil {
		return DecompileResult{
			InputPath:  inputFile,
			OutputPath: outputPath,
			Format:     "fas",
			Success:    false,
			Message:    fmt.Sprintf("failed to write output: %v", err),
		}
	}

	// Build module metadata.
	modules := []ModuleInfo{
		{
			Name: inputFile,
			Type: "fas",
			Size: len(data),
		},
	}

	if verbose {
		fmt.Printf("[+] FAS decompile complete: %s\n", inputFile)
		fmt.Printf("    Output: %s\n", outputPath)
		if meta, ok := result.Meta["string_count"]; ok {
			fmt.Printf("    String count: %v\n", meta)
		}
		if meta, ok := result.Meta["symbol_count"]; ok {
			fmt.Printf("    Symbol count: %v\n", meta)
		}
	}

	return DecompileResult{
		InputPath:  inputFile,
		OutputPath: outputPath,
		Format:     "fas",
		Success:    true,
		Message:    "decompile completed",
		SourceCode: result.Source,
		Modules:    modules,
	}
}

// decompileVLX decompiles a VLX file.
func decompileVLX(inputFile, outPath string, extractSeparate bool, outDir string, verbose bool) DecompileResult {
	// Ensure the file exists.
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "vlx",
			Success:   false,
			Message:   fmt.Sprintf("file does not exist: %s", inputFile),
		}
	}

	// Read the file.
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "vlx",
			Success:   false,
			Message:   fmt.Sprintf("failed to read file: %v", err),
		}
	}

	// Decompile with the adapter.
	vlxAdapter := adapter.NewVLXAdapter()
	result, err := vlxAdapter.Adapt(data)
	if err != nil {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "vlx",
			Success:   false,
			Message:   fmt.Sprintf("decompile failed: %v", err),
		}
	}

	// Resolve the output path.
	outputPath := outPath
	if outputPath == "" {
		if outDir != "" {
			baseName := path.Base(inputFile)
			outputPath = path.Join(outDir, strings.TrimSuffix(baseName, path.Ext(baseName))+".lsp")
		} else {
			outputPath = generateOutputPath(inputFile, ".lsp")
		}
	}

	// Ensure the output directory exists.
	outputDirPath := filepath.Dir(outputPath)
	if outputDirPath != "" && outputDirPath != "." {
		os.MkdirAll(outputDirPath, 0755)
	}

	// Write the merged output file.
	err = ioutil.WriteFile(outputPath, []byte(result.Source), 0644)
	if err != nil {
		return DecompileResult{
			InputPath:  inputFile,
			OutputPath: outputPath,
			Format:     "vlx",
			Success:    false,
			Message:    fmt.Sprintf("failed to write output: %v", err),
		}
	}

	// Build module metadata.
	modules := []ModuleInfo{}

	// Extract individual modules when requested.
	if extractSeparate && outDir != "" {
		// Parse the VLX output and extract each marked module.
		baseName := strings.TrimSuffix(path.Base(inputFile), path.Ext(inputFile))

		// Simple module split based on record markers.
		lines := strings.Split(result.Source, "\n")
		currentModule := ""
		var moduleContent []string

		for _, line := range lines {
			if strings.HasPrefix(line, ";; FAS Record: ") || strings.HasPrefix(line, ";; LSP Record: ") {
				// Save the previous module.
				if currentModule != "" && len(moduleContent) > 0 {
					modPath := path.Join(outDir, fmt.Sprintf("%s_%s.lsp", baseName, currentModule))
					ioutil.WriteFile(modPath, []byte(strings.Join(moduleContent, "\n")), 0644)
					modules = append(modules, ModuleInfo{
						Name: currentModule,
						Type: "fas",
						Size: len(strings.Join(moduleContent, "\n")),
					})
				}
				// Start a new module.
				if strings.HasPrefix(line, ";; FAS Record: ") {
					currentModule = strings.TrimPrefix(line, ";; FAS Record: ")
				} else {
					currentModule = strings.TrimPrefix(line, ";; LSP Record: ")
				}
				moduleContent = []string{}
			} else if currentModule != "" {
				moduleContent = append(moduleContent, line)
			}
		}

		// Save the final module.
		if currentModule != "" && len(moduleContent) > 0 {
			modPath := path.Join(outDir, fmt.Sprintf("%s_%s.lsp", baseName, currentModule))
			ioutil.WriteFile(modPath, []byte(strings.Join(moduleContent, "\n")), 0644)
			modules = append(modules, ModuleInfo{
				Name: currentModule,
				Type: "fas",
				Size: len(strings.Join(moduleContent, "\n")),
			})
		}
	}

	if verbose {
		fmt.Printf("[+] VLX decompile complete: %s\n", inputFile)
		fmt.Printf("    Output: %s\n", outputPath)
		if meta, ok := result.Meta["record_count"]; ok {
			fmt.Printf("    Record count: %v\n", meta)
		}
		if extractSeparate && len(modules) > 0 {
			fmt.Printf("    Extracted %d modules\n", len(modules))
			for _, mod := range modules {
				fmt.Printf("      - %s (%s, %d bytes)\n", mod.Name, mod.Type, mod.Size)
			}
		}
	}

	return DecompileResult{
		InputPath:  inputFile,
		OutputPath: outputPath,
		Format:     "vlx",
		Success:    true,
		Message:    "decompile completed",
		SourceCode: result.Source,
		Modules:    modules,
	}
}

// copyLSP copies an LSP file into the output location.
func copyLSP(inputFile, outPath, outDir string) DecompileResult {
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "lsp",
			Success:   false,
			Message:   fmt.Sprintf("file does not exist: %s", inputFile),
		}
	}

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return DecompileResult{
			InputPath: inputFile,
			Format:    "lsp",
			Success:   false,
			Message:   fmt.Sprintf("failed to read file: %v", err),
		}
	}

	outputPath := outPath
	if outputPath == "" {
		if outDir != "" {
			baseName := path.Base(inputFile)
			outputPath = path.Join(outDir, baseName)
		} else {
			outputPath = generateCopyOutputPath(inputFile)
		}
	}

	err = ioutil.WriteFile(outputPath, data, 0644)
	if err != nil {
		return DecompileResult{
			InputPath:  inputFile,
			OutputPath: outputPath,
			Format:     "lsp",
			Success:    false,
			Message:    fmt.Sprintf("failed to write output: %v", err),
		}
	}

	return DecompileResult{
		InputPath:  inputFile,
		OutputPath: outputPath,
		Format:     "lsp",
		Success:    true,
		Message:    "LSP file copied",
		SourceCode: string(data),
	}
}

func generateCopyOutputPath(inputPath string) string {
	dir := filepath.Dir(inputPath)
	base := filepath.Base(inputPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	ext := filepath.Ext(base)
	return filepath.Join(dir, name+".copy"+ext)
}

// batchDecompile processes multiple inputs.
func batchDecompile(pattern, outputDir string, recursive, verbose bool, human bool) []DecompileResult {
	results := []DecompileResult{}

	// Ensure the output directory exists.
	os.MkdirAll(outputDir, 0755)

	// Find matching files.
	files := findFiles(pattern, recursive)

	// Keep supported file types only.
	var filteredFiles []string
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext == ".fas" || ext == ".vlx" || ext == ".lsp" {
			filteredFiles = append(filteredFiles, f)
		}
	}
	files = filteredFiles

	if len(files) == 0 {
		if human {
			fmt.Printf("[!] No matching files found: %s\n", pattern)
		}
		return results
	}

	if human {
		fmt.Printf("[*] Found %d files. Starting decompile...\n", len(files))
		fmt.Printf("[*] Output directory: %s\n", outputDir)
		fmt.Println()
	}

	successCount := 0
	failCount := 0

	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		var result DecompileResult

		switch ext {
		case ".fas":
			result = decompileFAS(f, "", verbose)
		case ".vlx":
			result = decompileVLX(f, "", false, outputDir, verbose)
		case ".lsp":
			result = copyLSP(f, "", outputDir)
		}

		results = append(results, result)

		if result.Success {
			successCount++
		} else {
			failCount++
			if human {
				fmt.Printf("[X] Failed: %s\n", f)
				fmt.Printf("    Error: %s\n", result.Message)
			}
		}
	}

	if human {
		fmt.Println()
		fmt.Printf("[*] Decompile complete: %d succeeded, %d failed\n", successCount, failCount)
	}

	return results
}

// findFiles returns files matching the input pattern.
func findFiles(pattern string, recursive bool) []string {
	var files []string

	// If the input is a directory, walk it recursively when requested.
	if isDirectory(pattern) {
		if recursive {
			filepath.Walk(pattern, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if !info.IsDir() {
					ext := strings.ToLower(filepath.Ext(path))
					if ext == ".fas" || ext == ".vlx" || ext == ".lsp" {
						files = append(files, path)
					}
				}
				return nil
			})
		}
		return files
	}

	// Use glob matching for file patterns.
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return files
	}

	for _, match := range matches {
		if isDirectory(match) && recursive {
			// Recursively collect files from subdirectories.
			subFiles := findFiles(match+string(filepath.Separator)+"*", recursive)
			files = append(files, subFiles...)
		} else {
			files = append(files, match)
		}
	}

	return files
}

// isDirectory reports whether the path exists and is a directory.
func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// generateOutputPath derives the default output file path.
func generateOutputPath(inputPath, suffix string) string {
	dir := filepath.Dir(inputPath)
	base := filepath.Base(inputPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return filepath.Join(dir, name+suffix)
}
