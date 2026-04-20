# CADScanner

Chinese version: [README_zh-CN.md](./README_zh-CN.md)

CADScanner is a Go-based static analyzer for AutoLISP, FAS, and VLX files. This repository contains the project codebase used for CAD automation security analysis, with a focus on the core analysis pipeline and reproducible command-line workflows.

## Description

CADScanner is a security-focused analysis tool for CAD automation scripts and packaged extensions. It parses AutoLISP-family inputs, normalizes syntax across source and compiled formats, lifts program behavior into an intermediate representation, and detects suspicious capabilities such as file access, command execution, persistence logic, and obfuscation patterns. The project is designed for malware triage, rule-based inspection, and research workflows that need explainable results from a local CLI.

## Scope

- Parse and normalize AutoLISP-family inputs
- Build a security-oriented IR with lifted effects
- Detect suspicious behaviors and map them to ATT&CK-style techniques
- Produce text or JSON analysis output from a single CLI

## Repository Layout

```text
cadscanner/
|- main.go
|- configs/
|- cmd/
|- pkg/
|- examples/
|- README.md
`- README_zh-CN.md
```

## Build

```bash
go build .
```

## Test

```bash
go test ./...
```

## Usage

```bash
cadscanner examples/benign.lsp
cadscanner -format json examples/suspicious.lsp
cadscanner -config config.yaml examples/benign.lsp
go run ./cmd/inspect examples/suspicious.lsp
go run ./cmd/batcheval -root examples -format human
```

## Public Commands

- `cadscanner`: main analyzer CLI for `.lsp`, `.fas`, and `.vlx`
- `batcheval`: batch evaluation over a sample directory
- `decompile`: decompile `.fas` and `.vlx` inputs into pseudo-LISP output
- `inspect`: single-sample inspection command for effects, rule hits, and ATT&CK output
- `fasresources`: inspect extracted FAS resource tables
- `vlxdiag`: inspect VLX record structure and recovered metadata

## Research Commands

- `paperexp`: paper-oriented replay and calibration workflow over a benchmark set
- `apisufficiency`: API masking robustness experiment for recovered FAS/VLX representations
- `recoveryval`: recovery validation against paired source/compiled expectations
- `llmmetrics`: LLM cache and fusion evaluation; requires an LLM-enabled config

These commands are kept for reproducibility and evaluation, but they are not the primary user-facing CLI surface.

## Configuration

Start from `configs/config.example.yaml` when preparing a local configuration. For optional LLM-assisted analysis, keep credentials in environment variables rather than hardcoding secrets into a tracked file.

## Status

The project provides a public command set for analysis and format inspection, along with a separate group of research commands for paper reproduction and evaluation workflows.

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
