package main

import "testing"

func TestExtractExpectedGlobalBindingNamesFromSource_ExcludesLocalTemps(t *testing.T) {
	src := `
(setq appHome "C:/cad")
(defun c:test (arg / tmp path)
  (setq tmp 1)
  (setq path (strcat appHome "/plugin.lsp"))
  (setq sharedVar tmp)
  (setq arg 2)
  (setq helperName "visible")
)
(setq globalFlag T)
`

	got := extractExpectedGlobalBindingNamesFromSource(src)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"apphome", "globalflag"} {
		if !gotSet[want] {
			t.Fatalf("expected binding %q to be counted, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"tmp", "path", "arg", "sharedvar", "helpername"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected local/intermediate binding %q to be excluded, got=%v", wantAbsent, got)
		}
	}
}

func TestExtractRecoveredGlobalBindingNames_SkipsLocalAndFunctionLikeNames(t *testing.T) {
	meta := map[string]interface{}{
		"recovered_bindings": []interface{}{
			map[string]interface{}{"scope": "global", "name": "appHome", "kind": "call", "value": "C:/cad"},
			map[string]interface{}{"scope": "slot", "name": "tmp", "value": "1"},
			map[string]interface{}{"scope": "global", "name": "c:test", "kind": "symbol", "value": "helper"},
			map[string]interface{}{"scope": "global", "name": "setvar", "kind": "symbol", "value": "cmdecho"},
			map[string]interface{}{"scope": "global", "name": "shared_var", "kind": "literal", "value": "ok"},
		},
	}

	got := extractRecoveredGlobalBindingNames(meta)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"apphome", "shared_var"} {
		if !gotSet[want] {
			t.Fatalf("expected recovered global binding %q to be kept, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"tmp", "c:test", "setvar"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected recovered binding %q to be filtered, got=%v", wantAbsent, got)
		}
	}
}

func TestExtractRecoveredTopLevelBindingNamesFromSource_ExcludesInnerBindings(t *testing.T) {
	src := `
(setq 'appHome "C:/cad")
(progn
  (setq globalFlag T)
)
(defun c:test (arg / tmp path)
  (setq tmp 1)
  (setq path "x")
  (setq sharedVar tmp)
)
(lambda (/ hidden)
  (setq hidden 1)
)
`

	got := extractRecoveredTopLevelBindingNamesFromSource(src)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"apphome", "globalflag"} {
		if !gotSet[want] {
			t.Fatalf("expected recovered top-level binding %q to be kept, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"tmp", "path", "sharedvar", "hidden", "arg"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected inner binding %q to be excluded, got=%v", wantAbsent, got)
		}
	}
}

func TestFilterMeaningfulBindingNames_StripsGenericTemps(t *testing.T) {
	in := []string{
		"dwgpath",
		"acadpath",
		"support_path",
		"temp",
		"file",
		"ss",
		"ent",
		"lst",
		"fp1",
		"path3",
		"name",
		"result",
		"annotationobject",
	}

	got := filterMeaningfulBindingNames(in)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"dwgpath", "acadpath", "support_path", "path3", "annotationobject"} {
		if !gotSet[want] {
			t.Fatalf("expected meaningful binding %q to remain, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"temp", "file", "ss", "ent", "lst", "fp1", "name", "result"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected generic binding %q to be filtered, got=%v", wantAbsent, got)
		}
	}
}

func TestFilterRecoveredBindingNames_StripsDecompilerNoise(t *testing.T) {
	in := []string{
		"dwgpath",
		"acadpath",
		"mnlfilename1",
		"local_12",
		"arg_0",
		"alias_91",
		"mapcar",
		"open",
		"vla-get-modelspace",
		"acdbpolyline",
		"*error*",
		"null_result",
	}

	got := filterRecoveredBindingNames(in)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"dwgpath", "acadpath", "mnlfilename1"} {
		if !gotSet[want] {
			t.Fatalf("expected recovered binding %q to remain, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"local_12", "arg_0", "alias_91", "mapcar", "open", "vla-get-modelspace", "acdbpolyline", "*error*", "null_result"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected recovered binding noise %q to be filtered, got=%v", wantAbsent, got)
		}
	}
}

func TestExtractFoldedExpectedBindingNamesFromSource_RemovesTransitBindings(t *testing.T) {
	src := `
(setq acadexe (findfile "acad.exe"))
(setq acadpath (vl-filename-directory acadexe))
(setq support_path (strcat acadpath "\\support"))
(setq dwgname (getvar "dwgname"))
(setq dwgpath (findfile dwgname))
(if dwgpath
  (prompt dwgpath)
)
(open support_path "r")
`

	got := extractFoldedExpectedBindingNamesFromSource(src)
	gotSet := make(map[string]bool, len(got))
	for _, name := range got {
		gotSet[name] = true
	}

	for _, want := range []string{"support_path", "dwgpath"} {
		if !gotSet[want] {
			t.Fatalf("expected folded binding %q to remain, got=%v", want, got)
		}
	}

	for _, wantAbsent := range []string{"acadexe", "acadpath", "dwgname"} {
		if gotSet[wantAbsent] {
			t.Fatalf("expected transit binding %q to be folded away, got=%v", wantAbsent, got)
		}
	}
}
