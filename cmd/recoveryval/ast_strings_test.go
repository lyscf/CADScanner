package main

import "testing"

func TestExtractExpectedStringsFromSource_AST(t *testing.T) {
	src := `
(defun c:test ()
  (prompt "found!")
  (setq x "cmdecho")
  (setq y "(setq danger 1)")
  (setvar "cmdecho" 0)
  (set_tile "accept" "Run")
  (prompt (strcat "cannot complete function: exiting..." " now"))
  (setq z '("quoted-data"))
  (findfile "support/main.dcl")
)`

	got := extractExpectedStringsFromSource(src)
	gotSet := make(map[string]bool, len(got))
	for _, s := range got {
		gotSet[s] = true
	}

	wantPresent := []string{
		"found!",
		"cannot complete function: exiting...",
		"now",
		"run",
		"support/main.dcl",
	}
	for _, s := range wantPresent {
		if !gotSet[s] {
			t.Fatalf("expected string %q to be kept, got=%v", s, got)
		}
	}

	wantAbsent := []string{
		"cmdecho",
		"(setq danger 1)",
		"quoted-data",
	}
	for _, s := range wantAbsent {
		if gotSet[s] {
			t.Fatalf("expected string %q to be filtered, got=%v", s, got)
		}
	}
}
