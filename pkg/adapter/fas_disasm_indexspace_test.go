package adapter

import "testing"

func TestDisassemblerUsesSeparateIndexSpacesForSymbolsAndConsts(t *testing.T) {
	d := NewDisassembler(nil, []string{"RIGHT_SYM"}, []string{"RIGHT_CONST"})
	d.SetResourcePool([]FASResourceEntry{
		{Index: 0, Kind: "symbol", Value: "WRONG_SYM"},
		{Index: 1, Kind: "string", Value: "WRONG_CONST"},
	})

	if got, ok := d.symbolValueAt(0); !ok || got != "RIGHT_SYM" {
		t.Fatalf("symbolValueAt(0)=%q,%v want RIGHT_SYM,true", got, ok)
	}
	if got, ok := d.constValueAt(0); !ok || got != "RIGHT_CONST" {
		t.Fatalf("constValueAt(0)=%q,%v want RIGHT_CONST,true", got, ok)
	}
}
