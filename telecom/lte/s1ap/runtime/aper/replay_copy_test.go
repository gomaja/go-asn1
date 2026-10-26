// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_copy_test.go; SHA-256 8e564fb2ceeff63d25d57ee2603bc92079582767617a5d33fe51256921c079a9.
package aper

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestWireSpanCopiesAlignedOctets(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "wire_span.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	copies := 0
	for _, d := range source.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "copySpan" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "WriteBytes" {
				copies++
			}
			return true
		})
	}
	if copies != 1 {
		t.Fatalf("span replay has %d byte-copy paths; aligned octets must use one", copies)
	}
}
func TestSemanticComparisonAndPlanStayOnStack(t *testing.T) {
	var root Snapshot
	s := NewSemanticCapture(128)
	f := s.Begin()
	s.Uint(7)
	s.End(f, &root, false)
	allocs := testing.AllocsPerRun(100, func() {
		c := NewSemanticComparison(root)
		f := c.Begin()
		c.Uint(7)
		c.End(f, root, false)
		p := c.Plan()
		if !p.Unchanged(root) {
			panic("lost exact comparison")
		}
	})
	if allocs != 0 {
		t.Fatalf("unchanged comparison allocates: %.0f", allocs)
	}
}
func TestFreshPlanScopeRestoresSiblings(t *testing.T) {
	p := ReplayPlan{}
	b := NewEncodeBuffer(&p)
	previous := b.SuspendReplayPlan()
	if b.ReplayPlan() != nil {
		t.Fatal("fresh subtree inherited replay")
	}
	b.RestoreReplayPlan(previous)
	if b.ReplayPlan() != &p {
		t.Fatal("fresh subtree changed sibling plan")
	}
}

func TestReceivedSpanViewsAndMutableScalarStorage(t *testing.T) {
	original, options := ownTestDecodeInput([]byte{1, 2, 3}, decodeSettings{})
	b := newTestCompleteDecodeBuffer(original, options)
	if err := b.setDecodeSettingsAligned(options); err != nil {
		t.Fatal(err)
	}
	one, two := b.OwnInt64(1), b.OwnInt64(2)
	*one = 9
	if *two != 2 {
		t.Fatal("mutable scalar arms share storage")
	}
	image := OriginalWire(original)
	raw := OpaqueOpenType{image: image}
	var retained WireSpan
	raw.RetainContents(&retained)
	form := NewCompleteReceivedSpanForm(true, retained, "value", true, CompletePadding{})
	copy := form.OriginalBytes()
	copy[0] = 9
	if original[0] != 1 || form.OriginalBytes()[0] != 1 {
		t.Fatal("received view aliases original")
	}
	location := form.Location()
	location.Spans[0].Start = 99
	if form.Location().Spans[0].Start != 0 {
		t.Fatal("received location aliases codec metadata")
	}
	p := ReplayPlan{}
	if FirstReplayPlan(nil, &p) != nil || FirstReplayPlan(&p) != &p || FirstReplayPlan() != nil {
		t.Fatal("per-call plan carrier differs")
	}
}
