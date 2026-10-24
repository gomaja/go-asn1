// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_copy_test.go; SHA-256 41906d60e265ae81a14909a0e9310435bfe9cdb720dc7345fa87570fc329c77f.
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
	bb := NewBudgetBuffer(nil)
	bb.SetReplayPlan(&p)
	previous := bb.SuspendReplayPlan()
	if bb.ReplayPlan() != nil {
		t.Fatal("fresh subtree inherited replay")
	}
	bb.RestoreReplayPlan(previous)
	if bb.ReplayPlan() != &p {
		t.Fatal("fresh subtree changed siblings")
	}
}
func TestPackedLeafOwnershipUsesOneAllocation(t *testing.T) {
	data := []byte{0}
	allocations := testing.AllocsPerRun(100, func() {
		wire, state := OwnDecodeOptions(data)
		bb := NewCompleteDecodeBuffer(wire, state)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			panic(err)
		}
		if _, err := bb.ReadBit(); err != nil {
			panic(err)
		}
		value := bb.OwnInt64(7)
		s := SemanticCaptureFor(state)
		f := s.Begin()
		s.Int(*value)
		var root Snapshot
		s.End(f, &root, false)
		if _, err := FinishDecode(state, nil); err != nil {
			panic(err)
		}
	})
	t.Logf("packed leaf allocations=%v", allocations)
	if allocations != 1 {
		t.Fatalf("packed decode allocates %v, want one owner", allocations)
	}
}

func TestAlignedWriteBytesHasBulkPath(t *testing.T) {
	source, err := parser.ParseFile(token.NewFileSet(), "bitbuffer.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	bulk := 0
	for _, decl := range source.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "WriteBytes" {
			continue
		}
		for _, statement := range fn.Body.List {
			branch, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			aligned := false
			ast.Inspect(branch.Cond, func(n ast.Node) bool {
				if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.REM {
					aligned = true
				}
				return true
			})
			if !aligned {
				continue
			}
			ast.Inspect(branch.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "AppendValues" {
					bulk++
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "WriteBits" || sel.Sel.Name == "WriteBit") {
					t.Error("aligned bytes use per-bit writer")
				}
				return true
			})
		}
	}
	if bulk < 1 {
		t.Fatal("aligned byte-copy path missing")
	}
}
