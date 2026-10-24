// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	ast "go/ast"
	parser "go/parser"
	token "go/token"
	filepath "path/filepath"
	strconv "strconv"
	testing "testing"
)

// All source integer bounds are package initialization values. Repeated
// codecs must not parse them again or make one parsed copy per call site.
func TestConstantBoundsParsedOnlyAtInitialization(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob("internal/model/*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, shards...)
	counts := map[string]int{}
	local := 0
	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			_, inFunction := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "MustParseBigIntDecimal" {
					return true
				}
				if inFunction {
					local++
					return false
				}
				literal, ok := call.Args[0].(*ast.BasicLit)
				if !ok {
					t.Fatal("nonliteral bound")
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				counts[value]++
				return false
			})
		}
	}
	if local != 0 {
		t.Fatalf("integer bounds still parsed in %d codec call sites", local)
	}
	if len(counts) == 0 {
		t.Fatal("no parsed source bounds found")
	}
	for value, count := range counts {
		if count != 1 {
			t.Errorf("bound %s parsed %d times", value, count)
		}
	}
	t.Logf("%d distinct bounds parsed once at initialization", len(counts))
}
