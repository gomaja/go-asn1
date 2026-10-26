package lppa

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tests may use partition bridges to exercise private state, while names that
// the facade exports must be accessed through the root package.
func TestHandwrittenTestsUseRootExports(t *testing.T) {
	findings, err := shardReferencesToRootExports(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		t.Error(finding)
	}
}

func TestShardReferenceAuditFindsExportedNames(t *testing.T) {
	dir := t.TempDir()
	for name, source := range map[string]string{
		"facade.go": "package fixture; type RootType struct{}; var RootVariable int; const RootConstant=1; func RootFunction(){}",
		"fixture_test.go": `package fixture
import owner "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
var _=owner.RootType{}
var _=owner.RootVariable
var _=owner.RootConstant
var _=owner.RootFunction
var _=owner.BridgePrivateState
`,
		"generated_test.go": `// Code generated for the fixture. DO NOT EDIT.
package fixture
import owner "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
var _=owner.RootFunction
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := shardReferencesToRootExports(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("findings=%v, want four facade names and no private/generated reference", findings)
	}
	for _, name := range []string{"RootType", "RootVariable", "RootConstant", "RootFunction"} {
		found := false
		for _, finding := range findings {
			found = found || strings.Contains(finding, "."+name+" has a root export")
		}
		if !found {
			t.Errorf("missing finding for %s: %v", name, findings)
		}
	}
}

func shardReferencesToRootExports(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	set := token.NewFileSet()
	roots := map[string]bool{}
	tests := map[string]*ast.File{}
	for _, filename := range paths {
		file, err := parser.ParseFile(set, filename, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(filename, "_test.go") {
			if !ast.IsGenerated(file) {
				tests[filename] = file
			}
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() {
					roots[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							roots[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, name := range s.Names {
							if name.IsExported() {
								roots[name.Name] = true
							}
						}
					}
				}
			}
		}
	}
	var findings []string
	for filename, file := range tests {
		shards := map[string]string{}
		for _, imp := range file.Imports {
			value, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(value, "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s") {
				continue
			}
			name := path.Base(value)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			shards[name] = value
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			base, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, ok := shards[base.Name]; ok && roots[selector.Sel.Name] {
				findings = append(findings, fmt.Sprintf("%s:%d: %s.%s has a root export", filepath.Base(filename), set.Position(selector.Pos()).Line, base.Name, selector.Sel.Name))
			}
			return true
		})
	}
	sort.Strings(findings)
	return findings, nil
}
