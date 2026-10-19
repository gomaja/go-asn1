// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/entry_options_test.go; SHA-256 f646c7ac8ffe5522288411df2d4ec4b40cc6cd67afe0907607056651d8c6414f.
package ber

import (
	"embed"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// Embed source so completeness is checked even when the test binary runs
// elsewhere, including Windows. Only exported, option-consuming functions
// returning an error are codec entry points; option builders and markers are
// checked by their eventual codec consumer.
//
//go:embed *.go
var optionEntrySources embed.FS

var berOptionEntries = map[string]any{
	"DecodeTLV":                          DecodeTLV,
	"DecodeSequenceChildren":             DecodeSequenceChildren,
	"DecodeBoolean":                      DecodeBoolean,
	"DecodeInteger":                      DecodeInteger,
	"DecodeUint64":                       DecodeUint64,
	"DecodeBigInt":                       DecodeBigInt,
	"DecodeBitString":                    DecodeBitString,
	"DecodeOctetString":                  DecodeOctetString,
	"DecodeNull":                         DecodeNull,
	"DecodeObjectIdentifier":             DecodeObjectIdentifier,
	"DecodeRelativeObjectIdentifier":     DecodeRelativeObjectIdentifier,
	"DecodeEnumerated":                   DecodeEnumerated,
	"DecodeReal":                         DecodeReal,
	"DecodeString":                       DecodeString,
	"DecodeUTCTime":                      DecodeUTCTime,
	"DecodeGeneralizedTime":              DecodeGeneralizedTime,
	"DecodeRawValue":                     DecodeRawValue,
	"DecodeImplicitBitStringValue":       DecodeImplicitBitStringValue,
	"DecodeImplicitOctetStringValue":     DecodeImplicitOctetStringValue,
	"DecodeImplicitStringValue":          DecodeImplicitStringValue,
	"DecodeImplicitUTCTimeValue":         DecodeImplicitUTCTimeValue,
	"DecodeImplicitGeneralizedTimeValue": DecodeImplicitGeneralizedTimeValue,
	"DecodeRealValue":                    DecodeRealValue,
	"SkipTLV":                            SkipTLV,
	"DecodeSequenceContent":              DecodeSequenceContent,
	"DecodeConstructedContent":           DecodeConstructedContent,
	"DecodeExternal":                     DecodeExternal,
	"DecodeExternalValue":                DecodeExternalValue,
	"DecodeTaggedCollectionElement":      DecodeTaggedCollectionElement,
	"DecodeDualTaggedChoiceElement":      DecodeDualTaggedChoiceElement,
	"ValidateBERElement":                 ValidateBERElement,
	"DiagnosePreflight":                  DiagnosePreflight,
	"ValidateDecodeOptions":              ValidateDecodeOptions,
	"CheckDecodedLength":                 CheckDecodedLength,
	"CheckDecodedValue":                  CheckDecodedValue,
	"CheckDecodedCollectionLength":       CheckDecodedCollectionLength,
	"MarkBERSetOrder":                    MarkBERSetOrder,
	"EncodeExternal":                     EncodeExternal,
	"EncodeBERReal":                      EncodeBERReal,
	"ValidateEncodeOptions":              ValidateEncodeOptions,
	"CheckEncodedLength":                 CheckEncodedLength,
	"CheckEncodedValue":                  CheckEncodedValue,
	"CheckEncodedCollectionLength":       CheckEncodedCollectionLength,
	"CheckBEROpaqueElement":              CheckBEROpaqueElement,
	"CheckBEROpaqueReplay":               CheckBEROpaqueReplay,
}

// These generated-code orchestration helpers consume options after the public
// codec entry has validated them. They are not independent codec entries.
var berOptionHelpers = map[string]bool{
	"LocateDecodeError":          true,
	"OwnGeneratedBERInput":       true,
	"PrepareGeneratedBERInput":   true,
	"CompleteGeneratedBERDecode": true,
	"PrepareBERReplay":           true,
}

func TestBEROptionEntryRegistryComplete(t *testing.T) {
	files, err := optionEntrySources.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, file := range files {
		if strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		source, readErr := optionEntrySources.ReadFile(file.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), file.Name(), source, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, declaration := range parsed.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			hasError, hasOptions := false, false
			for _, result := range fn.Type.Results.List {
				if ident, ok := result.Type.(*ast.Ident); ok && ident.Name == "error" {
					hasError = true
				}
			}
			for _, parameter := range fn.Type.Params.List {
				var element ast.Expr
				switch typ := parameter.Type.(type) {
				case *ast.ArrayType:
					element = typ.Elt
				case *ast.Ellipsis:
					element = typ.Elt
				}
				if ident, ok := element.(*ast.Ident); ok && (ident.Name == "DecodeOption" || ident.Name == "EncodeOption") {
					hasOptions = true
				}
			}
			if !hasError || !hasOptions {
				continue
			}
			seen[fn.Name.Name] = true
			if berOptionHelpers[fn.Name.Name] {
				continue
			}
			if _, ok := berOptionEntries[fn.Name.Name]; !ok {
				t.Errorf("exported codec %s is missing from the option audit", fn.Name.Name)
			}
		}
	}
	for name := range berOptionEntries {
		if !seen[name] {
			t.Errorf("option registry contains stale entry %s", name)
		}
	}
	for name := range berOptionHelpers {
		if !seen[name] {
			t.Errorf("option helper registry contains stale entry %s", name)
		}
	}
	t.Logf("audited %d exported option-consuming codecs and validators", len(seen))
}

func TestBEROptionEntriesRejectInvalidOptions(t *testing.T) {
	var reports ViolationLog
	tolerance := WithTolerance(&reports)
	decodes := [][]DecodeOption{
		{nil},
		{WithDecodeLimits(DecodeLimits{MaxDepth: -1})},
		{WithDiagnosticLimits(DiagnosticLimits{MaxRecords: -1})},
		{WithDiagnosticLimits(DiagnosticLimits{MaxObservedBytes: -1})},
		{WithDecodeLimits(DecodeLimits{MaxElements: -1})},
		{WithDecodeLimits(DecodeLimits{MaxWork: -1})},
		{WithDecodeLimits(DecodeLimits{MaxRealDecimalDigits: -1})},
		{WithTolerance(nil)},
		{tolerance, tolerance},
		ChildDecodeOptions(nil, ""),
		ChildDecodeOptions(nil, "bad.path"),
	}
	encodes := [][]EncodeOption{
		{nil}, {WithTolerance(nil)}, {tolerance, tolerance},
		ChildEncodeOptions(nil, ""), ChildEncodeOptions(nil, "bad.path"),
	}
	for name, entry := range berOptionEntries {
		fn := reflect.ValueOf(entry)
		typ := fn.Type()
		optionIndex := -1
		for index := range typ.NumIn() {
			if typ.In(index) == reflect.TypeFor[[]DecodeOption]() || typ.In(index) == reflect.TypeFor[[]EncodeOption]() {
				optionIndex = index
				break
			}
		}
		if optionIndex < 0 {
			t.Fatalf("%s has no options parameter", name)
		}
		isDecode := typ.In(optionIndex) == reflect.TypeFor[[]DecodeOption]()
		count := len(encodes)
		if isDecode {
			count = len(decodes)
		}
		for optionIndexInTable := range count {
			for inputIndex, input := range [][]byte{nil, {0x1f}, {5, 0}} {
				for _, constructed := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/options%d/input%d/constructed%t", name, optionIndexInTable, inputIndex, constructed), func(t *testing.T) {
						arguments := make([]reflect.Value, typ.NumIn())
						for index := range arguments {
							arguments[index] = reflect.Zero(typ.In(index))
							if typ.In(index) == reflect.TypeFor[[]byte]() {
								arguments[index] = reflect.ValueOf(input)
							}
							if typ.In(index).Kind() == reflect.Bool {
								arguments[index] = reflect.ValueOf(constructed)
							}
						}
						var want error
						if isDecode {
							arguments[optionIndex] = reflect.ValueOf(decodes[optionIndexInTable])
							want = ValidateDecodeOptions(decodes[optionIndexInTable]...)
						} else {
							arguments[optionIndex] = reflect.ValueOf(encodes[optionIndexInTable])
							want = ValidateEncodeOptions(encodes[optionIndexInTable]...)
						}
						if want == nil {
							t.Fatal("invalid option fixture accepted")
						}
						var results []reflect.Value
						if typ.IsVariadic() {
							results = fn.CallSlice(arguments)
						} else {
							results = fn.Call(arguments)
						}
						got, _ := results[len(results)-1].Interface().(error)
						if got == nil || got.Error() != want.Error() || !errors.Is(got, ErrInvalidValue) {
							t.Fatalf("option precedence: got %v, want %v", got, want)
						}
					})
				}
			}
		}
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("rejected options published reports")
	}
}
