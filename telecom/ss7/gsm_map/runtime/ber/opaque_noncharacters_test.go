// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/opaque_noncharacters_test.go; SHA-256 27eb860ac15ed445da16d1e054305746ae72ca48f1f6f2906220edce336ae093.
package ber

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// X.680 (02/2021) §§41.6,41.16; ISO/IEC 10646:2003 §§7 a),8
// apply equally to an open UTF8String and its typed form.
func TestOpaqueNoncharacterDiagnostics(t *testing.T) {
	const source = "Module.Value.opaque"
	for _, r := range noncharacterTestRunes() {
		text := string(r)
		primitive := append([]byte{12, byte(len(text))}, []byte(text)...)
		type form struct {
			name      string
			wire      []byte
			canonical bool
		}
		forms := []form{{"primitive", primitive, true}, {"nested", append([]byte{48, byte(len(primitive))}, primitive...), true}}
		for split := 0; split <= len(text); split++ {
			segments := append([]byte{4, byte(split)}, []byte(text[:split])...)
			segments = append(segments, 4, byte(len(text)-split))
			segments = append(segments, []byte(text[split:])...)
			forms = append(forms, form{fmt.Sprintf("constructed/%d", split), append([]byte{44, byte(len(segments))}, segments...), false})
			indefinite := append([]byte{44, 128}, segments...)
			forms = append(forms, form{fmt.Sprintf("indefinite/%d", split), append(indefinite, 0, 0), false})
		}
		for _, form := range forms {
			for _, fresh := range []bool{false, true} {
				for _, tolerant := range []bool{false, true} {
					t.Run(fmt.Sprintf("U+%X/%s/fresh=%t/tolerant=%t", r, form.name, fresh, tolerant), func(t *testing.T) {
						original := bytes.Clone(form.wire)
						var reports ViolationLog
						var options []EncodeOption
						if fresh {
							options = append(options, WithoutBERReplay())
						}
						if tolerant {
							options = append(options, WithTolerance(&reports))
						}
						options = EncodeSource(ChildEncodeOptions(options, "opaque"), source)
						err := CheckBEROpaqueElement(form.wire, options...)
						if !fresh && tolerant {
							if err != nil {
								t.Fatal(err)
							}
							records := reports.Snapshot()
							if len(records) != 1 {
								t.Fatalf("reports=%d want=1", len(records))
							}
							checkOpaqueNoncharacterRecord(t, records[0], source)
						} else {
							if !errors.Is(err, ErrInvalidValue) {
								t.Fatalf("expected refusal: %v", err)
							}
							var value *ValidationError
							if !fresh || form.canonical {
								if !errors.As(err, &value) {
									t.Fatalf("missing value diagnostic: %T %v", err, err)
								}
								checkOpaqueNoncharacterRecord(t, value.Violation, source)
							} else if errors.As(err, &value) {
								t.Fatalf("fresh constructed form lost DER framing cause: %v", err)
							}
							if len(reports.Snapshot()) != 0 {
								t.Fatal("failed encode published reports")
							}
						}
						if !bytes.Equal(form.wire, original) {
							t.Fatal("opaque check changed original bytes")
						}
					})
				}
			}
		}
	}
}

func checkOpaqueNoncharacterRecord(t *testing.T, record Violation, source string) {
	t.Helper()
	if record.Rule != (RuleRef{Document: "ISO/IEC 10646", Edition: "2003", Clause: "7 a), 8"}) || !strings.Contains(record.Constraint, "noncharacters") || record.Source != source || !strings.HasPrefix(record.Path, "opaque") || record.Offset != nil || record.OctetOffset != nil || len(record.ChildIndexes) != 0 {
		t.Fatalf("opaque repertoire diagnostic: %+v", record)
	}
}

func TestOpaqueNoncharacterRescanPreservesStructuralError(t *testing.T) {
	// A later malformed BOOLEAN must not become a repertoire finding.
	wire := []byte{48, 9, 12, 3, 0xef, 0xb7, 0x90, 1, 2, 0, 0}
	for _, options := range [][]EncodeOption{nil, {WithoutBERReplay()}} {
		err := CheckBEROpaqueElement(wire, options...)
		var value *ValidationError
		if err == nil || errors.As(err, &value) || !strings.Contains(err.Error(), "BOOLEAN") {
			t.Fatalf("structural cause lost: %T %v", err, err)
		}
	}
}

func TestOpaqueUTF8RescanKeepsUnrelatedRule(t *testing.T) {
	cause := fmt.Errorf("%w: unrelated IA5 contents", ErrInvalidValue)
	err := opaqueUTF8EncodeError([]byte{22, 2, 27, 'N'}, "Module.Value", nil, cause)
	if err != cause {
		t.Fatalf("unrelated rule became UTF8 finding: %T %v", err, err)
	}
}

func TestUTF8NoncharacterEncoderDiagnostic(t *testing.T) {
	for _, r := range noncharacterTestRunes() {
		for _, encode := range []func(string) ([]byte, error){EncodeUTF8String, func(value string) ([]byte, error) { return EncodeStringTagChecked(12, value) }, func(value string) ([]byte, error) { return EncodeStringValueTagChecked(12, value) }} {
			_, err := encode(string(r))
			var value *ValidationError
			if !errors.As(err, &value) || !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("U+%X: %T %v", r, err, err)
			}
			if value.Rule != (RuleRef{Document: "ISO/IEC 10646", Edition: "2003", Clause: "7 a), 8"}) || strings.Contains(value.ObservedValue, "invalid UTF-8") || !strings.Contains(value.Constraint, "noncharacters") {
				t.Fatalf("noncharacter misdiagnosed: %+v", value.Violation)
			}
		}
	}
}
