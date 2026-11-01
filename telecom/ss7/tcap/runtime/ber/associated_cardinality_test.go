// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/associated_cardinality_test.go; SHA-256 616a79ada515c8c3e9696ae4502630f3f541956c56a73715bb57b947f2e71ce4.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func associatedCardinalityTLV(identifier byte, contents []byte, indefinite bool) []byte {
	out := append([]byte{identifier}, EncodeLength(len(contents))...)
	if indefinite {
		out = []byte{identifier, 0x80}
	}
	out = append(out, contents...)
	if indefinite {
		out = append(out, 0, 0)
	}
	return out
}

func checkAssociatedCardinalityError(t *testing.T, err, want error) {
	t.Helper()
	if want == nil && err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []error{ErrTruncated, ErrInvalidTag, ErrUnexpectedElement, ErrInvalidLength, ErrIndefiniteLength, ErrExtraData, ErrInvalidValue, ErrUnsupported, ErrResourceLimit} {
		if errors.Is(err, sentinel) != (sentinel == want) {
			t.Fatalf("error=%v, errors.Is(%v), want %v", err, sentinel, want)
		}
	}
}

func TestAssociatedExplicitIssueVectors(t *testing.T) {
	for _, row := range []struct {
		wire      string
		scan, der error
	}{
		{"280706032a0304a000", ErrUnexpectedElement, ErrInvalidValue},
		{"280b06032a0304a00405000500", ErrUnexpectedElement, ErrInvalidValue},
		{"280906032a0304a0020500", nil, nil},
		{"2b04a0008200", ErrUnexpectedElement, ErrInvalidValue},
		{"2b07a0038101018200", nil, nil},
		{"3d04a0008200", ErrUnexpectedElement, ErrInvalidValue},
		{"3d07a0038101018200", nil, nil},
	} {
		t.Run(row.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.scan)
			checkAssociatedCardinalityError(t, ValidateDEREncodedElement(wire), row.der)
		})
	}
}

// A second incomplete or ill-formed TLV retains its X.690 sentinel.
func TestAssociatedExplicitMalformedContents(t *testing.T) {
	for _, row := range []struct {
		body []byte
		want error
	}{
		{[]byte{5}, ErrTruncated}, {[]byte{5, 0, 5}, ErrTruncated},
		{[]byte{5, 0, 0xff}, ErrTruncated}, {[]byte{5, 0, 0, 0}, ErrInvalidTag},
	} {
		wire := associatedCardinalityTLV(0x28, associatedCardinalityTLV(0xa0, row.body, false), false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.want)
	}
}

// The associated-type rule follows universal encodings inside foreign values.
// X.690 (02/2021) §§8.15, 8.17.1, 8.18.1, 8.24.1.
func TestAssociatedExplicitNestedOpenValues(t *testing.T) {
	for _, identifier := range []byte{0x28, 0x2b, 0x3d} {
		for count := 0; count <= 2; count++ {
			inner := []byte{5, 0}
			if identifier != 0x28 {
				inner = []byte{0x85, 0}
			}
			body := associatedCardinalityTLV(0xa0, bytes.Repeat(inner, count), false)
			if identifier != 0x28 {
				body = append(body, 0x82, 0)
			}
			value := associatedCardinalityTLV(identifier, body, false)
			invoke := associatedCardinalityTLV(0xa1, append([]byte{2, 1, 1, 2, 1, 0x2d}, value...), false)
			components := associatedCardinalityTLV(0x6c, invoke, false)
			wire := associatedCardinalityTLV(0x62, append([]byte{0x48, 1, 1}, components...), false)
			var want error
			if count != 1 {
				want = ErrUnexpectedElement
			}
			checkAssociatedCardinalityError(t, ValidateBERElement(wire, TrackTCAPForm(nil, "TCMessage")...), want)
		}
	}
	// A context [0] without an associated-type position has no inferred schema.
	checkAssociatedCardinalityError(t, ValidateBERElement([]byte{0x30, 2, 0xa0, 0}), nil)
	// Once EXTERNAL's encoding is past, a later [0] is a schema mismatch,
	// rather than another explicit encoding position; the typed decoder owns it.
	checkAssociatedCardinalityError(t, ValidateBERElement([]byte{0x28, 6, 0xa0, 2, 5, 0, 0xa0, 0}), nil)
}

// Standalone profile scans enforce cardinality; generated preflight retains
// the typed decoder's cardinality error and schema location.
// X.690 (02/2021) §§8.14.3, 8.18.1; X.680 (02/2021) §31.2.7 b).
func TestAssociatedExplicitProfileExternalRoot(t *testing.T) {
	for count := 0; count <= 2; count++ {
		wire := associatedCardinalityTLV(0x28, append([]byte{6, 3, 0x2a, 3, 4}, associatedCardinalityTLV(0xa0, bytes.Repeat([]byte{5, 0}, count), false)...), false)
		opts := TrackTCAPForm(nil, "External")
		var want error
		if count != 1 {
			want = ErrUnexpectedElement
		}
		checkAssociatedCardinalityError(t, ValidateBERElement(wire, opts...), want)
		_, _, err := DecodeExternal(wire, opts...)
		checkAssociatedCardinalityError(t, err, want)
	}
}

// X.690 (02/2021) §§8.17.1, 8.24.1 and X.680 (02/2021) §§36.5,
// 44.5 assign identification to the first child only. Later [0] tags
// are abstract-syntax mismatches, without an inferred explicit wrapper.
func TestAssociatedLaterContextZero(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, later := range [][]byte{{0xa0, 0}, {0xa0, 4, 5, 0, 5, 0}} {
			for _, indefinite := range []bool{false, true} {
				wire := associatedCardinalityTLV(outer, append([]byte{0xa0, 2, 0x85, 0}, later...), indefinite)
				checkAssociatedCardinalityError(t, ValidateBERElement(wire), nil)
			}
		}
	}
}

func TestCharacterStringDERDiagnostics(t *testing.T) {
	for _, row := range []struct{ body, message string }{
		{"81008200", "identification must be [0] EXPLICIT"},
		{"a004850085008200", "identification must contain one alternative"},
		{"a00280008200", "syntaxes must be constructed"},
		{"a002a1008200", "OID identification must be primitive"},
		{"a002a2008200", "context id must be primitive"},
		{"a00283008200", "context negotiation must be constructed"},
		{"a002a5008200", "fixed must be primitive"},
		{"a00286008200", "identification alternative 6"},
		{"a008a00681012a80012a8200", "identification pair has invalid components"},
		{"a00285008100", "requires one primitive [2] data-value"},
	} {
		t.Run(row.message, func(t *testing.T) {
			body, err := hex.DecodeString(row.body)
			if err != nil {
				t.Fatal(err)
			}
			for _, outer := range []byte{0x2b, 0x3d} {
				wire := associatedCardinalityTLV(outer, body, false)
				err := ValidateDEREncodedElement(wire)
				name := "EMBEDDED PDV"
				if outer == 0x3d {
					name = "CHARACTER STRING"
				}
				want := fmt.Sprintf("ber: invalid value encoding: DER universal tag %d: %s %s", outer&31, name, row.message)
				if err == nil || err.Error() != want {
					t.Fatalf("wire=%x: %v, want %s", wire, err, want)
				}
				checkAssociatedCardinalityError(t, err, ErrInvalidValue)
			}
		})
	}
}

func TestAssociatedProfileScanCardinalityLocation(t *testing.T) {
	for _, encoded := range []string{
		"62154804010203046b0d280b060700118605010101a000",
		"62374804010203046b2f282d060700118605010101a022600f80020780a109060704000001000103600f80020780a109060704000001000103",
		"62314804010203046b292827060700118605010101a01c601a80020780a109060704000001000103be09280706032a0304a000",
		"62354804010203046b2d282b060700118605010101a020601e80020780a109060704000001000103be0d280b06032a0304a00405000500",
		"651448010105006b0d280b060700118605010101a000",
	} {
		wire, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		plain := ValidateBERElement(wire)
		checkAssociatedCardinalityError(t, plain, ErrUnexpectedElement)
		var plainLocation *ElementError
		if !errors.As(plain, &plainLocation) {
			t.Fatalf("missing plain location: %v", plain)
		}
		for _, root := range []string{"", "TCMessage"} {
			for _, tolerant := range []bool{false, true} {
				var opts []DecodeOption
				if tolerant {
					opts = append(opts, WithTolerance(new(ViolationLog)))
				}
				err := ValidateBERElement(wire, TrackTCAPForm(opts, root)...)
				checkAssociatedCardinalityError(t, err, ErrUnexpectedElement)
				var location *ElementError
				if !errors.As(err, &location) || location.Offset() != plainLocation.Offset() || fmt.Sprint(location.ChildIndexes()) != fmt.Sprint(plainLocation.ChildIndexes()) {
					t.Fatalf("profile location=%v, plain=%v", err, plain)
				}
				if wire[location.Offset()] != 0xa0 {
					t.Fatalf("error at %d is not wrapper: %x", location.Offset(), wire)
				}
			}
		}
	}
}
