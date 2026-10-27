// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/der_set_order_test.go; SHA-256 a79995f7e606ca377c56d3d8ba4df6b7a19fed6ad259d7438f58908be310ea64.
package ber

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"strings"
	"testing"
)

// X.690 (02/2021) §§10.3, 11.6; X.680 (02/2021) §§8.6, 27.3.
// A schema-free scan must retain both interpretations of UNIVERSAL 17.
func TestDERUniversalSetOrder(t *testing.T) {
	tests := []struct {
		name, wire string
		valid      bool
		offset     int
	}{
		{"descending equal tags", "3106020102020101", false, 0},
		{"descending distinct tags", "31060201010101ff", false, 0},
		{"sorted SET OF", "3106020101020102", true, 0},
		{"sorted SET", "31060101ff020101", true, 0},
		{"SET order only", "310430001200", true, 0},
		{"equal SET OF components", "3106020101020101", true, 0},
		{"empty", "3100", true, 0},
		{"singleton", "3103020101", true, 0},
		{"all classes", "3108050040008000c000", true, 0},
		{"class order before tag number", "3106a0008100c000", true, 0},
		{"descending classes", "310480004000", false, 0},
		{"high tags SET order only", "31099fff7f009f81800000", true, 0},
		{"high tags SET OF order only", "31099f818000009fff7f00", true, 0},
		{"neither global order", "310d9fff7f009f818000009f810000", false, 0},
		{"primitive then constructed same tag", "31048300a300", true, 0},
		{"constructed then primitive same tag", "3104a3008300", false, 0},
		{"different lengths SET OF", "310780010080020000", true, 0},
		{"descending lengths SET OF", "310780020000800100", false, 0},
		{"nested", "300a05003106020102020101", false, 4},
		{"nested under application", "600a05003106020102020101", false, 4},
		{"nested valid", "30083106020101020102", true, 0},
		{"implicit application boundary", "6006020102020101", true, 0},
		{"implicit context boundary", "a006020102020101", true, 0},
		{"implicit private boundary", "e006020102020101", true, 0},
		{"implicit application tag 17 boundary", "7106020102020101", true, 0},
		{"implicit context tag 17 boundary", "b106020102020101", true, 0},
		{"implicit private tag 17 boundary", "f106020102020101", true, 0},
	}
	validators := map[string]func([]byte) error{
		"encoded": ValidateDEREncodedElement,
		"element": ValidateDERElement,
		"TLV": func(b []byte) error {
			n, err := ValidateDERTLV(b)
			if err == nil && n != len(b) {
				return ErrExtraData
			}
			return err
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			for name, validate := range validators {
				t.Run(name, func(t *testing.T) {
					err := validate(wire)
					if tc.valid {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					if !errors.Is(err, ErrInvalidValue) {
						t.Fatalf("accepted invalid SET or wrong error: %v", err)
					}
					if !strings.Contains(err.Error(), "neither SET nor SET OF") || !strings.Contains(err.Error(), fmt.Sprintf("byte %d", tc.offset)) {
						t.Fatalf("missing SET order/location: %v", err)
					}
				})
			}
		})
	}
}

func TestDERUniversalSetTLVBoundary(t *testing.T) {
	wire := []byte{0x31, 0, 0x31, 6, 2, 1, 2, 2, 1, 1}
	n, err := ValidateDERTLV(wire)
	if err != nil || n != 2 {
		t.Fatalf("first TLV = %d, %v", n, err)
	}
	if err := ValidateDERElement(wire); !errors.Is(err, ErrExtraData) {
		t.Fatalf("extra element: %v", err)
	}
	for _, wire := range [][]byte{{0x31, 2, 1, 0}, {0x31, 2, 0x80, 1}} {
		if err := ValidateDERElement(wire); err == nil {
			t.Fatalf("invalid child accepted: %x", wire)
		}
	}
}

func TestDERUniversalSetGrowth(t *testing.T) {
	// Adjacent comparisons need constant workspace, and must not search all
	// earlier tags. The 64x input growth distinguishes a quadratic tag search.
	for _, setOf := range []bool{false, true} {
		t.Run(fmt.Sprint(setOf), func(t *testing.T) {
			counts := []int{64, 512, 4096}
			operations := make([]func(), len(counts))
			allocated := make([]uint64, len(counts))
			allocations := make([]uint64, len(counts))
			for index, count := range counts {
				var contents []byte
				for i := 0; i < count; i++ {
					number := 16384 + i
					if setOf {
						number = 16384
					}
					child, err := EncodeTLV(tag.Tag{Class: tag.ClassContextSpecific, Number: number}, []byte{0})
					if err != nil {
						t.Fatal(err)
					}
					contents = append(contents, child...)
				}
				wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSet, Constructed: true}, contents)
				if err != nil {
					t.Fatal(err)
				}
				operations[index] = func() {
					if err := ValidateDEREncodedElement(wire); err != nil {
						t.Fatal(err)
					}
				}
				allocated[index], allocations[index] = allocationCost(t, 5, operations[index])
			}
			times := growthTimes(t, operations...)
			for index, count := range counts {
				t.Logf("components=%d ns/op=%d B/op=%d allocs/op=%d", count, times[index], allocated[index], allocations[index])
				if index == 0 {
					continue
				}
				scale := int64(count / 64)
				if times[index] > times[0]*scale*4 {
					t.Fatalf("superlinear validation: %d components: %d ns; 64: %d ns", count, times[index], times[0])
				}
				if allocated[index] > allocated[0]*uint64(scale)+1024 || allocations[index] > allocations[0]*uint64(scale)+8 {
					t.Fatalf("superlinear workspace: %d components: %d bytes, %d allocations", count, allocated[index], allocations[index])
				}
			}
		})
	}
}

func TestDERSetOfPaddedComparison(t *testing.T) {
	// X.690 (02/2021) §11.6 pads only for comparison. A complete DER TLV
	// cannot strictly prefix another complete TLV, so exercise that branch on
	// octet strings directly, separately from the complete-component vectors.
	for _, tc := range []struct {
		left, right []byte
		want        int
	}{
		{[]byte{0x80, 1}, []byte{0x80, 1, 0}, 0},
		{[]byte{0x80, 1, 0, 0}, []byte{0x80, 1}, 0},
		{[]byte{0x80, 1}, []byte{0x80, 1, 0, 1}, -1},
		{[]byte{0x80, 1, 0, 1}, []byte{0x80, 1}, 1},
		{[]byte{0x80, 1, 0xff}, []byte{0x80, 2}, -1},
		{[]byte{0x80, 2}, []byte{0x80, 1, 0xff}, 1},
		{nil, []byte{0, 0}, 0}, {nil, []byte{0, 1}, -1},
		{[]byte{0, 1}, nil, 1}, {nil, nil, 0},
	} {
		if got := compareDEROctetStrings(tc.left, tc.right); got != tc.want {
			t.Errorf("compare(%x,%x)=%d; want %d", tc.left, tc.right, got, tc.want)
		}
	}
}
