// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/real_ber_contents_test.go; SHA-256 5ce0b4119258274a3e2be70962413d910824b3000940e8125668d2e34d5dcee1.
package ber

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// X.690 (02/2021) §8.5 defines BER contents; §11.3 adds DER normalization.
func TestRealBERContents(t *testing.T) {
	rows := []struct {
		name, contents string
		ber, der       error
	}{
		{"zero", "", nil, nil},
		{"binary base two", "800001", nil, nil},
		{"binary base eight", "900001", nil, ErrInvalidValue},
		{"binary base sixteen", "a00001", nil, ErrInvalidValue},
		{"reserved binary base", "b00001", ErrInvalidValue, ErrInvalidValue},
		{"scale one", "840001", nil, ErrInvalidValue},
		{"scale two", "880001", nil, ErrInvalidValue},
		{"scale three", "8c0001", nil, ErrInvalidValue},
		{"even mantissa", "800002", nil, ErrInvalidValue},
		{"negative mantissa", "c00001", nil, nil},
		{"two exponent octets", "81008001", nil, nil},
		{"three exponent octets", "8200800001", nil, nil},
		{"nonminimal short exponent", "81000001", nil, ErrInvalidValue},
		{"long exponent", "83040080000001", nil, nil},
		{"nonminimal long length", "83010001", nil, ErrInvalidValue},
		{"missing exponent", "80", ErrTruncated, ErrTruncated},
		{"truncated two octet exponent", "8100", ErrTruncated, ErrTruncated},
		{"truncated three octet exponent", "820000", ErrTruncated, ErrTruncated},
		{"missing exponent length", "83", ErrTruncated, ErrTruncated},
		{"zero exponent length", "8300", ErrInvalidValue, ErrInvalidValue},
		{"truncated long exponent", "83040080", ErrTruncated, ErrTruncated},
		{"long leading zero", "8302000001", ErrInvalidValue, ErrInvalidValue},
		{"long leading ones", "8302ffff01", ErrInvalidValue, ErrInvalidValue},
		{"missing mantissa", "8000", ErrTruncated, ErrTruncated},
		{"zero mantissa", "800000", ErrInvalidValue, ErrInvalidValue},
		{"NR1", "0131", nil, ErrInvalidValue},
		{"NR2", "02312e35", nil, ErrInvalidValue},
		{"NR3 canonical", "03312e452b30", nil, nil},
		{"NR1 spaces and sign", "0120202b303031", nil, ErrInvalidValue},
		{"NR2 comma and empty integer", "022c35", nil, ErrInvalidValue},
		{"NR2 empty fraction", "02312e", nil, ErrInvalidValue},
		{"NR3 lowercase and signed exponent", "032d312c32652d32", nil, ErrInvalidValue},
		{"NR3 zero exponent without plus", "03312e4530", ErrInvalidValue, ErrInvalidValue},
		{"decimal zero", "0130", ErrInvalidValue, ErrInvalidValue},
		{"NR3 noncanonical", "03312e30452b30", nil, ErrInvalidValue},
		{"empty NR1", "01", ErrInvalidValue, ErrInvalidValue},
		{"invalid NR2", "0231", ErrInvalidValue, ErrInvalidValue},
		{"invalid NR3", "03312e45", ErrInvalidValue, ErrInvalidValue},
		{"PLUS-INFINITY", "40", nil, nil},
		{"MINUS-INFINITY", "41", nil, nil},
		{"NOT-A-NUMBER", "42", nil, nil},
		{"minus zero", "43", nil, nil},
		{"special extra octet", "4000", ErrInvalidValue, ErrInvalidValue},
	}
	for form := 0; form < 64; form++ {
		if form >= 1 && form <= 3 {
			continue
		}
		rows = append(rows, struct {
			name, contents string
			ber, der       error
		}{fmt.Sprintf("reserved decimal %02x", form), fmt.Sprintf("%02x", form), ErrInvalidValue, ErrInvalidValue})
	}
	for form := 0x44; form < 0x80; form++ {
		rows = append(rows, struct {
			name, contents string
			ber, der       error
		}{fmt.Sprintf("reserved special %02x", form), fmt.Sprintf("%02x", form), ErrInvalidValue, ErrInvalidValue})
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			contents, err := hex.DecodeString(row.contents)
			if err != nil {
				t.Fatal(err)
			}
			wire := append([]byte{9, byte(len(contents))}, contents...)
			assertElementSentinels(t, ValidateBERElement(wire), row.ber)
			der := ValidateDERElement(wire)
			assertElementSentinels(t, der, row.der)
			if row.name == "reserved decimal 00" && (der == nil || !strings.Contains(der.Error(), "reserved REAL decimal form")) {
				t.Fatalf("reserved BER form misreported: %v", der)
			}
			// The same malformed REAL must survive rejection as its X.690 sentinel.
			// A valid REAL is well-formed but not an INTEGER (X.690 §8.3.1).
			want := row.ber
			if want == nil {
				want = ErrUnexpectedElement
			}
			_, _, err = DecodeInteger(wire)
			assertElementSentinels(t, err, want)
		})
	}
}

// X.690 (02/2021) §8.5: validation scans decimal contents without converting the value.
func TestBERDecimalRealValidationCost(t *testing.T) {
	for _, text := range []string{strings.Repeat("7", 1_000_000) + ".E+0", "1.E+" + strings.Repeat("7", 1_000_000)} {
		contents := append([]byte{3}, text...)
		wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, contents)
		if err != nil {
			t.Fatal(err)
		}
		allocations := testing.AllocsPerRun(1, func() {
			if err := ValidateBERElement(wire); err != nil {
				t.Fatal(err)
			}
		})
		if allocations > 8 {
			t.Fatalf("decimal validation allocated %.0f objects; want <= 8", allocations)
		}
	}
}

func TestBERRealContentsValidationAllocations(t *testing.T) {
	for _, contents := range [][]byte{{}, {0x40}, {0x80, 0, 1}, {1, '1'}, {2, '1', '.', '2'}, {3, '1', '.', 'E', '+', '0'}} {
		if got := testing.AllocsPerRun(10, func() {
			if err := validateBERUniversalContents(tag.TagReal, contents); err != nil {
				t.Fatal(err)
			}
		}); got != 0 {
			t.Errorf("contents %x: got %.0f allocations, want 0", contents, got)
		}
	}
}
