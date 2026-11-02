// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/associated_components_test.go; SHA-256 ce6b74f222034cf362da34f3b5936c54fb595927d0c8b9d758402c53327b7a78.
package ber

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// X.690 (02/2021) §§8.3.2, 8.9.2, 8.14.4, 8.17.1, 8.18.4 Table 2,
// 8.24.1; X.680 (02/2021) §§36.5, 44.5.
func TestAssociatedComponentsIssue(t *testing.T) {
	for _, row := range []struct {
		wire      string
		scan, der error
	}{
		{"2804a0020500", ErrInvalidValue, ErrInvalidValue},
		{"2807070164a0020500", ErrInvalidValue, ErrInvalidValue},
		{"2b0ba00581032a030481008200", ErrUnexpectedElement, ErrInvalidValue},
		{"2b06a00286008200", ErrUnexpectedElement, ErrInvalidValue},
		{"2b08a004820200018200", ErrInvalidValue, ErrInvalidValue},
		{"2b07a00581032a0304", ErrUnexpectedElement, ErrInvalidValue},
		{"2b0ba00581032a030482008200", ErrUnexpectedElement, ErrInvalidValue},
		{"3d0ba00581032a030481008200", ErrUnexpectedElement, ErrInvalidValue},
		{"3d06a00286008200", ErrUnexpectedElement, ErrInvalidValue},
		{"3d08a004820200018200", ErrInvalidValue, ErrInvalidValue},
		{"3d07a00581032a0304", ErrUnexpectedElement, ErrInvalidValue},
		{"3d0ba00581032a030482008200", ErrUnexpectedElement, ErrInvalidValue},
		{"280906032a0304a0020500", nil, nil},
		{"2b09a00581032a03048200", nil, nil},
		{"3d09a00581032a03048200", nil, nil},
		{"3d07a0028500820141", nil, nil},
	} {
		t.Run(row.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			for _, indef := range []bool{false, true} {
				data := associatedCardinalityTLV(wire[0], wire[2:], indef)
				for _, opts := range [][]DecodeOption{nil, {WithTolerance(new(ViolationLog))}} {
					checkAssociatedCardinalityError(t, ValidateBERElement(data, opts...), row.scan)
					if wire[0] == 0x28 {
						_, _, decodeErr := DecodeExternal(data, opts...)
						checkAssociatedCardinalityError(t, decodeErr, row.scan)
					}
				}
				der := row.der
				if indef {
					der = ErrIndefiniteLength
				}
				checkAssociatedCardinalityError(t, ValidateDEREncodedElement(data), der)
				if wire[0] == 0x28 {
					_, _, err := DecodeExternal(data)
					checkAssociatedCardinalityError(t, err, row.scan)
				}
				if row.scan == nil {
					associatedComponentsReplay(t, data)
				}
			}
		})
	}
}

func associatedComponentsReplay(t *testing.T, wire []byte) {
	t.Helper()
	identifier, contents, used, err := DecodeRawValue(wire)
	if err != nil || used != len(wire) {
		t.Fatalf("raw decode: %d %v", used, err)
	}
	var replay []byte
	if wire[1] == 0x80 {
		replay, err = EncodeConstructedIndefinite(identifier, contents)
	} else {
		replay, err = EncodeTLV(identifier, contents)
	}
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay mismatch: %v", err)
	}
}

func TestAssociatedComponentsAlternatives(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, row := range []struct {
			alt  string
			want error
		}{
			{"a00680012a81012a", nil}, {"81012a", nil}, {"820101", nil}, {"a30680010181012a", nil}, {"84012a", nil}, {"8500", nil},
			{"a000", ErrUnexpectedElement}, {"8100", ErrInvalidValue}, {"82020001", ErrInvalidValue}, {"a306800100810180", ErrInvalidValue}, {"840180", ErrInvalidValue}, {"850100", ErrInvalidValue},
			{"a00380012a", ErrUnexpectedElement}, {"a00980012a81012a81012a", ErrUnexpectedElement}, {"a30681010180012a", ErrUnexpectedElement},
			{"a10606012a06012a", ErrInvalidTag}, {"a200", ErrInvalidTag}, {"8000", ErrInvalidTag}, {"8300", ErrInvalidTag}, {"a500", ErrInvalidTag},
			{"06012a", ErrUnexpectedElement}, {"8600", ErrUnexpectedElement},
		} {
			alt, err := hex.DecodeString(row.alt)
			if err != nil {
				t.Fatal(err)
			}
			for count := 1; count <= 2; count++ {
				for _, indef := range []bool{false, true} {
					t.Run(fmt.Sprintf("%x/%s/%d/%t", outer, row.alt, count, indef), func(t *testing.T) {
						body := associatedCardinalityTLV(0xa0, bytes.Repeat(alt, count), indef)
						body = append(body, 0x82, 0)
						wire := associatedCardinalityTLV(outer, body, indef)
						want := row.want
						if count == 2 && want == nil {
							want = ErrUnexpectedElement
						}
						checkAssociatedCardinalityError(t, ValidateBERElement(wire), want)
						derWant := error(nil)
						if indef {
							derWant = ErrIndefiniteLength
						} else if want != nil {
							derWant = ErrInvalidValue
						}
						checkAssociatedCardinalityError(t, ValidateDEREncodedElement(wire), derWant)

						if want == nil {
							associatedComponentsReplay(t, wire)
						}
					})
				}
			}
		}
	}
}

func TestAssociatedComponentsConstructedData(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, indef := range []bool{false, true} {
			value := associatedCardinalityTLV(0xa2, []byte{4, 1, 0x41, 0x24, 3, 4, 1, 0x42}, indef)
			wire := associatedCardinalityTLV(outer, append([]byte{0xa0, 2, 0x85, 0}, value...), indef)
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), nil)
			der := ErrInvalidValue
			if indef {
				der = ErrIndefiniteLength
			}
			checkAssociatedCardinalityError(t, ValidateDEREncodedElement(wire), der)
			associatedComponentsReplay(t, wire)
			bad := associatedCardinalityTLV(outer, append([]byte{0xa0, 2, 0x85, 0}, []byte{0xa2, 2, 5, 0}...), indef)
			checkAssociatedCardinalityError(t, ValidateBERElement(bad), ErrInvalidTag)
		}
	}
}

func TestAssociatedComponentsExternalChoices(t *testing.T) {
	for _, reference := range [][]byte{{6, 1, 0x2a}, {2, 1, 1}, {6, 1, 0x2a, 2, 1, 1}} {
		for _, desc := range [][]byte{nil, {7, 1, 0x64}} {
			for _, choice := range [][]byte{{0xa0, 2, 5, 0}, {0x81, 1, 0x41}, {0x82, 2, 0, 0x41}, {0xa1, 3, 4, 1, 0x41}, {0xa2, 4, 3, 2, 0, 0x41}} {
				for _, indef := range []bool{false, true} {
					body := append(append(append([]byte{}, reference...), desc...), choice...)
					wire := associatedCardinalityTLV(0x28, body, indef)
					checkAssociatedCardinalityError(t, ValidateBERElement(wire), nil)
					var derWant error
					if indef {
						derWant = ErrIndefiniteLength
					} else if choice[0] == 0xa1 || choice[0] == 0xa2 {
						derWant = ErrInvalidValue
					}
					checkAssociatedCardinalityError(t, ValidateDEREncodedElement(wire), derWant)
					_, _, err := DecodeExternal(wire)
					checkAssociatedCardinalityError(t, err, nil)
					associatedComponentsReplay(t, wire)
				}
			}
		}
	}
	// X.681 (02/2021) Annex C §§C.4, C.6–C.7: INSTANCE OF has an OID
	// and an explicit [0] value;
	// all value types use the same valid EXTERNAL subset.
	for _, value := range [][]byte{{5, 0}, {2, 1, 1}, {0x30, 0}} {
		wire := associatedCardinalityTLV(0x28, append([]byte{6, 1, 0x2a}, associatedCardinalityTLV(0xa0, value, false)...), false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), nil)
	}
}

// X.690 §§8.9.2, 8.17.1, 8.18.1, 8.24.1: ordering and completeness
// are schema rules; an incomplete or malformed tail retains its BER error.
func TestAssociatedComponentsOrderAndMalformedTail(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, row := range []struct {
			body []byte
			want error
		}{
			{nil, ErrUnexpectedElement}, {[]byte{0x82, 0, 0xa0, 2, 0x85, 0}, ErrUnexpectedElement},
			{[]byte{0xa0, 2, 0x85, 0, 0x81, 0, 0x82, 0}, ErrUnexpectedElement},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 5}, ErrTruncated},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 0, 0}, ErrInvalidTag},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 0x22, 0}, ErrInvalidTag},
			{[]byte{0xa0, 2, 0x85, 0, 0x82, 0, 5, 1}, ErrTruncated},
		} {
			wire := associatedCardinalityTLV(outer, row.body, false)
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.want)
		}
	}
	for _, row := range []struct {
		body []byte
		want error
	}{
		{[]byte{6, 1, 0x2a}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0x83, 0}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0xa0, 2, 5, 0, 5, 0}, ErrUnexpectedElement},
		{[]byte{6, 1, 0x2a, 0x82, 0}, ErrInvalidValue},
		{[]byte{6, 1, 0x2a, 0x82, 1, 8}, ErrInvalidValue},
		{[]byte{6, 1, 0x2a, 0xa0, 2, 5, 0, 5}, ErrTruncated},
	} {
		wire := associatedCardinalityTLV(0x28, row.body, false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), row.want)
	}
}

// X.690 (02/2021) §8.14.3: an extra identification value is outside
// the abstract syntax; its context-specific contents have no inferred type.
func TestAssociatedComponentsExtraAlternativeKeepsUnknownContents(t *testing.T) {
	for _, outer := range []byte{0x2b, 0x3d} {
		for _, second := range [][]byte{{0x80, 0}, {0x81, 1, 0x80}, {0x82, 2, 0, 1}, {0x83, 0}, {0x84, 1, 0x80}, {0xa5, 0}, {0x85, 1, 0}} {
			checkAssociatedCardinalityError(t, ValidateBERElement(second), nil)
			wrapper := associatedCardinalityTLV(0xa0, append([]byte{0x85, 0}, second...), false)
			wire := associatedCardinalityTLV(outer, append(wrapper, 0x82, 0), false)
			checkAssociatedCardinalityError(t, ValidateBERElement(wire), ErrUnexpectedElement)
		}
		// A universal INTEGER still identifies its own base type in an extra
		// value and retains the same contents failure as a standalone INTEGER.
		second := []byte{2, 2, 0, 1}
		checkAssociatedCardinalityError(t, ValidateBERElement(second), ErrInvalidValue)
		wrapper := associatedCardinalityTLV(0xa0, append([]byte{0x85, 0}, second...), false)
		wire := associatedCardinalityTLV(outer, append(wrapper, 0x82, 0), false)
		checkAssociatedCardinalityError(t, ValidateBERElement(wire), ErrInvalidValue)
	}
}
