package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

// oracleOctetFragments assembles X.690 (02/2021) §8.7.3.2 segments
// independently of DecodeOctetString's recursive value decoder.
func oracleOctetFragments(contents []byte, depth int) ([]byte, bool) {
	var result []byte
	for offset := 0; offset < len(contents); {
		if depth > DefaultDecodeLimits().MaxDepth {
			return nil, false
		}
		segment, consumed, value, err := DecodeTLV(contents[offset:])
		if err != nil || consumed <= 0 || consumed > len(contents)-offset ||
			segment.Class != tag.ClassUniversal || segment.Number != tag.TagOctetString {
			return nil, false
		}
		if segment.Constructed {
			fragment, ok := oracleOctetFragments(value, depth+1)
			if !ok {
				return nil, false
			}
			result = append(result, fragment...)
		} else {
			result = append(result, value...)
		}
		offset += consumed
	}
	return result, true
}

func FuzzBERConstraintTolerance(f *testing.F) {
	f.Add([]byte{0x04, 0x01, 0xaa})
	f.Add([]byte{0x04, 0x02, 0xaa, 0xbb})
	f.Add([]byte{0x04, 0x81, 0x01, 0xaa})
	f.Add([]byte{0x24, 0x04, 0x04, 0x02, 0xaa, 0xbb})
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, tolerant := range []bool{false, true} {
			var reports ViolationLog
			var options []DecodeOption
			if tolerant {
				options = append(options, WithConstraintTolerance(&reports))
			}
			value, _, err := DecodeOctetString(wire, options...)
			if err != nil || len(value) == 2 {
				continue
			}
			err = CheckDecodedLength(options, "field", "SIZE (2)", len(value))
			if tolerant && (err != nil || len(reports.Snapshot()) != 1) {
				t.Fatalf("tolerant length check: error=%v reports=%+v", err, reports.Snapshot())
			}
			if !tolerant && err == nil {
				t.Fatal("strict length check admitted an out-of-range value")
			}
		}
	})
}

func FuzzBERImplicitConstructedOctetString(f *testing.F) {
	f.Add([]byte{0x04, 0x01, 0x00, 0x04, 0x02, 0x01, 0x21})
	f.Add([]byte{0x24, 0x80, 0x04, 0x01, 0x00, 0x04, 0x00, 0x04, 0x02, 0x01, 0x21, 0x00, 0x00})
	f.Add([]byte{0x04, 0x00})
	f.Add(deepImplicitOctetFragments(DefaultDecodeLimits().MaxDepth))
	f.Add(deepImplicitEmptyOctetFragments(DefaultDecodeLimits().MaxDepth))
	f.Fuzz(func(t *testing.T, contents []byte) {
		if len(contents) > 1024 {
			return
		}
		for _, tolerant := range []bool{false, true} {
			var reports ViolationLog
			var options []DecodeOption
			if tolerant {
				options = append(options, WithConstraintTolerance(&reports))
			}
			got, err := DecodeImplicitOctetStringValue(true, contents, options...)
			want, oracleOK := oracleOctetFragments(contents, 1)
			if (err == nil) != oracleOK || err == nil && !bytes.Equal(got, want) {
				t.Fatalf("implicit=%x/%v oracle=%x/%t", got, err, want, oracleOK)
			}
			if err == nil {
				canonical, encodeErr := EncodeOctetString(got)
				if encodeErr != nil || ValidateDEREncodedElement(canonical) != nil {
					t.Fatalf("canonical DER %x: %v", canonical, encodeErr)
				}
				decoded, consumed, decodeErr := DecodeOctetString(canonical)
				if decodeErr != nil || consumed != len(canonical) || !bytes.Equal(decoded, got) {
					t.Fatalf("canonical decode %x/%d: %v", decoded, consumed, decodeErr)
				}
			}
		}
	})
}

func deepImplicitOctetFragments(depth int) []byte {
	segment := []byte{0x04, 0x00}
	for range depth {
		segment = append([]byte{0x24}, append(EncodeLength(len(segment)), segment...)...)
	}
	return segment
}

func deepImplicitEmptyOctetFragments(depth int) []byte {
	segment := []byte{0x24, 0x00}
	for range depth - 1 {
		segment = append([]byte{0x24}, append(EncodeLength(len(segment)), segment...)...)
	}
	return segment
}

func TestImplicitOctetOracleIncludesOuterConstructedValue(t *testing.T) {
	contents := deepImplicitOctetFragments(DefaultDecodeLimits().MaxDepth)
	if _, ok := oracleOctetFragments(contents, 1); ok {
		t.Fatal("oracle admitted a segment deeper than the implicit wrapper permits")
	}
	if _, err := DecodeImplicitOctetStringValue(true, contents); err == nil {
		t.Fatal("decoder admitted a segment deeper than MaxDepth")
	}
	empty := deepImplicitEmptyOctetFragments(DefaultDecodeLimits().MaxDepth)
	if _, ok := oracleOctetFragments(empty, 1); !ok {
		t.Fatal("oracle rejected an empty constructed segment at MaxDepth")
	}
	if _, err := DecodeImplicitOctetStringValue(true, empty); err != nil {
		t.Fatalf("decoder rejected an empty constructed segment at MaxDepth: %v", err)
	}
}
