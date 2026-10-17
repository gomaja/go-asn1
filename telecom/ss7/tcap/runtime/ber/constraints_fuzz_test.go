// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/constraints_fuzz_test.go; SHA-256 9082b783ef3e30f16636ccc21f420836b3aadcd643b1a84a5464f4e8caca7b58.
package ber

import (
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
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
