// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/ber_test.go; SHA-256 c70cd0192c28c53a2303115f02bdb02913829269fcd24bec4f01adabce3c9607.
package ber

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestEncodeDecodeTag(t *testing.T) {
	tests := []struct {
		name string
		tag  tag.Tag
		hex  string
	}{
		{"BOOLEAN", tag.Tag{Class: tag.ClassUniversal, Number: 1}, "01"},
		{"INTEGER", tag.Tag{Class: tag.ClassUniversal, Number: 2}, "02"},
		{"SEQUENCE constructed", tag.Tag{Class: tag.ClassUniversal, Number: 16, Constructed: true}, "30"},
		{"CONTEXT 0", tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, "80"},
		{"CONTEXT 0 constructed", tag.Tag{Class: tag.ClassContextSpecific, Number: 0, Constructed: true}, "a0"},
		{"APPLICATION 1 constructed", tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, "61"},
		{"APPLICATION 2 constructed", tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, "62"},
		{"APPLICATION 4 constructed", tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, "64"},
		{"APPLICATION 5 constructed", tag.Tag{Class: tag.ClassApplication, Number: 5, Constructed: true}, "65"},
		{"APPLICATION 7 constructed", tag.Tag{Class: tag.ClassApplication, Number: 7, Constructed: true}, "67"},
		{"long form tag 31", tag.Tag{Class: tag.ClassUniversal, Number: 31}, "1f1f"},
		{"long form tag 128", tag.Tag{Class: tag.ClassUniversal, Number: 128}, "1f8100"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.tag.Encode()
			expectedBytes, _ := hex.DecodeString(tc.hex)
			if !bytes.Equal(encoded, expectedBytes) {
				t.Errorf("encode: got %x, want %s", encoded, tc.hex)
			}

			decoded, consumed, err := DecodeTag(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if !decoded.Equal(tc.tag) || decoded.Constructed != tc.tag.Constructed {
				t.Errorf("decode: got %v, want %v", decoded, tc.tag)
			}
		})
	}
}

func TestDecodeTagRejectsOverflowAndNonMinimalHighTag(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"integer collision", "1f82808080808080808002"},
		{"wrap to tag 32", "1f82808080808080808020"},
		{"wrap to tag 127", "1f8280808080808080807f"},
		{"signed overflow", "1f81808080808080808000"},
		{"short-form number", "1f1e"},
		{"leading zero group", "1f801f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := DecodeTag(wire); !errors.Is(err, ErrInvalidTag) {
				t.Fatalf("DecodeTag(%x) error = %v, want ErrInvalidTag", wire, err)
			}
		})
	}
	maxTag := tag.Tag{Class: tag.ClassContextSpecific, Number: math.MaxInt}
	if decoded, n, err := DecodeTag(maxTag.Encode()); err != nil || n != len(maxTag.Encode()) || !decoded.Equal(maxTag) {
		t.Fatalf("maximum tag round trip: decoded=%v bytes=%d error=%v", decoded, n, err)
	}
}

func FuzzDecodeTagCanonical(f *testing.F) {
	for _, wire := range [][]byte{
		{0x02}, {0x1f, 0x1f}, {0x1f, 0x80, 0x1f},
		{0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02},
		{0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x20},
		{0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f},
	} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, n, err := DecodeTag(wire)
		if err == nil && (n <= 0 || n > len(wire) || !bytes.Equal(decoded.Encode(), wire[:n])) {
			t.Fatalf("DecodeTag accepted noncanonical identifier %x as %v (%d bytes)", wire, decoded, n)
		}
	})
}

func TestEncodeDecodeLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
		hex    string
	}{
		{"zero", 0, "00"},
		{"short 1", 1, "01"},
		{"short 127", 127, "7f"},
		{"long 128", 128, "8180"},
		{"long 256", 256, "820100"},
		{"long 65535", 65535, "82ffff"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeLength(tc.length)
			expectedBytes, _ := hex.DecodeString(tc.hex)
			if !bytes.Equal(encoded, expectedBytes) {
				t.Errorf("encode: got %x, want %s", encoded, tc.hex)
			}

			decoded, indefinite, consumed, err := DecodeLength(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if indefinite {
				t.Error("unexpected indefinite length")
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if decoded != tc.length {
				t.Errorf("decode: got %d, want %d", decoded, tc.length)
			}
		})
	}
}

func TestIndefiniteLength(t *testing.T) {
	data := []byte{0x80}
	_, indef, consumed, err := DecodeLength(data)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !indef {
		t.Error("expected indefinite")
	}
	if consumed != 1 {
		t.Errorf("consumed: got %d, want 1", consumed)
	}
}

func TestDecodeLengthRejectsIntOverflow(t *testing.T) {
	wire := []byte{0x84, 0x80, 0, 0, 0} // 2^31 octets
	got, indefinite, consumed, err := DecodeLength(wire)
	if uint64(^uint(0)>>1) < 1<<31 {
		if err == nil {
			t.Fatalf("accepted unrepresentable length %d (indefinite=%v, consumed=%d)", got, indefinite, consumed)
		}
		return
	}
	if err != nil || indefinite || consumed != len(wire) || uint64(got) != 1<<31 {
		t.Fatalf("length = %d, indefinite=%v, consumed=%d, error=%v", got, indefinite, consumed, err)
	}
}

func TestBERLengthCannotWrapSliceBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"definite", []byte{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff}},
		{"nested indefinite", []byte{0x30, 0x80, 0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateBERElement(tc.wire); err == nil {
				t.Fatal("accepted BER length beyond input")
			}
			if _, _, _, err := DecodeTLV(tc.wire); err == nil {
				t.Fatal("accepted length beyond input")
			}
			if _, err := ValidateDERTLV(tc.wire); err == nil {
				t.Fatal("accepted truncated DER input")
			}
		})
	}
}

func TestValidateDERLargeCanonicalOID(t *testing.T) {
	// X.690 (02/2021) §§8.19–8.20 do not bound subidentifiers to uint64.
	for _, wire := range []string{
		"060b2a82808080808080808000",     // 1.2.18446744073709551616
		"0d0a82808080808080808000",       // relative arc 18446744073709551616
		"300d060b2a82808080808080808000", // raw DER child
	} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDERElement(data); err != nil {
			t.Fatalf("rejected canonical DER %s: %v", wire, err)
		}
	}
	large, _ := hex.DecodeString("060b2a82808080808080808000")
	if oid, _, err := DecodeObjectIdentifier(large); err != nil || oid.String() != "1.2.18446744073709551616" {
		t.Fatalf("large OID decode error = %v", err)
	}
	for _, wire := range []string{"06028000", "060181", "0d028000", "0d0181"} {
		data, _ := hex.DecodeString(wire)
		if err := ValidateDERElement(data); err == nil {
			t.Fatalf("accepted malformed base-128 OID %s", wire)
		}
	}
}

func TestValidateDERUTF8AndEmbeddedPDV(t *testing.T) {
	// X.690 (02/2021) §§8.17, 8.23.10; X.680 (02/2021) §36.5.
	for _, wire := range []string{
		"0c03636174",                     // UTF8String "cat"
		"0c03e282ac",                     // U+20AC in its shortest form
		"2b07a0028500820141",             // fixed identification, data "A"
		"2b08a00381012a820141",           // syntax OID 1.2, data "A"
		"2b0da008a00680012a81012b820141", // syntaxes pair
		"2b08a003820101820141",           // presentation context id
		"2b0da008a30680010181012a820141", // context negotiation
		"2b08a00384012a820141",           // transfer syntax
	} {
		data, _ := hex.DecodeString(wire)
		if err := ValidateDERElement(data); err != nil {
			t.Fatalf("rejected valid DER %s: %v", wire, err)
		}
	}
	for _, tc := range []struct{ wire, reason string }{
		{"0c01ff", "UTF8String"},                        // invalid byte
		{"0c02c0af", "UTF8String"},                      // overlong slash
		{"0c03eda080", "UTF8String"},                    // surrogate
		{"0c02e282", "UTF8String"},                      // truncated scalar
		{"2b00", "unexpected end"},                      // no identification or data
		{"2b03820141", "identification"},                // missing identification
		{"2b04a0028500", "unexpected end"},              // missing data
		{"2b0aa0028500810141820141", "data-value"},      // descriptor forbidden
		{"2b07a0028600820141", "alternative 6"},         // unknown identification alternative
		{"2b09a00481028000820141", "OBJECT IDENTIFIER"}, // nonminimal OID
		{"2b08a004820200018200", "nonminimal"},          // nonminimal INTEGER
		{"2b07a0028500a20141", "primitive [2]"},         // constructed data-value
	} {
		data, _ := hex.DecodeString(tc.wire)
		if err := ValidateDERElement(data); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("invalid DER %s: error=%v, want %q", tc.wire, err, tc.reason)
		}
		wrapped := mustEncode(t)(EncodeSequence(data))
		if err := ValidateDERElement(wrapped); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("invalid raw child %s: error=%v, want %q", tc.wire, err, tc.reason)
		}
	}
}

func FuzzValidateDERElementNoPanic(f *testing.F) {
	for _, seed := range [][]byte{
		{0x02, 0x01, 0x00},
		{0x02, 0x81, 0x01, 0x00},
		{0x1f, 0x02, 0x01, 0x00},
		{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff},
		{0x31, 0x07, 0x04, 0x05, 'v', 'a', 'l', 'u', 'e'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidateDERElement(data)
	})
}

func TestEncodeDecodeInteger(t *testing.T) {
	tests := []struct {
		name  string
		value int64
	}{
		{"zero", 0},
		{"positive 1", 1},
		{"positive 127", 127},
		{"positive 128", 128},
		{"positive 256", 256},
		{"negative -1", -1},
		{"negative -128", -128},
		{"negative -129", -129},
		{"large positive", 1234567890},
		{"large negative", -1234567890},
		{"max int64", math.MaxInt64},
		{"min int64", math.MinInt64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeInteger(tc.value)
			decoded, consumed, err := DecodeInteger(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if decoded != tc.value {
				t.Errorf("got %d, want %d", decoded, tc.value)
			}
		})
	}
}

func TestEncodeDecodeBigInt(t *testing.T) {
	tests := []struct {
		name  string
		value *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"positive", big.NewInt(42)},
		{"negative", big.NewInt(-42)},
		{"large", new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := mustEncode(t)(EncodeBigInt(tc.value))
			decoded, consumed, err := DecodeBigInt(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if decoded.Cmp(tc.value) != 0 {
				t.Errorf("got %s, want %s", decoded, tc.value)
			}
		})
	}
}

func TestEncodeDecodeNull(t *testing.T) {
	encoded := EncodeNull()
	consumed, err := DecodeNull(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
	}
	expected, _ := hex.DecodeString("0500")
	if !bytes.Equal(encoded, expected) {
		t.Errorf("encoding: got %x, want 0500", encoded)
	}
}

func TestEncodeDecodeOID(t *testing.T) {
	tests := []struct {
		name string
		oid  []uint64
		hex  string
	}{
		{"id-at-commonName", []uint64{2, 5, 4, 3}, "0603550403"},
		{"rsaEncryption", []uint64{1, 2, 840, 113549, 1, 1, 1}, "06092a864886f70d010101"},
		{"id-ce", []uint64{2, 5, 29}, "0602551d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := mustEncode(t)(EncodeObjectIdentifier(runtime.MustObjectIdentifierFromArcs(tc.oid...)))
			expected, _ := hex.DecodeString(tc.hex)
			if !bytes.Equal(encoded, expected) {
				t.Errorf("encode: got %x, want %s", encoded, tc.hex)
			}

			decoded, consumed, err := DecodeObjectIdentifier(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			decodedArcs, ok := decoded.Arcs()
			if !ok {
				t.Fatal("arc range")
			}
			if len(decodedArcs) != len(tc.oid) {
				t.Fatalf("len: got %d, want %d", len(decodedArcs), len(tc.oid))
			}
			for i := range decodedArcs {
				if decodedArcs[i] != tc.oid[i] {
					t.Errorf("arc[%d]: got %d, want %d", i, decodedArcs[i], tc.oid[i])
				}
			}
		})
	}
}

func TestImplicitTagPreservesFormAndLength(t *testing.T) {
	indefinite := mustEncode(t)(EncodeConstructedIndefinite(
		tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence},
		EncodeNull(),
	))
	got, err := EncodeImplicitTagWithClass(tag.ClassApplication, 12, indefinite)
	if err != nil {
		t.Fatalf("EncodeImplicitTagWithClass: %v", err)
	}
	want := append([]byte{0x6c}, indefinite[1:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("retagged value = %x, want %x", got, want)
	}
}

func TestImplicitTagReconstructionAllocationBudget(t *testing.T) {
	inner := []byte{0x04, 0x01, 'A'}
	var encoded []byte
	canonicalAllocs := testing.AllocsPerRun(1000, func() {
		var err error
		encoded, err = EncodeSequence(inner)
		if err != nil {
			t.Fatal(err)
		}
	})
	for _, wire := range [][]byte{
		{0xa0, 0x03, 0x04, 0x01, 'A'},
		{0xa0, 0x81, 0x03, 0x04, 0x01, 'A'},
		{0xa0, 0x80, 0x04, 0x01, 'A', 0, 0},
	} {
		allocs := testing.AllocsPerRun(1000, func() {
			var err error
			encoded, err = EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, wire)
			if err != nil {
				t.Fatal(err)
			}
		})
		if allocs > canonicalAllocs {
			t.Fatalf("retagging %x allocated %.0f times, canonical reconstruction allocated %.0f", wire, allocs, canonicalAllocs)
		}
	}
	_ = encoded
}

// TestDecodeTCAPBegin validates decoding of a real TCAP Begin message from go-tcap.
func TestDecodeTCAPBegin(t *testing.T) {
	// TCAP Begin: SRI-SM operation from go-tcap test vectors.
	hexData := "62494804004734a86b1e281c060700118605010101a011600f80020780a1090607040000010014036c21a11f02010002012d3017800891328490507608f38101ff820891328490000005f7"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	// Outer tag: APPLICATION 2 CONSTRUCTED (Begin).
	outerTag, total, value, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	if outerTag.Class != tag.ClassApplication || outerTag.Number != 2 || !outerTag.Constructed {
		t.Fatalf("expected APPLICATION 2 CONSTRUCTED, got %v", outerTag)
	}

	// Parse children of Begin.
	children, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children: %v", err)
	}
	if len(children) < 2 {
		t.Fatalf("expected at least 2 children, got %d", len(children))
	}

	// First child: OTID (originating transaction ID).
	otidTag, _, otidValue, err := DecodeTLV(children[0])
	if err != nil {
		t.Fatalf("decode OTID: %v", err)
	}
	if otidTag.Number != 8 {
		t.Errorf("OTID tag: got %d, want 8", otidTag.Number)
	}
	expectedOTID, _ := hex.DecodeString("004734a8")
	if !bytes.Equal(otidValue, expectedOTID) {
		t.Errorf("OTID value: got %x, want %x", otidValue, expectedOTID)
	}
}

// TestDecodeGSMMAPSriSm validates decoding of a GSM MAP SRI-for-SM from go-gsmmap.
func TestDecodeGSMMAPSriSm(t *testing.T) {
	// SRI-for-SM request from go-gsmmap test vectors.
	hexData := "301380069122608538188101ff8206912260909899"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	// Outer tag: SEQUENCE.
	outerTag, total, value, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	if outerTag.Class != tag.ClassUniversal || outerTag.Number != tag.TagSequence || !outerTag.Constructed {
		t.Fatalf("expected SEQUENCE, got %v", outerTag)
	}

	// Parse SEQUENCE children.
	children, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children: %v", err)
	}
	if len(children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(children))
	}

	// Child 0: CONTEXT [0] IMPLICIT (MSISDN) = OCTET STRING.
	msisdnTag, _, msisdnValue, err := DecodeTLV(children[0])
	if err != nil {
		t.Fatalf("decode MSISDN: %v", err)
	}
	if msisdnTag.Class != tag.ClassContextSpecific || msisdnTag.Number != 0 {
		t.Errorf("MSISDN tag: got %v, want CONTEXT 0", msisdnTag)
	}
	expectedMSISDN, _ := hex.DecodeString("912260853818")
	if !bytes.Equal(msisdnValue, expectedMSISDN) {
		t.Errorf("MSISDN: got %x, want %x", msisdnValue, expectedMSISDN)
	}

	// Child 1: CONTEXT [1] IMPLICIT (sm-RP-PRI) = BOOLEAN.
	priTag, _, priValue, err := DecodeTLV(children[1])
	if err != nil {
		t.Fatalf("decode sm-RP-PRI: %v", err)
	}
	if priTag.Class != tag.ClassContextSpecific || priTag.Number != 1 {
		t.Errorf("sm-RP-PRI tag: got %v, want CONTEXT 1", priTag)
	}
	if len(priValue) != 1 || priValue[0] != 0xFF {
		t.Errorf("sm-RP-PRI value: got %x, want ff", priValue)
	}

	// Child 2: CONTEXT [2] IMPLICIT (serviceCentreAddress) = OCTET STRING.
	scaTag, _, scaValue, err := DecodeTLV(children[2])
	if err != nil {
		t.Fatalf("decode SCA: %v", err)
	}
	if scaTag.Class != tag.ClassContextSpecific || scaTag.Number != 2 {
		t.Errorf("SCA tag: got %v, want CONTEXT 2", scaTag)
	}
	expectedSCA, _ := hex.DecodeString("912260909899")
	if !bytes.Equal(scaValue, expectedSCA) {
		t.Errorf("SCA: got %x, want %x", scaValue, expectedSCA)
	}
}

// TestDecodeTCAPEnd validates decoding of a TCAP End message.
func TestDecodeTCAPEnd(t *testing.T) {
	// TCAP End with returnResultLast.
	hexData := "640d4904008bd0406c05a203020102"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	outerTag, total, value, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	// APPLICATION 4 = End.
	if outerTag.Class != tag.ClassApplication || outerTag.Number != 4 || !outerTag.Constructed {
		t.Fatalf("expected APPLICATION 4 CONSTRUCTED, got %v", outerTag)
	}

	children, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(children))
	}
}

// TestDecodeTCAPContinue validates decoding of a TCAP Continue message.
func TestDecodeTCAPContinue(t *testing.T) {
	hexData := "651348040419000f4904008bd0406c05a203020101"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	outerTag, _, _, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	// APPLICATION 5 = Continue.
	if outerTag.Class != tag.ClassApplication || outerTag.Number != 5 || !outerTag.Constructed {
		t.Fatalf("expected APPLICATION 5 CONSTRUCTED, got %v", outerTag)
	}
}

// TestDecodeTCAPAbort validates decoding of a TCAP Abort message.
func TestDecodeTCAPAbort(t *testing.T) {
	hexData := "6732490402b0d1c46b2a2828060700118605010101a01d611b80020780a109060704000001001402a203020101a305a103020102"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	outerTag, total, _, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	// APPLICATION 7 = Abort.
	if outerTag.Class != tag.ClassApplication || outerTag.Number != 7 || !outerTag.Constructed {
		t.Fatalf("expected APPLICATION 7 CONSTRUCTED, got %v", outerTag)
	}
}

// TestDecodeGSMMAPSriSmResp validates decoding of a GSM MAP SRI-SM response.
func TestDecodeGSMMAPSriSmResp(t *testing.T) {
	hexData := "3015040882131068584836f3a0098107917394950862f6"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	outerTag, total, value, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	if outerTag.Number != tag.TagSequence {
		t.Fatalf("expected SEQUENCE, got %v", outerTag)
	}

	children, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(children))
	}

	// Child 0: OCTET STRING (IMSI).
	imsiTag, _, imsiValue, err := DecodeTLV(children[0])
	if err != nil {
		t.Fatalf("decode IMSI: %v", err)
	}
	if imsiTag.Number != tag.TagOctetString {
		t.Errorf("IMSI tag: got %v, want OCTET STRING", imsiTag)
	}
	expectedIMSI, _ := hex.DecodeString("82131068584836f3")
	if !bytes.Equal(imsiValue, expectedIMSI) {
		t.Errorf("IMSI: got %x, want %x", imsiValue, expectedIMSI)
	}

	// Child 1: CONTEXT [0] CONSTRUCTED (LocationInfoWithLMSI).
	locTag, _, _, err := DecodeTLV(children[1])
	if err != nil {
		t.Fatalf("decode LocationInfo: %v", err)
	}
	if locTag.Class != tag.ClassContextSpecific || locTag.Number != 0 || !locTag.Constructed {
		t.Errorf("LocationInfo tag: got %v, want CONTEXT 0 CONSTRUCTED", locTag)
	}
}

// TestDecodeGSMMAPMtFsm validates decoding of a GSM MAP MT-ForwardSM.
func TestDecodeGSMMAPMtFsm(t *testing.T) {
	hexData := "3081b7800826610011829761f6840891328490000005f704819e4009d047f6dbfe06000042217251400000a00500035f020190e53c0b947fd741e8b0bd0c9abfdb6510bcec26a7dd67d09c5e86cf41693728ffaecb41f2f2393da7cbc3f4f4db0d82cbdfe3f27cee0241d9e5f0bc0c32bfd9ecf71d44479741ecb47b0da2bf41e3771bce2ed3cb203abadc0685dd64d09c1e96d341e4323b6d2fcbd3ee33888e96bfeb6734e8c87edbdf2190bc3c96d7d3f476d94d77d5e70500"

	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}

	outerTag, total, value, err := DecodeTLV(data)
	if err != nil {
		t.Fatalf("decode TLV: %v", err)
	}
	if total != len(data) {
		t.Errorf("consumed: got %d, want %d", total, len(data))
	}
	if outerTag.Number != tag.TagSequence {
		t.Fatalf("expected SEQUENCE, got %v", outerTag)
	}

	children, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children: %v", err)
	}
	// MT-ForwardSM has at least 3 children: SM-RP-DA, SM-RP-OA, SM-RP-UI.
	if len(children) < 3 {
		t.Fatalf("expected at least 3 children, got %d", len(children))
	}
}
