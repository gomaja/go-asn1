package ber

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/gomaja/go-asn1/runtime/tag"
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

func TestEncodeDecodeBoolean(t *testing.T) {
	for _, val := range []bool{true, false} {
		encoded := EncodeBoolean(val)
		decoded, _, consumed, err := DecodeBoolean(encoded)
		if err != nil {
			t.Fatalf("bool=%v: decode error: %v", val, err)
		}
		if consumed != len(encoded) {
			t.Errorf("bool=%v: consumed %d, want %d", val, consumed, len(encoded))
		}
		if decoded != val {
			t.Errorf("bool: got %v, want %v", decoded, val)
		}
	}
	// DER: true must encode as 0xFF.
	encoded := EncodeBoolean(true)
	if encoded[2] != 0xFF {
		t.Errorf("DER true: value byte got %02x, want ff", encoded[2])
	}
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
			encoded := EncodeBigInt(tc.value)
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

func TestEncodeDecodeBitString(t *testing.T) {
	tests := []struct {
		name       string
		bytes      []byte
		unusedBits int
	}{
		{"empty", nil, 0},
		{"full byte", []byte{0xFF}, 0},
		{"7 bits", []byte{0xFE}, 1},
		{"multi byte", []byte{0xDE, 0xAD, 0xBE, 0xEF}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeBitString(tc.bytes, tc.unusedBits)
			decoded, unusedBits, consumed, err := DecodeBitString(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if tc.bytes == nil {
				if len(decoded) != 0 {
					t.Errorf("expected empty, got %x", decoded)
				}
				return
			}
			if !bytes.Equal(decoded, tc.bytes) {
				t.Errorf("bytes: got %x, want %x", decoded, tc.bytes)
			}
			if unusedBits != tc.unusedBits {
				t.Errorf("unusedBits: got %d, want %d", unusedBits, tc.unusedBits)
			}
		})
	}
}

func TestEncodeDecodeOctetString(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"binary", []byte{0x00, 0xFF, 0xDE, 0xAD}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeOctetString(tc.value)
			decoded, consumed, err := DecodeOctetString(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if !bytes.Equal(decoded, tc.value) {
				t.Errorf("got %x, want %x", decoded, tc.value)
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
			encoded := EncodeObjectIdentifier(tc.oid)
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
			if len(decoded) != len(tc.oid) {
				t.Fatalf("len: got %d, want %d", len(decoded), len(tc.oid))
			}
			for i := range decoded {
				if decoded[i] != tc.oid[i] {
					t.Errorf("arc[%d]: got %d, want %d", i, decoded[i], tc.oid[i])
				}
			}
		})
	}
}

func TestEncodeDecodeEnumerated(t *testing.T) {
	for _, v := range []int64{0, 1, -1, 42, 255} {
		encoded := EncodeEnumerated(v)
		decoded, consumed, err := DecodeEnumerated(encoded)
		if err != nil {
			t.Fatalf("v=%d: decode error: %v", v, err)
		}
		if consumed != len(encoded) {
			t.Errorf("v=%d: consumed %d, want %d", v, consumed, len(encoded))
		}
		if decoded != v {
			t.Errorf("got %d, want %d", decoded, v)
		}
	}
}

func TestEncodeDecodeReal(t *testing.T) {
	tests := []struct {
		name  string
		value float64
	}{
		{"zero", 0},
		{"positive", 3.14},
		{"negative", -2.718},
		{"one", 1.0},
		{"large", 1e100},
		{"small", 1e-100},
		{"+inf", math.Inf(1)},
		{"-inf", math.Inf(-1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := EncodeReal(tc.value)
			decoded, consumed, err := DecodeReal(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
			}
			if math.IsInf(tc.value, 0) {
				if !math.IsInf(decoded, int(tc.value)) {
					t.Errorf("got %v, want %v", decoded, tc.value)
				}
			} else if tc.value != decoded {
				t.Errorf("got %v, want %v", decoded, tc.value)
			}
		})
	}

	// NaN test.
	encoded := EncodeReal(math.NaN())
	decoded, _, err := DecodeReal(encoded)
	if err != nil {
		t.Fatalf("NaN decode error: %v", err)
	}
	if !math.IsNaN(decoded) {
		t.Errorf("expected NaN, got %v", decoded)
	}
}

func TestEncodeDecodeUTCTime(t *testing.T) {
	now := time.Date(2024, 3, 15, 10, 30, 45, 0, time.UTC)
	encoded := EncodeUTCTime(now)
	decoded, consumed, err := DecodeUTCTime(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
	}
	if !decoded.Equal(now) {
		t.Errorf("got %v, want %v", decoded, now)
	}
}

func TestEncodeDecodeGeneralizedTime(t *testing.T) {
	now := time.Date(2024, 3, 15, 10, 30, 45, 0, time.UTC)
	encoded := EncodeGeneralizedTime(now)
	decoded, consumed, err := DecodeGeneralizedTime(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if consumed != len(encoded) {
		t.Errorf("consumed: got %d, want %d", consumed, len(encoded))
	}
	if !decoded.Equal(now) {
		t.Errorf("got %v, want %v", decoded, now)
	}
}

func TestEncodeDecodeSequence(t *testing.T) {
	// Build a SEQUENCE { INTEGER 42, BOOLEAN true }
	children := append(EncodeInteger(42), EncodeBoolean(true)...)
	encoded := EncodeSequence(children)

	// Decode the outer TLV.
	outerTag, total, value, err := DecodeTLV(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if total != len(encoded) {
		t.Errorf("consumed: got %d, want %d", total, len(encoded))
	}
	if outerTag.Class != tag.ClassUniversal || outerTag.Number != tag.TagSequence || !outerTag.Constructed {
		t.Errorf("unexpected tag: %v", outerTag)
	}

	// Decode children.
	childTLVs, err := DecodeSequenceChildren(value)
	if err != nil {
		t.Fatalf("decode children error: %v", err)
	}
	if len(childTLVs) != 2 {
		t.Fatalf("expected 2 children, got %d", len(childTLVs))
	}

	intVal, _, err := DecodeInteger(childTLVs[0])
	if err != nil {
		t.Fatalf("decode integer: %v", err)
	}
	if intVal != 42 {
		t.Errorf("integer: got %d, want 42", intVal)
	}

	boolVal, _, _, err := DecodeBoolean(childTLVs[1])
	if err != nil {
		t.Fatalf("decode boolean: %v", err)
	}
	if !boolVal {
		t.Error("boolean: got false, want true")
	}
}

func TestExplicitTag(t *testing.T) {
	// Encode INTEGER 42, then wrap in EXPLICIT [0].
	inner := EncodeInteger(42)
	wrapped := EncodeExplicitTag(0, inner)

	// Decode outer tag.
	outerTag, _, value, err := DecodeTLV(wrapped)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if outerTag.Class != tag.ClassContextSpecific || outerTag.Number != 0 || !outerTag.Constructed {
		t.Errorf("unexpected outer tag: %v", outerTag)
	}

	// Decode inner INTEGER.
	intVal, _, err := DecodeInteger(value)
	if err != nil {
		t.Fatalf("decode inner integer: %v", err)
	}
	if intVal != 42 {
		t.Errorf("got %d, want 42", intVal)
	}
}

func TestImplicitTag(t *testing.T) {
	// Encode OCTET STRING, then re-tag as IMPLICIT [1].
	inner := EncodeOctetString([]byte("hello"))
	retagged := EncodeImplicitTag(1, false, inner)

	// Decode outer tag.
	outerTag, _, value, err := DecodeTLV(retagged)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if outerTag.Class != tag.ClassContextSpecific || outerTag.Number != 1 {
		t.Errorf("unexpected outer tag: %v", outerTag)
	}
	if string(value) != "hello" {
		t.Errorf("got %q, want %q", string(value), "hello")
	}
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
