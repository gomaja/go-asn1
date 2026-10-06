package validation

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
)

// ENBname and MMEname are PrintableString (SIZE (1..150, ...)), URI-Address
// is VisibleString: in the ALIGNED variant each character takes B2 = 8 bits
// (ITU-T X.691 (02/2021) 30.5.2; go-asn1#101). The S1SetupRequest,
// S1SetupResponse, ENBConfigurationUpdate, MMEConfigurationUpdate and
// TraceActivation values are pycrate 0.7.11 APER encodings that tshark 4.6.8
// dissects to the same strings. S1RemovalResponse (id-S1Removal, 67) is known
// to neither tool, so its field bytes are derived from X.691 30.5 by hand;
// they equal the tshark-checked S1SetupResponse MMEname for the same value.
func TestStringIEsMatchPycrate(t *testing.T) {
	for _, tc := range []struct {
		objectSet string
		id        int64
		value     string
		wire      string
	}{
		{"S1SetupRequestIEs", 60, "ab", "00806162"},
		{"S1SetupRequestIEs", 60, "eNB-1", "0200654e422d31"},
		{"ENBConfigurationUpdateIEs", 60, strings.Repeat("q", 151), "808097" + strings.Repeat("71", 151)},
		{"S1SetupResponseIEs", 61, "ab", "00806162"},
		{"MMEConfigurationUpdateIEs", 61, "ab", "00806162"},
		{"S1RemovalResponseIEs", 61, "ab", "00806162"},
		{"S1RemovalResponseIEs", 61, "MME-west 1", "04804d4d452d776573742031"},
	} {
		wire, _ := hex.DecodeString(tc.wire)
		decoded, err := s1ap.DecodeIEFieldValue(tc.objectSet, tc.id, wire)
		if err != nil {
			t.Fatalf("%s %d: decode %s: %v", tc.objectSet, tc.id, tc.wire, err)
		}
		if complete, ok := decoded.(*per.CompleteValue[string]); !ok || complete.Value != tc.value {
			t.Fatalf("%s %d: decode %s = %#v, want %q", tc.objectSet, tc.id, tc.wire, decoded, tc.value)
		}
		bb := per.NewBitBuffer()
		if err := per.EncodeKnownMultiplierStringAlignedExt(bb, tc.value, 7, 1, 150, true, true); err != nil {
			t.Fatal(err)
		}
		if got := bb.CompleteBytes(); !bytes.Equal(got, wire) {
			t.Fatalf("encode %q = %x, want %s", tc.value, got, tc.wire)
		}
	}
	uri, _ := hex.DecodeString("08687474703a2f2f78")
	if decoded, err := s1ap.DecodeExtensionFieldValue("TraceActivation-ExtIEs", 325, uri); err != nil {
		t.Fatalf("URI-Address: %v", err)
	} else if complete, ok := decoded.(*per.CompleteValue[string]); !ok || complete.Value != "http://x" {
		t.Fatalf("URI-Address = %#v", decoded)
	}
	// The 7-bit encoding of "ab" that the aligned codec used to produce.
	if decoded, err := s1ap.DecodeIEFieldValue("S1SetupRequestIEs", 60, []byte{0x00, 0x80, 0xc3, 0x88}); err == nil {
		t.Fatalf("decoded the 7-bit encoding as %#v", decoded)
	}

	// S1RemovalResponse carrying MMEname "ab", through the PDU and the
	// recursive IE decoder.
	removal, _ := hex.DecodeString("2043000b000001003d400400806162")
	var response s1ap.S1APPDU
	if err := response.UnmarshalAPER(removal); err != nil {
		t.Fatal(err)
	}
	if again, err := response.MarshalAPER(); err != nil || !bytes.Equal(again, removal) {
		t.Fatalf("S1RemovalResponse re-encoded %x, %v", again, err)
	}
	decoded, err := response.DecodeValueRecursive()
	if err != nil || len(decoded.ProtocolIEs) != 1 || decoded.ProtocolIEs[0].Field.Id != 61 {
		t.Fatalf("S1RemovalResponse IEs = %+v, %v", decoded, err)
	}
	if complete, ok := decoded.ProtocolIEs[0].Value.(*per.CompleteValue[string]); !ok || complete.Value != "ab" {
		t.Fatalf("S1RemovalResponse MMEname = %#v", decoded.ProtocolIEs[0].Value)
	}

	pdu, _ := hex.DecodeString("00110027000004003b00080000f11000000010003c400400806162004000070000004000f1100089400140")
	var message s1ap.S1APPDU
	if err := message.UnmarshalAPER(pdu); err != nil {
		t.Fatal(err)
	}
	if again, err := message.MarshalAPER(); err != nil || !bytes.Equal(again, pdu) {
		t.Fatalf("S1SetupRequest re-encoded %x, %v", again, err)
	}
}
