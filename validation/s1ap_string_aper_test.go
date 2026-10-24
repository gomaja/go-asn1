package validation

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
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
	enb := func(codec s1ap.ENBnameValueCodec) s1apStringCheck {
		return checkS1APStringCodec(codec, func(value s1ap.ENBnameAPERValue) string { return value.Value })
	}
	mme := func(codec s1ap.MMEnameValueCodec) s1apStringCheck {
		return checkS1APStringCodec(codec, func(value s1ap.MMEnameAPERValue) string { return value.Value })
	}
	for _, tc := range []struct {
		name  string
		check s1apStringCheck
		value string
		wire  string
	}{
		{"S1SetupRequestIEs", enb(s1ap.S1SetupRequestIEs().ENBname().Codec()), "ab", "00806162"},
		{"S1SetupRequestIEs", enb(s1ap.S1SetupRequestIEs().ENBname().Codec()), "eNB-1", "0200654e422d31"},
		{"ENBConfigurationUpdateIEs", enb(s1ap.ENBConfigurationUpdateIEs().ENBname().Codec()), strings.Repeat("q", 151), "808097" + strings.Repeat("71", 151)},
		{"S1SetupResponseIEs", mme(s1ap.S1SetupResponseIEs().MMEname().Codec()), "ab", "00806162"},
		{"MMEConfigurationUpdateIEs", mme(s1ap.MMEConfigurationUpdateIEs().MMEname().Codec()), "ab", "00806162"},
		{"S1RemovalResponseIEs", mme(s1ap.S1RemovalResponseIEs().MMEname().Codec()), "ab", "00806162"},
		{"S1RemovalResponseIEs", mme(s1ap.S1RemovalResponseIEs().MMEname().Codec()), "MME-west 1", "04804d4d452d776573742031"},
	} {
		wire, _ := hex.DecodeString(tc.wire)
		tc.check(t, tc.name, tc.value, wire, tc.wire)
	}

	uri, _ := hex.DecodeString("08687474703a2f2f78")
	uriValue, _, err := s1ap.TraceActivationExtIEs().TraceCollectionEntityURI().Codec().DecodeAPER(uri)
	if err != nil || uriValue.Value != "http://x" {
		t.Fatalf("URI-Address=%q err=%v", uriValue.Value, err)
	}
	// Reject the old invalid seven-bit aligned representation.
	if decoded, _, err := s1ap.S1SetupRequestIEs().ENBname().Codec().DecodeAPER([]byte{0, 0x80, 0xc3, 0x88}); err == nil {
		t.Fatalf("decoded old seven-bit form as %q", decoded.Value)
	}

	// S1RemovalResponse carrying MMEname "ab", through the PDU and the
	// one-pass typed IE decoder.
	removal, _ := hex.DecodeString("2043000b000001003d400400806162")
	var response s1ap.S1APPDU
	if _, err := response.UnmarshalAPER(removal); err != nil {
		t.Fatal(err)
	}
	if again, err := response.MarshalAPER(); err != nil || !bytes.Equal(again, removal) {
		t.Fatalf("S1RemovalResponse re-encoded %x, %v", again, err)
	}
	body, ok := response.SuccessfulOutcome.Value.AsS1RemovalResponse()
	if !ok || len(body.ProtocolIEs) != 1 || body.ProtocolIEs[0].Id != 61 {
		t.Fatalf("S1RemovalResponse typed body=%+v", body)
	}
	name, ok := body.ProtocolIEs[0].Value.AsMMEname()
	if !ok || name == nil || *name != "ab" {
		t.Fatalf("S1RemovalResponse MMEname=%v ok=%v", name, ok)
	}

	pdu, _ := hex.DecodeString("00110027000004003b00080000f11000000010003c400400806162004000070000004000f1100089400140")
	var message s1ap.S1APPDU
	if _, err := message.UnmarshalAPER(pdu); err != nil {
		t.Fatal(err)
	}
	if again, err := message.MarshalAPER(); err != nil || !bytes.Equal(again, pdu) {
		t.Fatalf("S1SetupRequest re-encoded %x, %v", again, err)
	}
}

// Each source string now has its own concrete holder. Keep the shared oracle
// assertions caller-parametric while retaining each holder's typed access.
type s1apStringCodec[V any] interface {
	DecodeAPER([]byte, ...aper.DecodeOption) (V, aper.DecodeReport, error)
	New(string) (V, error)
	EncodeAPER(V, ...aper.EncodeOption) ([]byte, error)
}
type s1apStringCheck func(*testing.T, string, string, []byte, string)

func checkS1APStringCodec[V any](codec s1apStringCodec[V], contents func(V) string) s1apStringCheck {
	return func(t *testing.T, name, value string, wire []byte, wireText string) {
		t.Helper()
		decoded, _, err := codec.DecodeAPER(wire)
		if err != nil || contents(decoded) != value {
			t.Fatalf("%s decode=%q err=%v want=%q", name, contents(decoded), err, value)
		}
		fresh, err := codec.New(value)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := codec.EncodeAPER(fresh); err != nil || !bytes.Equal(got, wire) {
			t.Fatalf("%s encode=%x err=%v want=%s", name, got, err, wireText)
		}
	}
}
