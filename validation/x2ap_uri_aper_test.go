package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/runtime/per"
	"github.com/gomaja/go-asn1/telecom/lte/x2ap"
)

// URI-Address is VisibleString: in the ALIGNED variant each character takes
// B2 = 8 bits (ITU-T X.691 (02/2021) 30.5.2; go-asn1#101). The TraceStart
// PDU below is a synthetic pycrate 0.7.11 encoding whose TraceActivation
// carries extension 405 (TS 36.423 V19.1.0); tshark 4.6.8 dissects it as
// "URI-Address: https://ref.invalid/x2" without expert items.
func TestURIAddressMatchesPycrate(t *testing.T) {
	field, _ := hex.DecodeString("1668747470733a2f2f7265662e696e76616c69642f7832")
	decoded, err := x2ap.DecodeExtensionFieldValue("TraceActivation-ExtIEs", 405, field)
	if err != nil {
		t.Fatalf("decode extension 405: %v", err)
	}
	if complete, ok := decoded.(*per.CompleteValue[string]); !ok || complete.Value != "https://ref.invalid/x2" {
		t.Fatalf("decode extension 405 = %#v", decoded)
	}
	bb := per.NewBitBuffer()
	if err := per.EncodeKnownMultiplierStringAligned(bb, "https://ref.invalid/x2", 7, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := bb.CompleteBytes(); !bytes.Equal(got, field) {
		t.Fatalf("encode = %x, want %x", got, field)
	}

	pdu, _ := hex.DecodeString("002f4040000003006f0002000100cf00020002000d402d4000f11000000100018000f80a0000010000019540171668747470733a2f2f7265662e696e76616c69642f7832")
	var message x2ap.X2APPDU
	if err := message.UnmarshalAPER(pdu); err != nil {
		t.Fatal(err)
	}
	if again, err := message.MarshalAPER(); err != nil || !bytes.Equal(again, pdu) {
		t.Fatalf("TraceStart re-encoded %x, %v", again, err)
	}
	value, err := message.DecodeValueRecursive()
	if err != nil {
		t.Fatalf("recursive decode: %v", err)
	}
	var uris []string
	for _, ie := range value.ProtocolIEs {
		for _, extension := range ie.Extensions {
			if complete, ok := extension.Value.(*per.CompleteValue[string]); ok && extension.Field.Id == 405 {
				uris = append(uris, complete.Value)
			}
		}
	}
	if len(uris) != 1 || uris[0] != "https://ref.invalid/x2" {
		t.Fatalf("URI-Address values = %q", uris)
	}
}
