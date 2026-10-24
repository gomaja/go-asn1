package validation

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/x2ap"
	"github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// URI-Address is VisibleString: in the ALIGNED variant each character takes
// B2 = 8 bits (ITU-T X.691 (02/2021) 30.5.2; go-asn1#101). The TraceStart
// PDU below is a synthetic pycrate 0.7.11 encoding whose TraceActivation
// carries extension 405 (TS 36.423 V19.1.0); tshark 4.6.8 dissects it as
// "URI-Address: https://ref.invalid/x2" without expert items.
func TestURIAddressMatchesPycrate(t *testing.T) {
	field, _ := hex.DecodeString("1668747470733a2f2f7265662e696e76616c69642f7832")
	codec := x2ap.TraceActivationExtIEs().TraceCollectionEntityURI().Codec()
	decoded, _, err := codec.DecodeAPER(field)
	if err != nil || decoded.Value != "https://ref.invalid/x2" {
		t.Fatalf("decode extension 405: %v", err)
	}
	if wire, err := codec.EncodeAPER(decoded, aper.WithoutReplay()); err != nil || !bytes.Equal(wire, field) {
		t.Fatalf("URI encode: %x, %v", wire, err)
	}

	pdu, _ := hex.DecodeString("002f4040000003006f0002000100cf00020002000d402d4000f11000000100018000f80a0000010000019540171668747470733a2f2f7265662e696e76616c69642f7832")
	var message x2ap.X2APPDU
	if _, err := message.UnmarshalAPER(pdu); err != nil {
		t.Fatal(err)
	}
	if again, err := message.MarshalAPER(); err != nil || !bytes.Equal(again, pdu) {
		t.Fatalf("TraceStart re-encoded %x, %v", again, err)
	}
	value, ok := message.InitiatingMessage.Value.AsTraceStart()
	if !ok {
		t.Fatal("typed TraceStart missing")
	}
	var uris []string
	for i := range value.ProtocolIEs {
		trace, ok := x2ap.TraceStartIEs().TraceActivation().Get(&value.ProtocolIEs[i])
		if !ok {
			continue
		}
		for j := range trace.IEExtensions {
			uri, ok := x2ap.TraceActivationExtIEs().TraceCollectionEntityURI().Get(&trace.IEExtensions[j])
			if ok {
				uris = append(uris, *uri)
			}
		}
	}
	if len(uris) != 1 || uris[0] != "https://ref.invalid/x2" {
		t.Fatalf("URI-Address values = %q", uris)
	}
}
