// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

// TestVectorSuccessfulOutcomeDapsExtensionRecursive verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.1.1.2, 9.3.4, and 9.3.7; DAPS response extensions remain recursively reachable from the procedure value.
func TestVectorSuccessfulOutcomeDapsExtensionRecursive(t *testing.T) {
	input := asn1VectorHex(t, "000027000004000a400200070009400200080001400e000000400912800000016e000100000c400201aa")
	codec := s19.SuccessfulOutcomeCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "Value.AsHandoverRequestAcknowledge.ProtocolIEs[2].Value.AsERABsAdmittedList[0].Value.AsERABsAdmittedItem.IEExtensions[0].ExtensionValue.AsDAPSResponseInfo.DAPSResponseIndicator", "0")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
