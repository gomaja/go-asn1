// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

// TestVectorNrraReportRecursive verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.1.11 and 9.2; recursive NRRA report open-type decoding.
func TestVectorNrraReportRecursive(t *testing.T) {
	input := asn1VectorHex(t, "000001019e4009000006040000000000")
	codec := s19.AccessAndMobilityIndicationCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "ProtocolIEs[0].Id", "414")
	asn1VectorAssertPath(t, &decoded.Value, "ProtocolIEs[0].Value.AsNRRAReport[0].NRRAReport", "\"BAAAAAAA\"")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
