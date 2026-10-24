// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

// TestVectorErabSetupUnknownExtensionPreserved verifies 3GPP TS 36.423 V19.1.0 (2026-02), sections 9.3.4 and 9.3.8; unknown/private ProtocolExtensionField values remain raw.
func TestVectorErabSetupUnknownExtensionPreserved(t *testing.T) {
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000fffc4004deadbeef")
	codec := s11.ERABsToBeSetupItemCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "IEExtensions[0].Id", "65532")
	asn1VectorAssertPath(t, &decoded.Value, "IEExtensions[0].ExtensionValue.Opaque.Bytes", "\"3q2+7w==\"")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
