// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	testing "testing"
)

// TestVectorErabSetupDapsExtensionRecursive verifies 3GPP TS 36.423 V19.1.0 (2025-12), sections 9.3.4, 9.3.5, and 9.3.7; id-DAPSRequestInfo 363.
func TestVectorErabSetupDapsExtensionRecursive(t *testing.T) {
	input := asn1VectorHex(t, "2500093c03e00a000001deadbeef0000016b400100")
	codec := s10.ERABsToBeSetupItemCodec()
	decoded, _, err := codec.DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &decoded.Value, "IEExtensions[0].ExtensionValue.AsDAPSRequestInfo.DAPSIndicator", "0")
	wire, err := codec.EncodeAPER(decoded)
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
