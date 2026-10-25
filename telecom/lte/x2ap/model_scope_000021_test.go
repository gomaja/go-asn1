// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// TestVectorProtocolIeFieldHeader verifies 3GPP TS 36.423 V19.1.0 (2025-12), section 9.3.8; ProtocolIE-Field APER header and open-type payload.
func TestVectorProtocolIeFieldHeader(t *testing.T) {
	input := asn1VectorHex(t, "12344001aa")
	var field s18.HandoverRequestIEField
	bb := aper.NewBitBufferFromBytes(input)
	err := s18.X2apInternalHandoverRequestIEFieldUnmarshalAPERFrom(&field, bb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
		t.Fatal(err)
	}
	asn1VectorAssertPath(t, &field, "Id", "4660")
	asn1VectorAssertPath(t, &field, "Criticality", "1")
	asn1VectorAssertPath(t, &field, "Value.Opaque.Bytes", "\"qg==\"")
	out := aper.NewBitBuffer()
	err = s18.X2apInternalHandoverRequestIEFieldMarshalAPERTo(&field, out)
	wire := out.CompleteBytes()
	if err != nil || !bytes.Equal(wire, input) {
		t.Fatalf("replay = %x, %v", wire, err)
	}
}
