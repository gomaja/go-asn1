// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func FuzzAPERProtocolIEField(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12344001aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var field s18.HandoverRequestIEField
		bb := aper.NewBitBufferFromBytes(input)
		if err := s18.X2apInternalHandoverRequestIEFieldUnmarshalAPERFrom(&field, bb); err != nil {
			return
		}
		_, _ = aper.CaptureFinalBits(bb, "ProtocolIEField[HandoverRequestIEValue]")
	})
}
