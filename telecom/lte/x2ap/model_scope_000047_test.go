// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

func FuzzAPERDispatchProtocolIeValueHandoverRequestIEsID10(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0007"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s18.HandoverRequestIEs().OldENBUEX2APID().Codec().DecodeAPER(input)
	})
}
