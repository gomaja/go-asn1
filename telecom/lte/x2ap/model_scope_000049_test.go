// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	testing "testing"
)

func FuzzAPERDispatchProtocolExtensionValueERABsAdmittedItemExtIEsID366(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s06.ERABsAdmittedItemExtIEs().DAPSResponseInfo().Codec().DecodeAPER(input)
	})
}
