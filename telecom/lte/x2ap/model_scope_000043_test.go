// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

func FuzzAPERDispatchProtocolIeRecursiveFieldERABsToBeSetupItemIEsID4(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4500060701f00afd0055037806f5"))
	f.Add(asn1VectorHexForFuzz("00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s11.ERABsToBeSetupItemIEs().ERABsToBeSetupItem().Codec().DecodeAPER(input)
	})
}
