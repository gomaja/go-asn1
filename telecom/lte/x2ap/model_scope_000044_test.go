// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

func FuzzAPERAccessAndMobilityIndicationProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001019e4009000006040000000000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s20.AccessAndMobilityIndicationCodec().DecodeAPER(input)
	})
}
