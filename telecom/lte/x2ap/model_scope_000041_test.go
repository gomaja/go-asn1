// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

func FuzzAPERGlobalGNBID(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0001020300"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s11.GlobalGNBIDCodec().DecodeAPER(input)
	})
}
