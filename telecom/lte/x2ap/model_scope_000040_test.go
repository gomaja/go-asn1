// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

func FuzzAPERX2APPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s20.X2APPDUCodec().DecodeAPER(input)
	})
}
