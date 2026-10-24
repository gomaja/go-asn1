// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	testing "testing"
)

func FuzzAPERERABsAdmittedItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12800000016e0000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s09.ERABsAdmittedItemCodec().DecodeAPER(input)
	})
}
