// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	testing "testing"
)

func FuzzAPERERABsToBeSetupItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000016b400100"))
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("2500093c03e00a000001deadbeef0000016b4001ff"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s11.ERABsToBeSetupItemCodec().DecodeAPER(input)
	})
}
