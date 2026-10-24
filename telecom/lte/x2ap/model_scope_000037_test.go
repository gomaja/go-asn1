// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

func FuzzAPERX2APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0000007b000006000a00020001000540020000000b00080021f35412345670001700070021f354000101000e004100010000000000000000000000000000000000000000000000000000000000000000000000000000010001000004400e4500060401f0c000020100000001020000000f400c000021f35412345670000005"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s19.X2APPDUCodec().DecodeAPER(input)
	})
}
