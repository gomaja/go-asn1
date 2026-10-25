// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

func FuzzAPERSuccessfulOutcomeProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000027000004000a400200070009400200080001400e000000400912800000016e000100000c400201aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s19.SuccessfulOutcomeCodec().DecodeAPER(input)
	})
}
