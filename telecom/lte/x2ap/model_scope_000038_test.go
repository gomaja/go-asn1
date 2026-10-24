// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	testing "testing"
)

func FuzzAPERDispatchProtocolIeValueHandoverRequestIEsID15(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000021f35412345670000005"))
	f.Add(asn1VectorHexForFuzz("800006f730010840b10000050006f730010220c10000020006f730010840b10000010006f730010220c10000120006f730010840b10000070006f730010220c100000d0006f730010840b100001a0006f730010220c10000030006f730010840b1000062"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s18.HandoverRequestIEs().UEHistoryInformation().Codec().DecodeAPER(input)
	})
}
