// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func FuzzAPERDispatchProtocolIeRecursiveFieldERABsToBeSetupItemIEsID65532(f *testing.F) {
	{
		field, err := s11.ERABsToBeSetupItemIEs().NewOpaque(65532, s00.CriticalityIgnore, asn1VectorHexForFuzz("deadbeef"))
		if err != nil {
			f.Fatal(err)
		}
		bb := aper.NewBitBuffer()
		if err := s11.X2apInternalERABsToBeSetupItemIEFieldMarshalAPERTo(&field, bb); err != nil {
			f.Fatal(err)
		}
		f.Add(bb.CompleteBytes())
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var field s11.ERABsToBeSetupItemIEField
		bb := aper.NewBitBufferFromBytes(input)
		if err := s11.X2apInternalERABsToBeSetupItemIEFieldUnmarshalAPERFrom(&field, bb); err != nil {
			return
		}
		_, _ = aper.CaptureFinalBits(bb, "ProtocolIEField[ERABsToBeSetupItemIEValue]")
	})
}
