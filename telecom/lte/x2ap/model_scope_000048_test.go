// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func FuzzAPERDispatchProtocolExtensionRecursiveFieldERABsAdmittedItemExtIEsID65532(f *testing.F) {
	{
		field, err := s06.ERABsAdmittedItemExtIEs().NewOpaque(65532, s00.CriticalityIgnore, asn1VectorHexForFuzz("deadbeef"))
		if err != nil {
			f.Fatal(err)
		}
		bb := aper.NewBitBuffer()
		if err := s06.X2apInternalERABsAdmittedItemExtIEsExtFieldMarshalAPERTo(&field, bb); err != nil {
			f.Fatal(err)
		}
		f.Add(bb.CompleteBytes())
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var field s06.ERABsAdmittedItemExtIEsExtField
		bb := aper.NewBitBufferFromBytes(input)
		if err := s06.X2apInternalERABsAdmittedItemExtIEsExtFieldUnmarshalAPERFrom(&field, bb); err != nil {
			return
		}
		_, _ = aper.CaptureFinalBits(bb, "ProtocolExtensionField[ERABsAdmittedItemExtIEsValue]")
	})
}
