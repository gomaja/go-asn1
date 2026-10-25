// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func eRABsAdmittedItemExtIEsValuereplayBoundExtensionFieldCodec() ERABsAdmittedItemExtIEsExtFieldValueCodec {
	return ERABsAdmittedItemExtIEsExtFieldValueCodec{decode: func(data []byte, state aper.DecodeState) (s06.ERABsAdmittedItemExtIEsExtField, error) {
		var value s06.ERABsAdmittedItemExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, state)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			return value, err
		}
		if err := s06.X2apInternalERABsAdmittedItemExtIEsExtFieldUnmarshalAPERFrom(&value, bb); err != nil {
			return value, err
		}
		_, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField")
		return value, err
	}, encode: func(value s06.ERABsAdmittedItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := s06.X2apInternalERABsAdmittedItemExtIEsExtFieldMarshalAPERTo(&value, bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v s06.ERABsAdmittedItemExtIEsExtField, state aper.DecodeState) (s06.ERABsAdmittedItemExtIEsExtField, aper.Snapshot) {
		s := aper.SemanticCaptureFor(state)
		f := s.Begin()
		s07.X2apInternalERABsAdmittedItemExtIEsValuecaptureX2APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s06.ERABsAdmittedItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s07.X2apInternalERABsAdmittedItemExtIEsValuecompareX2APProtocolExtensionField(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}}
}
