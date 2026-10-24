// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func errorIndicationIEValuereplayBoundFieldCodec() ErrorIndicationIEFieldValueCodec {
	return ErrorIndicationIEFieldValueCodec{decode: func(data []byte, state aper.DecodeState) (s11.ErrorIndicationIEField, error) {
		var value s11.ErrorIndicationIEField
		bb := aper.NewCompleteDecodeBuffer(data, state)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			return value, err
		}
		if err := s11.X2apInternalErrorIndicationIEFieldUnmarshalAPERFrom(&value, bb); err != nil {
			return value, err
		}
		_, err := aper.CaptureFinalBits(bb, "ProtocolIEField")
		return value, err
	}, encode: func(value s11.ErrorIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := s11.X2apInternalErrorIndicationIEFieldMarshalAPERTo(&value, bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v s11.ErrorIndicationIEField, state aper.DecodeState) (s11.ErrorIndicationIEField, aper.Snapshot) {
		s := aper.SemanticCaptureFor(state)
		f := s.Begin()
		s12.X2apInternalErrorIndicationIEValuecaptureX2APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s11.ErrorIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s12.X2apInternalErrorIndicationIEValuecompareX2APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}}
}
