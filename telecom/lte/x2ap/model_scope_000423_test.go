// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func eRABsToBeSetupItemIEValuereplayBoundFieldCodec() ERABsToBeSetupItemIEFieldValueCodec {
	return ERABsToBeSetupItemIEFieldValueCodec{decode: func(data []byte, state aper.DecodeState) (s10.ERABsToBeSetupItemIEField, error) {
		var value s10.ERABsToBeSetupItemIEField
		bb := aper.NewCompleteDecodeBuffer(data, state)
		if err := bb.SetDecodeOptionsAligned(state); err != nil {
			return value, err
		}
		if err := s10.X2apInternalERABsToBeSetupItemIEFieldUnmarshalAPERFrom(&value, bb); err != nil {
			return value, err
		}
		_, err := aper.CaptureFinalBits(bb, "ProtocolIEField")
		return value, err
	}, encode: func(value s10.ERABsToBeSetupItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := s10.X2apInternalERABsToBeSetupItemIEFieldMarshalAPERTo(&value, bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v s10.ERABsToBeSetupItemIEField, state aper.DecodeState) (s10.ERABsToBeSetupItemIEField, aper.Snapshot) {
		s := aper.SemanticCaptureFor(state)
		f := s.Begin()
		s10.X2apInternalERABsToBeSetupItemIEValuecaptureX2APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s10.ERABsToBeSetupItemIEField, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s10.X2apInternalERABsToBeSetupItemIEValuecompareX2APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}}
}
