// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ERABsToBeSetupItemIEFieldValueCodec is the concrete ValueCodec[ERABsToBeSetupItemIEField].
type ERABsToBeSetupItemIEFieldValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(s10.ERABsToBeSetupItemIEField, aper.DecodeState) (s10.ERABsToBeSetupItemIEField, aper.Snapshot)
	compare func(s10.ERABsToBeSetupItemIEField, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (s10.ERABsToBeSetupItemIEField, error)
	encode  func(s10.ERABsToBeSetupItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
}
