// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ErrorIndicationUnsuccessfulBinding is the concrete UnsuccessfulBinding[ErrorIndication].
type ErrorIndicationUnsuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(s20.ErrorIndication, aper.DecodeState) (s20.ErrorIndication, aper.Snapshot)
	compare  func(s20.ErrorIndication, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s20.ErrorIndication, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*s20.ErrorIndication, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (s20.ErrorIndication, error)
	inject   func(s20.ErrorIndication) s14.UnsuccessfulValue
}
