// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ErrorIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ErrorIndicationIEValue]].
type ErrorIndicationIEFieldValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(s11.ErrorIndicationIEField, aper.DecodeState) (s11.ErrorIndicationIEField, aper.Snapshot)
	compare func(s11.ErrorIndicationIEField, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (s11.ErrorIndicationIEField, error)
	encode  func(s11.ErrorIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
}
