// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ERABsAdmittedItemExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[ERABsAdmittedItemExtIEsValue]].
type ERABsAdmittedItemExtIEsExtFieldValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(s06.ERABsAdmittedItemExtIEsExtField, aper.DecodeState) (s06.ERABsAdmittedItemExtIEsExtField, aper.Snapshot)
	compare func(s06.ERABsAdmittedItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (s06.ERABsAdmittedItemExtIEsExtField, error)
	encode  func(s06.ERABsAdmittedItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
}
