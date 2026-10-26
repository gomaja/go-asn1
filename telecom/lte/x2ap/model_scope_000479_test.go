// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ERABsAdmittedItemExtIEsExtFieldAPERValue is the concrete APERValue[ERABsAdmittedItemExtIEsExtField].
type ERABsAdmittedItemExtIEsExtFieldAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         s06.ERABsAdmittedItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}
