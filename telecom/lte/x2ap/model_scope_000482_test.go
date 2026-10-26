// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ErrorIndicationIEFieldAPERValue is the concrete APERValue[ErrorIndicationIEField].
type ErrorIndicationIEFieldAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         s11.ErrorIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}
