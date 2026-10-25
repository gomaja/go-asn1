// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// WithoutReplay returns a copy that encodes without received replay state.
func (v ERABsAdmittedItemExtIEsExtFieldAPERValue) WithoutReplay() ERABsAdmittedItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
