// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// ReceivedForm returns the retained wire representation, if present.
func (v ERABsAdmittedItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}
