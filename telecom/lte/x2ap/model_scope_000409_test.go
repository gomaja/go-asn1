// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// Codec returns the complete APER codec for the bound source value.
func (b ErrorIndicationUnsuccessfulBinding) Codec() s20.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s20.ErrorIndicationValueCodec{}
	}
	return s20.X2apInternalConstructT25ErrorIndicationValueCodecF4pathF6decodeF6encodeF7captureF7compareF7context(aper.Path(b.info.Rule.Assignment.Assignment), b.decode, func(value s20.ErrorIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, b.capture, b.compare, b.context)

}
