// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ERABsToBeSetupItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABsToBeSetupItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ERABsToBeSetupItemIEFieldAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ERABsToBeSetupItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ERABsToBeSetupItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ERABsToBeSetupItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
}
