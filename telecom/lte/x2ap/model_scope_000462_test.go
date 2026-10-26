// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// New validates the source value and constructs a value without received replay state.
func (c ERABsAdmittedItemExtIEsExtFieldValueCodec) New(value s06.ERABsAdmittedItemExtIEsExtField) (ERABsAdmittedItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ERABsAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABsAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABsAdmittedItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ERABsAdmittedItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}
