// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// New validates the source value and constructs a value without received replay state.
func (c ERABsToBeSetupItemIEFieldValueCodec) New(value s11.ERABsToBeSetupItemIEField) (ERABsToBeSetupItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABsToBeSetupItemIEFieldAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABsToBeSetupItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABsToBeSetupItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ERABsToBeSetupItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}
