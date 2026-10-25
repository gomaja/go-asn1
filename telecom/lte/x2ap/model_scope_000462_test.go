// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// New validates the source value and constructs a value without received replay state.
func (c ErrorIndicationIEFieldValueCodec) New(value s11.ErrorIndicationIEField) (ErrorIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}
