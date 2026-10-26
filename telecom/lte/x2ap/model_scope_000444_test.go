// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// New validates the source value and constructs a value without received replay state.
func (c Int64ValueCodec) New(value int64,

) (Int64APERValue, error) {
	if c.encode == nil {
		return Int64APERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Int64APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Int64APERValue{}, aper.OperationError(err, "Value.New")
	}
	return Int64APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}
