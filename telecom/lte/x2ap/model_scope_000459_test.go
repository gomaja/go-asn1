// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func (c ERABsAdmittedItemExtIEsExtFieldValueCodec) encodeUnplanned(value s06.ERABsAdmittedItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
