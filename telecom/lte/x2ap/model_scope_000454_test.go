// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func (c ERABsToBeSetupItemIEFieldValueCodec) encodeChanged(value s11.ERABsToBeSetupItemIEField, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
