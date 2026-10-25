// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ErrorIndicationIEFieldValueCodec) EncodeAPER(value ErrorIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, plan)
	}
	return c.encodeUnplanned(value.Value, fresh, budget)
}
