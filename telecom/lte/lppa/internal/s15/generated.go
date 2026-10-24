// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s15 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s15

import (
	q7 "fmt"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q16 "math/big"
)

func BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.TDDConfigurationExtIEsExtContainer, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.TDDConfigurationExtIEsExtContainer, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}

// AddOTDOACellsValueCodec is the concrete ValueCodec[AddOTDOACells].
type AddOTDOACellsValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AddOTDOACells, q5.DecodeState,

	) (AddOTDOACells, q5.Snapshot,

	)
	compare func(AddOTDOACells, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AddOTDOACells,

		error)
	encode func(AddOTDOACells,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AddOTDOACellsValueCodec) New(value AddOTDOACells,

) (AddOTDOACellsAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellsAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AddOTDOACellsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AddOTDOACellsAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AddOTDOACellsValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AddOTDOACellsAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellsAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AddOTDOACellsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellsAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AddOTDOACellsAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AddOTDOACellsValueCodec) EncodeAPER(value AddOTDOACellsAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c AddOTDOACellsValueCodec) encodeBudget(value AddOTDOACells,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellsValueCodec) encodeChanged(value AddOTDOACells,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// AddOTDOACellInformationValueCodec is the concrete ValueCodec[AddOTDOACellInformation].
type AddOTDOACellInformationValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AddOTDOACellInformation, q5.DecodeState,

	) (AddOTDOACellInformation, q5.Snapshot,

	)
	compare func(AddOTDOACellInformation, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AddOTDOACellInformation,

		error)
	encode func(AddOTDOACellInformation,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AddOTDOACellInformationValueCodec) New(value AddOTDOACellInformation,

) (AddOTDOACellInformationAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellInformationAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AddOTDOACellInformationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellInformationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AddOTDOACellInformationAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AddOTDOACellInformationValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AddOTDOACellInformationAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellInformationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AddOTDOACellInformationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellInformationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellInformationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AddOTDOACellInformationAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AddOTDOACellInformationValueCodec) EncodeAPER(value AddOTDOACellInformationAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c AddOTDOACellInformationValueCodec) encodeBudget(value AddOTDOACellInformation,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellInformationValueCodec) encodeChanged(value AddOTDOACellInformation,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// AddOTDOACellsElemValueCodec is the concrete ValueCodec[AddOTDOACellsElem].
type AddOTDOACellsElemValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AddOTDOACellsElem, q5.DecodeState,

	) (AddOTDOACellsElem, q5.Snapshot,

	)
	compare func(AddOTDOACellsElem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AddOTDOACellsElem,

		error)
	encode func(AddOTDOACellsElem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AddOTDOACellsElemValueCodec) New(value AddOTDOACellsElem,

) (AddOTDOACellsElemAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellsElemAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AddOTDOACellsElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellsElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AddOTDOACellsElemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AddOTDOACellsElemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AddOTDOACellsElemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellsElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AddOTDOACellsElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellsElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellsElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AddOTDOACellsElemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AddOTDOACellsElemValueCodec) EncodeAPER(value AddOTDOACellsElemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c AddOTDOACellsElemValueCodec) encodeBudget(value AddOTDOACellsElem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellsElemValueCodec) encodeChanged(value AddOTDOACellsElem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// AssistanceInformationControlValueCodec is the concrete ValueCodec[AssistanceInformationControl].
type AssistanceInformationControlValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AssistanceInformationControl, q5.DecodeState,

	) (AssistanceInformationControl, q5.Snapshot,

	)
	compare func(AssistanceInformationControl, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AssistanceInformationControl,

		error)
	encode func(AssistanceInformationControl,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationControlValueCodec) New(value AssistanceInformationControl,

) (AssistanceInformationControlAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationControlAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AssistanceInformationControlAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationControlAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AssistanceInformationControlValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AssistanceInformationControlAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationControlAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AssistanceInformationControlAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationControlAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationControlAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AssistanceInformationControlAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationControlValueCodec) EncodeAPER(value AssistanceInformationControlAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c AssistanceInformationControlValueCodec) encodeBudget(value AssistanceInformationControl,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationControlValueCodec) encodeChanged(value AssistanceInformationControl,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOACellInformationValueCodec is the concrete ValueCodec[OTDOACellInformation].
type OTDOACellInformationValueCodec struct {
	context q6.BridgeCodecContext
	capture func(OTDOACellInformation, q5.DecodeState,

	) (OTDOACellInformation, q5.Snapshot,

	)
	compare func(OTDOACellInformation, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (OTDOACellInformation,

		error)
	encode func(OTDOACellInformation,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOACellInformationValueCodec) New(value OTDOACellInformation,

) (OTDOACellInformationAPERValue, error) {
	if c.encode == nil {
		return OTDOACellInformationAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOACellInformationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellInformationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOACellInformationAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOACellInformationValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOACellInformationAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellInformationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOACellInformationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellInformationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellInformationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOACellInformationAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOACellInformationValueCodec) EncodeAPER(value OTDOACellInformationAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c OTDOACellInformationValueCodec) encodeBudget(value OTDOACellInformation,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellInformationValueCodec) encodeChanged(value OTDOACellInformation,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOACellInformationItemValueCodec is the concrete ValueCodec[OTDOACellInformationItem].
type OTDOACellInformationItemValueCodec struct {
	context q6.BridgeCodecContext
	capture func(OTDOACellInformationItem, q5.DecodeState,

	) (OTDOACellInformationItem, q5.Snapshot,

	)
	compare func(OTDOACellInformationItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (OTDOACellInformationItem,

		error)
	encode func(OTDOACellInformationItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOACellInformationItemValueCodec) New(value OTDOACellInformationItem,

) (OTDOACellInformationItemAPERValue, error) {
	if c.encode == nil {
		return OTDOACellInformationItemAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOACellInformationItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellInformationItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOACellInformationItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOACellInformationItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOACellInformationItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellInformationItemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOACellInformationItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellInformationItemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellInformationItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOACellInformationItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOACellInformationItemValueCodec) EncodeAPER(value OTDOACellInformationItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c OTDOACellInformationItemValueCodec) encodeBudget(value OTDOACellInformationItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellInformationItemValueCodec) encodeChanged(value OTDOACellInformationItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TDDConfigurationValueCodec is the concrete ValueCodec[TDDConfiguration].
type TDDConfigurationValueCodec struct {
	context q6.BridgeCodecContext
	capture func(TDDConfiguration, q5.DecodeState,

	) (TDDConfiguration, q5.Snapshot,

	)
	compare func(TDDConfiguration, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (TDDConfiguration,

		error)
	encode func(TDDConfiguration,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TDDConfigurationValueCodec) New(value TDDConfiguration,

) (TDDConfigurationAPERValue, error) {
	if c.encode == nil {
		return TDDConfigurationAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TDDConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TDDConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TDDConfigurationAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TDDConfigurationValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TDDConfigurationAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TDDConfigurationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TDDConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TDDConfigurationAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TDDConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TDDConfigurationAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TDDConfigurationValueCodec) EncodeAPER(value TDDConfigurationAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c TDDConfigurationValueCodec) encodeBudget(value TDDConfiguration,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TDDConfigurationValueCodec) encodeChanged(value TDDConfiguration,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(fields q8.AssistanceInformationControlIEContainer, rows []q6.FieldInfo, path string, budget *q5.DecodeBudget,

) q9.ValidationReport {
	report := func() q9.ValidationReport {
		sealed := q9.ValidationReport{Complete: true}
		*q9.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q9.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q9.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q9.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q7.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q8.BridgeAssistanceInformationControlIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q8.BridgeAssistanceInformationControlIEValueMethodRule(field.Value)
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q7.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q4.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q4.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q7.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q4.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			q9.BridgeValidationReportMethodAddDeferred(&report, q6.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q9.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeSystemInformationExtIEsValueValidateLPPaExtensionContainer(fields q4.SystemInformationExtIEsExtContainer, rows []q6.FieldInfo, path string, budget *q5.DecodeBudget) q9.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q4.SystemInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q9.ValidationReport {
			sealed := q9.ValidationReport{}
			*q9.BridgeValidationReportFieldErr(&sealed) = err
			*q9.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q4.SystemInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSystemInformationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// assistanceInformationControlIEValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.AssistanceInformationControlIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.AssistanceInformationControlIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

// systemInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SystemInformationExtIEsValue].
type SystemInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q10.SystemInformationExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q10.SystemInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.TDDConfigurationExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgeTDDConfigurationExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q10.BridgeTDDConfigurationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q10.BridgeTDDConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q10.BridgeTDDConfigurationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v), *q4.BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionField(v *q4.TDDConfigurationExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q10.BridgeTDDConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v), *q4.BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// AddOTDOACellsAPERValue is the concrete APERValue[AddOTDOACells].
type AddOTDOACellsAPERValue struct {
	context q6.BridgeCodecContext
	Value   AddOTDOACells

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AddOTDOACellsAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AddOTDOACellsAPERValue) WithoutReplay() AddOTDOACellsAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellInformationAPERValue is the concrete APERValue[AddOTDOACellInformation].
type AddOTDOACellInformationAPERValue struct {
	context q6.BridgeCodecContext
	Value   AddOTDOACellInformation

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AddOTDOACellInformationAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AddOTDOACellInformationAPERValue) WithoutReplay() AddOTDOACellInformationAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellsElemAPERValue is the concrete APERValue[AddOTDOACellsElem].
type AddOTDOACellsElemAPERValue struct {
	context q6.BridgeCodecContext
	Value   AddOTDOACellsElem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AddOTDOACellsElemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AddOTDOACellsElemAPERValue) WithoutReplay() AddOTDOACellsElemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationControlAPERValue is the concrete APERValue[AssistanceInformationControl].
type AssistanceInformationControlAPERValue struct {
	context q6.BridgeCodecContext
	Value   AssistanceInformationControl

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationControlAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AssistanceInformationControlAPERValue) WithoutReplay() AssistanceInformationControlAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellInformationAPERValue is the concrete APERValue[OTDOACellInformation].
type OTDOACellInformationAPERValue struct {
	context q6.BridgeCodecContext
	Value   OTDOACellInformation

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOACellInformationAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOACellInformationAPERValue) WithoutReplay() OTDOACellInformationAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellInformationItemAPERValue is the concrete APERValue[OTDOACellInformationItem].
type OTDOACellInformationItemAPERValue struct {
	context q6.BridgeCodecContext
	Value   OTDOACellInformationItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOACellInformationItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOACellInformationItemAPERValue) WithoutReplay() OTDOACellInformationItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TDDConfigurationAPERValue is the concrete APERValue[TDDConfiguration].
type TDDConfigurationAPERValue struct {
	context q6.BridgeCodecContext
	Value   TDDConfiguration

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TDDConfigurationAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TDDConfigurationAPERValue) WithoutReplay() TDDConfigurationAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeSystemInformationExtIEsValueValidateLPPaIEContainer(fields q4.SystemInformationExtIEsIEContainer, rows []q6.FieldInfo, path string, budget *q5.DecodeBudget,

) q9.ValidationReport {
	report := func() q9.ValidationReport {
		sealed := q9.ValidationReport{Complete: true}
		*q9.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q9.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q9.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q9.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q7.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q10.BridgeSystemInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q10.BridgeSystemInformationExtIEsValueMethodRule(field.Value)
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q7.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q4.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q4.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q7.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q4.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			q9.BridgeValidationReportMethodAddIssue(&report, q9.ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q4.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q5.SourceRule{q4.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			q9.BridgeValidationReportMethodAddDeferred(&report, q6.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q9.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

type AddOTDOACells = []AddOTDOACellsElem
type AddOTDOACellInformation = []OTDOACellInformationItem
type OTDOACellInformation = []OTDOACellInformationItem

// OTDOACellInformationItem represents the ASN.1 CHOICE type OTDOACell-Information-Item.
type OTDOACellInformationItem struct {
	knownOpenBytes             uint64
	replay                     q5.Snapshot
	stream                     q5.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              q5.WireSpan
	Choice                     int
	perPadding                 q5.CompletePadding                    `json:"-"`
	perOpenTypePadding         q5.CompletePadding                    `json:"-"`
	UnknownExtension           *q5.ChoiceExtension                   `json:"UnknownExtension,omitempty"`
	PCI                        q6.PCI                                `json:"PCI,omitzero"`
	CellId                     *q12.ECGI                             `json:"CellId,omitempty"`
	TAC                        *q6.TAC                               `json:"TAC,omitempty"`
	EARFCN                     q6.EARFCN                             `json:"EARFCN,omitzero"`
	PRSBandwidth               *q6.PRSBandwidth                      `json:"PRSBandwidth,omitempty"`
	PRSConfigurationIndex      q6.PRSConfigurationIndex              `json:"PRSConfigurationIndex,omitzero"`
	CPLength                   *q6.CPLength                          `json:"CPLength,omitempty"`
	NumberOfDlFrames           *q6.NumberOfDlFrames                  `json:"NumberOfDlFrames,omitempty"`
	NumberOfAntennaPorts       *q6.NumberOfAntennaPorts              `json:"NumberOfAntennaPorts,omitempty"`
	SFNInitialisationTime      *q6.SFNInitialisationTime             `json:"SFNInitialisationTime,omitempty"`
	EUTRANAccessPointPosition  *q13.EUTRANAccessPointPosition        `json:"EUTRANAccessPointPosition,omitempty"`
	PRSMutingConfiguration     *q14.PRSMutingConfiguration           `json:"PRSMutingConfiguration,omitempty"`
	Prsid                      q6.PRSID                              `json:"Prsid,omitzero"`
	Tpid                       q6.TPID                               `json:"Tpid,omitzero"`
	TpType                     *q6.TPType                            `json:"TpType,omitempty"`
	NumberOfDlFramesExtended   q6.NumberOfDlFramesExtended           `json:"NumberOfDlFramesExtended,omitzero"`
	CrsCPlength                *q6.CPLength                          `json:"CrsCPlength,omitempty"`
	MBSFNsubframeConfiguration q9.MBSFNsubframeConfiguration         `json:"MBSFNsubframeConfiguration,omitzero"`
	NPRSConfiguration          *q15.NPRSConfiguration                `json:"NPRSConfiguration,omitempty"`
	OffsetNBChanneltoEARFCN    *q6.OffsetNBChanneltoEARFCN           `json:"OffsetNBChanneltoEARFCN,omitempty"`
	OperationModeInfo          *q6.OperationModeInfo                 `json:"OperationModeInfo,omitempty"`
	NPRSID                     *q16.Int                              `json:"NPRSID,omitempty"`
	DLBandwidth                *q6.DLBandwidth                       `json:"DLBandwidth,omitempty"`
	PRSOccasionGroup           *q6.PRSOccasionGroup                  `json:"PRSOccasionGroup,omitempty"`
	PRSFreqHoppingConfig       *q14.PRSFrequencyHoppingConfiguration `json:"PRSFreqHoppingConfig,omitempty"`
	RepetitionNumberofSIB1NB   *q6.RepetitionNumberofSIB1NB          `json:"RepetitionNumberofSIB1NB,omitempty"`
	NPRSSequenceInfo           q6.NPRSSequenceInfo                   `json:"NPRSSequenceInfo,omitzero"`
	NPRSType2                  *q15.NPRSConfiguration                `json:"NPRSType2,omitempty"`
	TddConfiguration           *TDDConfiguration                     `json:"TddConfiguration,omitempty"`
}

// TDDConfiguration represents the ASN.1 type TDDConfiguration (SEQUENCE).
type TDDConfiguration struct {
	replay             q5.Snapshot
	stream             q5.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q5.WireSpan
	SubframeAssignment int64                                 `asn1:"tag:0,context,implicit"`
	IEExtensions       q4.TDDConfigurationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                  `asn1:"-" json:"-"`
	extCount           int64                                 `asn1:"-" json:"-"`
	extPresent         []bool                                `asn1:"-" json:"-"`
	extData            [][]byte                              `asn1:"-" json:"-"`
	perPadding         q5.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding      []q5.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin          []q5.OpaqueOrigin
	extWire            []q5.WireSpan
}

// AddOTDOACellsElem represents the ASN.1 type Add-OTDOACells-Elem (SEQUENCE).
type AddOTDOACellsElem struct {
	replay                q5.Snapshot
	stream                q5.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         q5.WireSpan
	AddOTDOACellInfo      AddOTDOACellInformation             `asn1:"tag:0,context,implicit"`
	addOTDOACellInfoIndef bool                                `asn1:"-" json:"-"`
	IEExtensions          q10.AddOTDOACellsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                `asn1:"-" json:"-"`
	extCount              int64                               `asn1:"-" json:"-"`
	extPresent            []bool                              `asn1:"-" json:"-"`
	extData               [][]byte                            `asn1:"-" json:"-"`
	perPadding            q5.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding         []q5.CompletePadding                `asn1:"-" json:"-"`
	extOrigin             []q5.OpaqueOrigin
	extWire               []q5.WireSpan
}
type BridgeAsn1cAPERAddOTDOACellsListValue struct{ Value AddOTDOACells }
type BridgeAsn1cAPERAddOTDOACellInformationListValue struct{ Value AddOTDOACellInformation }
type BridgeAsn1cAPEROTDOACellInformationListValue struct{ Value OTDOACellInformation }

// MarshalAPER encodes OTDOACellInformationItem to APER format.
func (v *OTDOACellInformationItem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *OTDOACellInformationItem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return q7.Errorf("%s known choice %d and unknown extension are both selected", "OTDOACellInformationItem:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q7.Errorf("%s extension index %d must be non-negative", "OTDOACellInformationItem:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 18 {
			return q7.Errorf("%s extension index %d is known to this schema", "OTDOACellInformationItem:", v.UnknownExtension.Index())
		}
		if err := q5.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := q5.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return q7.Errorf("%s choice %d must be positive", "OTDOACellInformationItem:", v.Choice)
	}
	isExtension := v.Choice > 11
	if err := q5.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 11 {
			return q7.Errorf("extension choice index outside root")
		}
		if err := q5.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-11-1)); err != nil {
			return err
		}
		inner := q5.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case q6.OTDOACellInformationItemChoicePRSMutingConfiguration:
			if v.PRSMutingConfiguration == nil {
				return q7.Errorf("choice alternative pRSMutingConfiguration is nil")
			}
			if err := q14.BridgePRSMutingConfigurationMethodMarshalAPERTo(v.PRSMutingConfiguration, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding pRSMutingConfiguration: %w", err)
			}
		case q6.OTDOACellInformationItemChoicePrsid:
			if err := q5.EncodeIntegerBigBoundsAligned(inner, v.Prsid, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true); err != nil {
				return q7.Errorf("encoding prsid: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceTpid:
			if err := q5.EncodeIntegerBigBoundsAligned(inner, v.Tpid, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true); err != nil {
				return q7.Errorf("encoding tpid: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceTpType:
			if v.TpType == nil {
				return q7.Errorf("choice alternative tpType is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.TpType), 1, true); err != nil {
				return q7.Errorf("encoding tpType: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			if err := q5.EncodeIntegerBigBoundsAligned(inner, v.NumberOfDlFramesExtended, q6.BridgeAsn1IntegerBound2, q6.BridgeAsn1IntegerBound9, true); err != nil {
				return q7.Errorf("encoding numberOfDlFrames-Extended: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceCrsCPlength:
			if v.CrsCPlength == nil {
				return q7.Errorf("choice alternative crsCPlength is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.CrsCPlength), 2, true); err != nil {
				return q7.Errorf("encoding crsCPlength: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			if err := q5.EncodeCollection(inner, int64(len(v.MBSFNsubframeConfiguration)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_mbsfnsubframeconfiguration < 0 || fragmentOffset_mbsfnsubframeconfiguration > int64(len(v.MBSFNsubframeConfiguration)) || fragmentLength_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration > int64(len(v.MBSFNsubframeConfiguration[fragmentOffset_mbsfnsubframeconfiguration:])) {
					return q7.Errorf("collection fragment outside value")
				}
				for _, elem := range v.MBSFNsubframeConfiguration[fragmentOffset_mbsfnsubframeconfiguration : fragmentOffset_mbsfnsubframeconfiguration+fragmentLength_mbsfnsubframeconfiguration] {
					if err := q9.BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(&elem, inner, len(fresh) != 0 && fresh[0]); err != nil {
						return q7.Errorf("encoding mBSFNsubframeConfiguration element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return q7.Errorf("encoding mBSFNsubframeConfiguration: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceNPRSConfiguration:
			if v.NPRSConfiguration == nil {
				return q7.Errorf("choice alternative nPRSConfiguration is nil")
			}
			if err := q15.BridgeNPRSConfigurationMethodMarshalAPERTo(v.NPRSConfiguration, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding nPRSConfiguration: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			if v.OffsetNBChanneltoEARFCN == nil {
				return q7.Errorf("choice alternative offsetNBChanneltoEARFCN is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.OffsetNBChanneltoEARFCN), 21, true); err != nil {
				return q7.Errorf("encoding offsetNBChanneltoEARFCN: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceOperationModeInfo:
			if v.OperationModeInfo == nil {
				return q7.Errorf("choice alternative operationModeInfo is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.OperationModeInfo), 3, true); err != nil {
				return q7.Errorf("encoding operationModeInfo: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceNPRSID:
			if err := q5.EncodeIntegerBigBoundsAligned(inner, v.NPRSID, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true); err != nil {
				return q7.Errorf("encoding nPRS-ID: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceDLBandwidth:
			if v.DLBandwidth == nil {
				return q7.Errorf("choice alternative dL-Bandwidth is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.DLBandwidth), 6, true); err != nil {
				return q7.Errorf("encoding dL-Bandwidth: %w", err)
			}
		case q6.OTDOACellInformationItemChoicePRSOccasionGroup:
			if v.PRSOccasionGroup == nil {
				return q7.Errorf("choice alternative pRSOccasionGroup is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.PRSOccasionGroup), 7, true); err != nil {
				return q7.Errorf("encoding pRSOccasionGroup: %w", err)
			}
		case q6.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			if v.PRSFreqHoppingConfig == nil {
				return q7.Errorf("choice alternative pRSFreqHoppingConfig is nil")
			}
			if err := q14.BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERTo(v.PRSFreqHoppingConfig, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding pRSFreqHoppingConfig: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			if v.RepetitionNumberofSIB1NB == nil {
				return q7.Errorf("choice alternative repetitionNumberofSIB1-NB is nil")
			}
			if err := q5.EncodeEnumeratedAligned(inner, int64(*v.RepetitionNumberofSIB1NB), 3, true); err != nil {
				return q7.Errorf("encoding repetitionNumberofSIB1-NB: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceNPRSSequenceInfo:
			if err := q5.EncodeIntegerBigBoundsAligned(inner, v.NPRSSequenceInfo, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound11, true); err != nil {
				return q7.Errorf("encoding nPRSSequenceInfo: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceNPRSType2:
			if v.NPRSType2 == nil {
				return q7.Errorf("choice alternative nPRSType2 is nil")
			}
			if err := q15.BridgeNPRSConfigurationMethodMarshalAPERTo(v.NPRSType2, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding nPRSType2: %w", err)
			}
		case q6.OTDOACellInformationItemChoiceTddConfiguration:
			if v.TddConfiguration == nil {
				return q7.Errorf("choice alternative tddConfiguration is nil")
			}
			if err := v.TddConfiguration.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding tddConfiguration: %w", err)
			}
		default:
			return q7.Errorf("unknown OTDOACellInformationItem extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.perOpenTypePadding)
		if err != nil {
			return err
		}
		if err := q5.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q7.Errorf("choice index outside root")
	}
	if err := q5.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 10); err != nil {
		return err
	}
	switch v.Choice {
	case q6.OTDOACellInformationItemChoicePCI:
		if err := q5.EncodeIntegerBigBoundsAligned(bb, v.PCI, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound17, true); err != nil {
			return q7.Errorf("encoding pCI: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceCellId:
		if v.CellId == nil {
			return q7.Errorf("choice alternative cellId is nil")
		}
		if err := q12.BridgeECGIMethodMarshalAPERTo(v.CellId, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q7.Errorf("encoding cellId: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceTAC:
		if v.TAC == nil {
			return q7.Errorf("choice alternative tAC is nil")
		}
		if err := q5.EncodeOctetStringAligned(bb, []byte(*v.TAC), 2, 2, true); err != nil {
			return q7.Errorf("encoding tAC: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceEARFCN:
		if err := q5.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound20, true); err != nil {
			return q7.Errorf("encoding eARFCN: %w", err)
		}
	case q6.OTDOACellInformationItemChoicePRSBandwidth:
		if v.PRSBandwidth == nil {
			return q7.Errorf("choice alternative pRS-Bandwidth is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.PRSBandwidth), 6, true); err != nil {
			return q7.Errorf("encoding pRS-Bandwidth: %w", err)
		}
	case q6.OTDOACellInformationItemChoicePRSConfigurationIndex:
		if err := q5.EncodeIntegerBigBoundsAligned(bb, v.PRSConfigurationIndex, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true); err != nil {
			return q7.Errorf("encoding pRS-ConfigurationIndex: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceCPLength:
		if v.CPLength == nil {
			return q7.Errorf("choice alternative cPLength is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.CPLength), 2, true); err != nil {
			return q7.Errorf("encoding cPLength: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfDlFrames:
		if v.NumberOfDlFrames == nil {
			return q7.Errorf("choice alternative numberOfDlFrames is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.NumberOfDlFrames), 4, true); err != nil {
			return q7.Errorf("encoding numberOfDlFrames: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		if v.NumberOfAntennaPorts == nil {
			return q7.Errorf("choice alternative numberOfAntennaPorts is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.NumberOfAntennaPorts), 2, true); err != nil {
			return q7.Errorf("encoding numberOfAntennaPorts: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceSFNInitialisationTime:
		if v.SFNInitialisationTime == nil {
			return q7.Errorf("choice alternative sFNInitialisationTime is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.SFNInitialisationTime.Bytes, v.SFNInitialisationTime.BitLength, 64, 64, true); err != nil {
			return q7.Errorf("encoding sFNInitialisationTime: %w", err)
		}
	case q6.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		if v.EUTRANAccessPointPosition == nil {
			return q7.Errorf("choice alternative e-UTRANAccessPointPosition is nil")
		}
		if err := q13.BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v.EUTRANAccessPointPosition, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q7.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	default:
		return q7.Errorf("unknown OTDOACellInformationItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes OTDOACellInformationItem from APER format.
func (v *OTDOACellInformationItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACellInformationItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellInformationItem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q17.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q17.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	padding, err := q5.CaptureFinalBits(bb, "OTDOACellInformationItem")
	if err != nil {
		return q17.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *OTDOACellInformationItem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellInformationItem{}
	isExtension, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q5.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q17.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q5.DecodeChoiceExtensionAligned(bb, extIdx, 18)
		if extIdx < 18 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q17.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 18 {
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)
			v.
				stream.RecordUsage(replayUsage,

				bb)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(11) {
			return q7.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 11 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case q6.OTDOACellInformationItemChoicePRSMutingConfiguration:
			extensionPath = "PRSMutingConfiguration"
			var dec_prsmutingconfiguration q14.PRSMutingConfiguration
			if err := q14.BridgePRSMutingConfigurationMethodUnmarshalAPERFrom(&dec_prsmutingconfiguration, inner); err != nil {
				return q17.WrapDecodePath(err, "PRSMutingConfiguration")
			}
			if err := q5.ChargeValue(inner, dec_prsmutingconfiguration); err != nil {
				return err
			}
			v.PRSMutingConfiguration = &dec_prsmutingconfiguration
		case q6.OTDOACellInformationItemChoicePrsid:
			extensionPath = "Prsid"
			val_prsid, err := q5.DecodeIntegerBigBoundsAligned(inner, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return q17.WrapDecodePath(err, "Prsid")
			}
			v.Prsid = val_prsid
		case q6.OTDOACellInformationItemChoiceTpid:
			extensionPath = "Tpid"
			val_tpid, err := q5.DecodeIntegerBigBoundsAligned(inner, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return q17.WrapDecodePath(err, "Tpid")
			}
			v.Tpid = val_tpid
		case q6.OTDOACellInformationItemChoiceTpType:
			extensionPath = "TpType"
			val_tptype, err := q5.DecodeEnumeratedAligned(inner, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "TpType"})
			if err != nil {
				return q17.WrapDecodePath(err, "TpType")
			}
			tmp_tptype := q6.TPType(val_tptype)
			if err := q5.ChargeValue(inner, tmp_tptype); err != nil {
				return err
			}
			v.TpType = (*q6.TPType)(bb.OwnInt64(int64(tmp_tptype)))
		case q6.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			extensionPath = "NumberOfDlFramesExtended"
			val_numberofdlframesextended, err := q5.DecodeIntegerBigBoundsAligned(inner, q6.BridgeAsn1IntegerBound2, q6.BridgeAsn1IntegerBound9, true)
			if err != nil {
				return q17.WrapDecodePath(err, "NumberOfDlFramesExtended")
			}
			v.NumberOfDlFramesExtended = val_numberofdlframesextended
		case q6.OTDOACellInformationItemChoiceCrsCPlength:
			extensionPath = "CrsCPlength"
			val_crscplength, err := q5.DecodeEnumeratedAligned(inner, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CrsCPlength"})
			if err != nil {
				return q17.WrapDecodePath(err, "CrsCPlength")
			}
			tmp_crscplength := q6.CPLength(val_crscplength)
			if err := q5.ChargeValue(inner, tmp_crscplength); err != nil {
				return err
			}
			v.CrsCPlength = (*q6.CPLength)(bb.OwnInt64(int64(tmp_crscplength)))
		case q6.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			extensionPath = "MBSFNsubframeConfiguration"
			tmp_mbsfnsubframeconfiguration := make(q9.MBSFNsubframeConfiguration, 0)
			_, errCollection_mbsfnsubframeconfiguration := q5.DecodeCollection(inner, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
				if fragmentOffset_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration > int64(^uint(0)>>1) || fragmentOffset_mbsfnsubframeconfiguration > int64(^uint(0)>>1)-fragmentLength_mbsfnsubframeconfiguration {
					return q7.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_mbsfnsubframeconfiguration; i++ {
					var elem q9.MBSFNsubframeConfigurationValue
					if err := q9.BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(&elem, inner); err != nil {
						return q17.WrapDecodePath(err, q7.Sprintf("MBSFNsubframeConfiguration[%d]", fragmentOffset_mbsfnsubframeconfiguration+i))
					}
					if next, err := q5.AppendValues(inner, tmp_mbsfnsubframeconfiguration, elem); err != nil {
						return err
					} else {
						tmp_mbsfnsubframeconfiguration = next
					}
				}
				return nil
			})
			if errCollection_mbsfnsubframeconfiguration != nil {
				return q17.WrapDecodePath(errCollection_mbsfnsubframeconfiguration, "MBSFNsubframeConfiguration")
			}
			v.MBSFNsubframeConfiguration = tmp_mbsfnsubframeconfiguration
		case q6.OTDOACellInformationItemChoiceNPRSConfiguration:
			extensionPath = "NPRSConfiguration"
			recoveryMark_nprsconfiguration := inner.RecoveryComponent("NPRSConfiguration")
			var dec_nprsconfiguration q15.NPRSConfiguration
			if err := q15.BridgeNPRSConfigurationMethodUnmarshalAPERFrom(&dec_nprsconfiguration, inner); err != nil {
				return q17.WrapDecodePath(err, "NPRSConfiguration")
			}
			if err := q5.ChargeValue(inner, dec_nprsconfiguration); err != nil {
				return err
			}
			v.NPRSConfiguration = &dec_nprsconfiguration
			inner.LeaveComponent(recoveryMark_nprsconfiguration)
		case q6.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			extensionPath = "OffsetNBChanneltoEARFCN"
			val_offsetnbchanneltoearfcn, err := q5.DecodeEnumeratedAligned(inner, 21, true, q5.EnumerationSource{KnownExtensions: 0, Path: "OffsetNBChanneltoEARFCN"})
			if err != nil {
				return q17.WrapDecodePath(err, "OffsetNBChanneltoEARFCN")
			}
			tmp_offsetnbchanneltoearfcn := q6.OffsetNBChanneltoEARFCN(val_offsetnbchanneltoearfcn)
			if err := q5.ChargeValue(inner, tmp_offsetnbchanneltoearfcn); err != nil {
				return err
			}
			v.OffsetNBChanneltoEARFCN = (*q6.OffsetNBChanneltoEARFCN)(bb.OwnInt64(int64(tmp_offsetnbchanneltoearfcn)))
		case q6.OTDOACellInformationItemChoiceOperationModeInfo:
			extensionPath = "OperationModeInfo"
			val_operationmodeinfo, err := q5.DecodeEnumeratedAligned(inner, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "OperationModeInfo"})
			if err != nil {
				return q17.WrapDecodePath(err, "OperationModeInfo")
			}
			tmp_operationmodeinfo := q6.OperationModeInfo(val_operationmodeinfo)
			if err := q5.ChargeValue(inner, tmp_operationmodeinfo); err != nil {
				return err
			}
			v.OperationModeInfo = (*q6.OperationModeInfo)(bb.OwnInt64(int64(tmp_operationmodeinfo)))
		case q6.OTDOACellInformationItemChoiceNPRSID:
			extensionPath = "NPRSID"
			val_nprsid, err := q5.DecodeIntegerBigBoundsAligned(inner, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return q17.WrapDecodePath(err, "NPRSID")
			}
			v.NPRSID = val_nprsid
		case q6.OTDOACellInformationItemChoiceDLBandwidth:
			extensionPath = "DLBandwidth"
			val_dlbandwidth, err := q5.DecodeEnumeratedAligned(inner, 6, true, q5.EnumerationSource{KnownExtensions: 0, Path: "DLBandwidth"})
			if err != nil {
				return q17.WrapDecodePath(err, "DLBandwidth")
			}
			tmp_dlbandwidth := q6.DLBandwidth(val_dlbandwidth)
			if err := q5.ChargeValue(inner, tmp_dlbandwidth); err != nil {
				return err
			}
			v.DLBandwidth = (*q6.DLBandwidth)(bb.OwnInt64(int64(tmp_dlbandwidth)))
		case q6.OTDOACellInformationItemChoicePRSOccasionGroup:
			extensionPath = "PRSOccasionGroup"
			val_prsoccasiongroup, err := q5.DecodeEnumeratedAligned(inner, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "PRSOccasionGroup"})
			if err != nil {
				return q17.WrapDecodePath(err, "PRSOccasionGroup")
			}
			tmp_prsoccasiongroup := q6.PRSOccasionGroup(val_prsoccasiongroup)
			if err := q5.ChargeValue(inner, tmp_prsoccasiongroup); err != nil {
				return err
			}
			v.PRSOccasionGroup = (*q6.PRSOccasionGroup)(bb.OwnInt64(int64(tmp_prsoccasiongroup)))
		case q6.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			extensionPath = "PRSFreqHoppingConfig"
			recoveryMark_prsfreqhoppingconfig := inner.RecoveryComponent("PRSFreqHoppingConfig")
			var dec_prsfreqhoppingconfig q14.PRSFrequencyHoppingConfiguration
			if err := q14.BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERFrom(&dec_prsfreqhoppingconfig, inner); err != nil {
				return q17.WrapDecodePath(err, "PRSFreqHoppingConfig")
			}
			if err := q5.ChargeValue(inner, dec_prsfreqhoppingconfig); err != nil {
				return err
			}
			v.PRSFreqHoppingConfig = &dec_prsfreqhoppingconfig
			inner.LeaveComponent(recoveryMark_prsfreqhoppingconfig)
		case q6.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			extensionPath = "RepetitionNumberofSIB1NB"
			val_repetitionnumberofsib1nb, err := q5.DecodeEnumeratedAligned(inner, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "RepetitionNumberofSIB1NB"})
			if err != nil {
				return q17.WrapDecodePath(err, "RepetitionNumberofSIB1NB")
			}
			tmp_repetitionnumberofsib1nb := q6.RepetitionNumberofSIB1NB(val_repetitionnumberofsib1nb)
			if err := q5.ChargeValue(inner, tmp_repetitionnumberofsib1nb); err != nil {
				return err
			}
			v.RepetitionNumberofSIB1NB = (*q6.RepetitionNumberofSIB1NB)(bb.OwnInt64(int64(tmp_repetitionnumberofsib1nb)))
		case q6.OTDOACellInformationItemChoiceNPRSSequenceInfo:
			extensionPath = "NPRSSequenceInfo"
			val_nprssequenceinfo, err := q5.DecodeIntegerBigBoundsAligned(inner, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound11, true)
			if err != nil {
				return q17.WrapDecodePath(err, "NPRSSequenceInfo")
			}
			v.NPRSSequenceInfo = val_nprssequenceinfo
		case q6.OTDOACellInformationItemChoiceNPRSType2:
			extensionPath = "NPRSType2"
			recoveryMark_nprstype2 := inner.RecoveryComponent("NPRSType2")
			var dec_nprstype2 q15.NPRSConfiguration
			if err := q15.BridgeNPRSConfigurationMethodUnmarshalAPERFrom(&dec_nprstype2, inner); err != nil {
				return q17.WrapDecodePath(err, "NPRSType2")
			}
			if err := q5.ChargeValue(inner, dec_nprstype2); err != nil {
				return err
			}
			v.NPRSType2 = &dec_nprstype2
			inner.LeaveComponent(recoveryMark_nprstype2)
		case q6.OTDOACellInformationItemChoiceTddConfiguration:
			extensionPath = "TddConfiguration"
			recoveryMark_tddconfiguration := inner.RecoveryComponent("TddConfiguration")
			var dec_tddconfiguration TDDConfiguration
			if err := dec_tddconfiguration.unmarshalAPERFrom(inner); err != nil {
				return q17.WrapDecodePath(err, "TddConfiguration")
			}
			if err := q5.ChargeValue(inner, dec_tddconfiguration); err != nil {
				return err
			}
			v.TddConfiguration = &dec_tddconfiguration
			inner.LeaveComponent(recoveryMark_tddconfiguration)
		}
		padding, err := q5.CaptureOpenTypePadding(inner)
		if err != nil {
			return q17.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q5.DecodeConstrainedWholeNumberAligned(bb, 0, 10)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q7.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q6.OTDOACellInformationItemChoicePCI:
		val_pci, err := q5.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound17, true)
		if err != nil {
			return q17.WrapDecodePath(err, "PCI")
		}
		v.PCI = val_pci
	case q6.OTDOACellInformationItemChoiceCellId:
		toleranceMark_cellid := bb.EnterComponent("CellId")
		var dec_cellid q12.ECGI
		if err := q12.BridgeECGIMethodUnmarshalAPERFrom(&dec_cellid, bb); err != nil {
			return q17.WrapDecodePath(err, "CellId")
		}
		if err := q5.ChargeValue(bb, dec_cellid); err != nil {
			return err
		}
		v.CellId = &dec_cellid
		bb.LeaveComponent(toleranceMark_cellid)
	case q6.OTDOACellInformationItemChoiceTAC:
		val_tac, err := q5.DecodeOctetStringAligned(bb, 2, 2, true)
		if err != nil {
			return q17.WrapDecodePath(err, "TAC")
		}
		tmp_tac := q6.TAC(val_tac)
		if err := q5.ChargeValue(bb, tmp_tac); err != nil {
			return err
		}
		v.TAC = &tmp_tac
	case q6.OTDOACellInformationItemChoiceEARFCN:
		val_earfcn, err := q5.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound20, true)
		if err != nil {
			return q17.WrapDecodePath(err, "EARFCN")
		}
		v.EARFCN = val_earfcn
	case q6.OTDOACellInformationItemChoicePRSBandwidth:
		val_prsbandwidth, err := q5.DecodeEnumeratedAligned(bb, 6, true, q5.EnumerationSource{KnownExtensions: 0, Path: "PRSBandwidth"})
		if err != nil {
			return q17.WrapDecodePath(err, "PRSBandwidth")
		}
		tmp_prsbandwidth := q6.PRSBandwidth(val_prsbandwidth)
		if err := q5.ChargeValue(bb, tmp_prsbandwidth); err != nil {
			return err
		}
		v.PRSBandwidth = (*q6.PRSBandwidth)(bb.OwnInt64(int64(tmp_prsbandwidth)))
	case q6.OTDOACellInformationItemChoicePRSConfigurationIndex:
		val_prsconfigurationindex, err := q5.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound14, true)
		if err != nil {
			return q17.WrapDecodePath(err, "PRSConfigurationIndex")
		}
		v.PRSConfigurationIndex = val_prsconfigurationindex
	case q6.OTDOACellInformationItemChoiceCPLength:
		val_cplength, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CPLength"})
		if err != nil {
			return q17.WrapDecodePath(err, "CPLength")
		}
		tmp_cplength := q6.CPLength(val_cplength)
		if err := q5.ChargeValue(bb, tmp_cplength); err != nil {
			return err
		}
		v.CPLength = (*q6.CPLength)(bb.OwnInt64(int64(tmp_cplength)))
	case q6.OTDOACellInformationItemChoiceNumberOfDlFrames:
		val_numberofdlframes, err := q5.DecodeEnumeratedAligned(bb, 4, true, q5.EnumerationSource{KnownExtensions: 0, Path: "NumberOfDlFrames"})
		if err != nil {
			return q17.WrapDecodePath(err, "NumberOfDlFrames")
		}
		tmp_numberofdlframes := q6.NumberOfDlFrames(val_numberofdlframes)
		if err := q5.ChargeValue(bb, tmp_numberofdlframes); err != nil {
			return err
		}
		v.NumberOfDlFrames = (*q6.NumberOfDlFrames)(bb.OwnInt64(int64(tmp_numberofdlframes)))
	case q6.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		val_numberofantennaports, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "NumberOfAntennaPorts"})
		if err != nil {
			return q17.WrapDecodePath(err, "NumberOfAntennaPorts")
		}
		tmp_numberofantennaports := q6.NumberOfAntennaPorts(val_numberofantennaports)
		if err := q5.ChargeValue(bb, tmp_numberofantennaports); err != nil {
			return err
		}
		v.NumberOfAntennaPorts = (*q6.NumberOfAntennaPorts)(bb.OwnInt64(int64(tmp_numberofantennaports)))
	case q6.OTDOACellInformationItemChoiceSFNInitialisationTime:
		bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := q5.DecodeBitStringAligned(bb, 64, 64, true)
		if err != nil {
			return q17.WrapDecodePath(err, "SFNInitialisationTime")
		}
		tmp_sfninitialisationtime := q17.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
		if err := q5.ChargeValue(bb, tmp_sfninitialisationtime); err != nil {
			return err
		}
		v.SFNInitialisationTime = &tmp_sfninitialisationtime
	case q6.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		toleranceMark_eutranaccesspointposition := bb.EnterComponent("EUTRANAccessPointPosition")
		var dec_eutranaccesspointposition q13.EUTRANAccessPointPosition
		if err := q13.BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(&dec_eutranaccesspointposition, bb); err != nil {
			return q17.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		if err := q5.ChargeValue(bb, dec_eutranaccesspointposition); err != nil {
			return err
		}
		v.EUTRANAccessPointPosition = &dec_eutranaccesspointposition
		bb.LeaveComponent(toleranceMark_eutranaccesspointposition)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPERSystemInformationTo appends a SystemInformation list to bb.
func BridgeMarshalAPERSystemInformationTo(list q8.SystemInformation, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q8.BridgeAsn1cAPERSystemInformationListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q7.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q8.BridgeSystemInformationElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q7.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes TDDConfiguration to APER format.
func (v *TDDConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TDDConfiguration) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := q5.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.SubframeAssignment), 7, true); err != nil {
		return q7.Errorf("encoding subframeAssignment: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q4.BridgeTDDConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q7.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q7.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q7.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q5.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q5.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes TDDConfiguration from APER format.
func (v *TDDConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TDDConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TDDConfiguration) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q17.WrapDecodePath(err, "TDDConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q17.WrapDecodePath(err, "TDDConfiguration")
	}
	padding, err := q5.CaptureFinalBits(bb, "TDDConfiguration")
	if err != nil {
		return q17.WrapDecodePath(err, "TDDConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TDDConfiguration) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfiguration{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_subframeassignment, err := q5.DecodeEnumeratedAligned(bb, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "SubframeAssignment"})
	if err != nil {
		return q17.WrapDecodePath(err, "SubframeAssignment")
	}
	v.SubframeAssignment = val_subframeassignment
	if opt_ieextensions {
		tmp_ieextensions := make(q4.TDDConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q4.TDDConfigurationExtIEsExtField
				if err := q4.BridgeTDDConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q17.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q5.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q17.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q17.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		if err := q5.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q5.ChargeSlice[q5.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q5.OpaqueOrigin, len(v.extData))
		if err := q5.ChargeSlice[q5.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q5.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q17.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q5.UnknownExtension, i); err != nil {
					return err
				}
				var retained q5.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes AddOTDOACellsElem to APER format.
func (v *AddOTDOACellsElem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AddOTDOACellsElem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := q5.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeCollection(bb, int64(len(v.AddOTDOACellInfo)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_addotdoacellinfo < 0 || fragmentOffset_addotdoacellinfo > int64(len(v.AddOTDOACellInfo)) || fragmentLength_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo > int64(len(v.AddOTDOACellInfo[fragmentOffset_addotdoacellinfo:])) {
			return q7.Errorf("collection fragment outside value")
		}
		for _, elem := range v.AddOTDOACellInfo[fragmentOffset_addotdoacellinfo : fragmentOffset_addotdoacellinfo+fragmentLength_addotdoacellinfo] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding add-OTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q7.Errorf("encoding add-OTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q10.BridgeAddOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q7.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q7.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q7.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q5.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q5.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes AddOTDOACellsElem from APER format.
func (v *AddOTDOACellsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AddOTDOACellsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AddOTDOACellsElem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q17.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q17.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	padding, err := q5.CaptureFinalBits(bb, "AddOTDOACellsElem")
	if err != nil {
		return q17.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AddOTDOACellsElem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsElem{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_addotdoacellinfo := bb.EnterComponent("AddOTDOACellInfo")
	v.AddOTDOACellInfo = make(AddOTDOACellInformation, 0)
	_, errCollection_addotdoacellinfo := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo > int64(^uint(0)>>1) || fragmentOffset_addotdoacellinfo > int64(^uint(0)>>1)-fragmentLength_addotdoacellinfo {
			return q7.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_addotdoacellinfo; i++ {
			var elem OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_addotdoacellinfo + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q17.WrapDecodePath(err, q7.Sprintf("AddOTDOACellInfo[%d]", fragmentOffset_addotdoacellinfo+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q5.AppendValues(bb, v.AddOTDOACellInfo, elem); err != nil {
				return err
			} else {
				v.AddOTDOACellInfo = next
			}
		}
		return nil
	})
	if errCollection_addotdoacellinfo != nil {
		return q17.WrapDecodePath(errCollection_addotdoacellinfo, "AddOTDOACellInfo")
	}
	bb.LeaveComponent(toleranceMark_addotdoacellinfo)
	if opt_ieextensions {
		tmp_ieextensions := make(q10.AddOTDOACellsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q10.AddOTDOACellsExtIEsExtField
				if err := q10.BridgeAddOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q17.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q5.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q17.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q17.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		if err := q5.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q5.ChargeSlice[q5.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q5.OpaqueOrigin, len(v.extData))
		if err := q5.ChargeSlice[q5.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q5.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q17.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q5.UnknownExtension, i); err != nil {
					return err
				}
				var retained q5.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AddOTDOACellsElem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellsElem) WithoutReplay() AddOTDOACellsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero AddOTDOACellsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellInformationItem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellInformationItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellInformationItem) WithoutReplay() OTDOACellInformationItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero OTDOACellInformationItem
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TDDConfiguration) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "TDDConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TDDConfiguration) WithoutReplay() TDDConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero TDDConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AddOTDOACellsElem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AddOTDOACellsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AddOTDOACellsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TDDConfiguration) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TDDConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TDDConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *AddOTDOACellsElem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "AddOTDOACellsElem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "AddOTDOACellsElem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "AddOTDOACellsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "AddOTDOACellsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "AddOTDOACellsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "AddOTDOACellsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "AddOTDOACellsElem")
}
func (v *AddOTDOACellsElem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellsElem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellsElem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaAddOTDOACellsElem(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellsElem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellsElem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}
func (v *OTDOACellInformationItem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "OTDOACellInformationItem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "OTDOACellInformationItem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellInformationItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "OTDOACellInformationItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "OTDOACellInformationItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "OTDOACellInformationItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "OTDOACellInformationItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "OTDOACellInformationItem")
}
func (v *OTDOACellInformationItem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellInformationItem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellInformationItem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOACellInformationItem(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationItem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationItem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}
func (v *TDDConfiguration) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "TDDConfiguration")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "TDDConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaTDDConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "TDDConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "TDDConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "TDDConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "TDDConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "TDDConfiguration")
}
func (v *TDDConfiguration) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *TDDConfiguration) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *TDDConfiguration) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaTDDConfiguration(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *TDDConfiguration) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *TDDConfiguration) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AddOTDOACellsElem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "AddOTDOACellsElem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellsElem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellsElem{}
		return report, q5.OperationError(err, "AddOTDOACellsElem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "AddOTDOACellsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellInformationItem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "OTDOACellInformationItem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellInformationItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellInformationItem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellInformationItem{}
		return report, q5.OperationError(err, "OTDOACellInformationItem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "OTDOACellInformationItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *TDDConfiguration) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "TDDConfiguration")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded TDDConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaTDDConfiguration(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = TDDConfiguration{}
		return report, q5.OperationError(err, "TDDConfiguration")
	}
	*v = decoded
	return report, q5.OperationError(nil, "TDDConfiguration")
}

// NewOTDOACellInformationItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewOTDOACellInformationItemUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (OTDOACellInformationItem, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return OTDOACellInformationItem{}, q5.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return OTDOACellInformationItem{}, q5.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	value := OTDOACellInformationItem{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return OTDOACellInformationItem{}, q5.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	return value, q5.OperationError(nil, "OTDOACellInformationItemUnknownExtension")
}

// AssistanceInformationControl represents the ASN.1 type AssistanceInformationControl (SEQUENCE).
type AssistanceInformationControl struct {
	replay           q5.Snapshot
	stream           q5.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q5.WireSpan
	ProtocolIEs      q8.AssistanceInformationControlIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                       `asn1:"-" json:"-"`
	extCount         int64                                      `asn1:"-" json:"-"`
	extPresent       []bool                                     `asn1:"-" json:"-"`
	extData          [][]byte                                   `asn1:"-" json:"-"`
	perPadding       q5.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []q5.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []q5.OpaqueOrigin
	extWire          []q5.WireSpan
}

// MarshalAPER encodes AssistanceInformationControl to APER format.
func (v *AssistanceInformationControl) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationControl) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			replay.
			ReplayTo(v.stream, bb); ok ||
			err !=
				nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := q5.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q5.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q7.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q8.BridgeAssistanceInformationControlIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q7.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q7.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q7.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q5.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q5.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes AssistanceInformationControl from APER format.
func (v *AssistanceInformationControl) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationControl with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationControl) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q17.WrapDecodePath(err, "AssistanceInformationControl")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q17.WrapDecodePath(err, "AssistanceInformationControl")
	}
	padding, err := q5.CaptureFinalBits(bb, "AssistanceInformationControl")
	if err != nil {
		return q17.WrapDecodePath(err, "AssistanceInformationControl")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationControl) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationControl{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q8.AssistanceInformationControlIEContainer, 0)
	_, errCollection_protocolies := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q7.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q8.AssistanceInformationControlIEField
			if err := q8.BridgeAssistanceInformationControlIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q17.WrapDecodePath(err, q7.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q5.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q17.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q17.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		if err := q5.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q5.ChargeSlice[q5.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q5.OpaqueOrigin, len(v.extData))
		if err := q5.ChargeSlice[q5.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q5.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q7.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q17.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q5.UnknownExtension, i); err != nil {
					return err
				}
				var retained q5.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationControl) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationControl", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationControl) WithoutReplay() AssistanceInformationControl {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero AssistanceInformationControl
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationControl) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationControl) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationControl) RemoveExtension(index uint64) error {
	if v == nil {
		return q17.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q17.WrapDecodePath(err, q7.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *AssistanceInformationControl) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationControl")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "AssistanceInformationControl")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationControl(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "AssistanceInformationControl")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "AssistanceInformationControl")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "AssistanceInformationControl")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "AssistanceInformationControl")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "AssistanceInformationControl")
}
func (v *AssistanceInformationControl) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationControl) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationControl) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationControl(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationControl) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationControl) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AssistanceInformationControl) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationControl")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationControl
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationControl(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationControl{}
		return report, q5.OperationError(err, "AssistanceInformationControl")
	}
	*v = decoded
	return report, q5.OperationError(nil, "AssistanceInformationControl")
}
func BridgeCaptureLPPaAddOTDOACellInformation(v *AddOTDOACellInformation, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaOTDOACellInformationItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaAddOTDOACellInformation(v *AddOTDOACellInformation, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaOTDOACellInformationItem(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaAddOTDOACells(v *AddOTDOACells, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaAddOTDOACellsElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaAddOTDOACells(v *AddOTDOACells, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaAddOTDOACellsElem(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaAddOTDOACellsElem(v *AddOTDOACellsElem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeCaptureLPPaAddOTDOACellInformation(&v.AddOTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellsElem(v *AddOTDOACellsElem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeCompareLPPaAddOTDOACellInformation(&v.AddOTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationControl(v *AssistanceInformationControl, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q8.BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationControl(v *AssistanceInformationControl, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellInformation(v *OTDOACellInformation, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaOTDOACellInformationItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaOTDOACellInformation(v *OTDOACellInformation, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaOTDOACellInformationItem(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOACellInformationItem(v *OTDOACellInformationItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.OpenBytes(v.knownOpenBytes)
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, nil, false)
	}
	switch v.Choice {
	case q6.OTDOACellInformationItemChoicePCI:
		q6.BridgeCaptureLPPaPCI(&v.PCI, s)
	case q6.OTDOACellInformationItemChoiceCellId:
		{
			f := s.Begin()
			s.Bool(v.CellId == nil)
			if v.CellId != nil {
				q12.BridgeCaptureLPPaECGI(v.CellId, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceTAC:
		{
			f := s.Begin()
			s.Bool(v.TAC == nil)
			if v.TAC != nil {
				q6.BridgeCaptureLPPaTAC(v.TAC, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceEARFCN:
		q6.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	case q6.OTDOACellInformationItemChoicePRSBandwidth:
		{
			f := s.Begin()
			s.Bool(v.PRSBandwidth == nil)
			if v.PRSBandwidth != nil {
				q6.BridgeCaptureLPPaPRSBandwidth(v.PRSBandwidth, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoicePRSConfigurationIndex:
		q6.BridgeCaptureLPPaPRSConfigurationIndex(&v.PRSConfigurationIndex, s)
	case q6.OTDOACellInformationItemChoiceCPLength:
		{
			f := s.Begin()
			s.Bool(v.CPLength == nil)
			if v.CPLength != nil {
				q6.BridgeCaptureLPPaCPLength(v.CPLength, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfDlFrames:
		{
			f := s.Begin()
			s.Bool(v.NumberOfDlFrames == nil)
			if v.NumberOfDlFrames != nil {
				q6.BridgeCaptureLPPaNumberOfDlFrames(v.NumberOfDlFrames, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		{
			f := s.Begin()
			s.Bool(v.NumberOfAntennaPorts == nil)
			if v.NumberOfAntennaPorts != nil {
				q6.BridgeCaptureLPPaNumberOfAntennaPorts(v.NumberOfAntennaPorts, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceSFNInitialisationTime:
		{
			f := s.Begin()
			s.Bool(v.SFNInitialisationTime == nil)
			if v.SFNInitialisationTime != nil {
				q6.BridgeCaptureLPPaSFNInitialisationTime(v.SFNInitialisationTime, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		{
			f := s.Begin()
			s.Bool(v.EUTRANAccessPointPosition == nil)
			if v.EUTRANAccessPointPosition != nil {
				q13.BridgeCaptureLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoicePRSMutingConfiguration:
		{
			f := s.Begin()
			s.Bool(v.PRSMutingConfiguration == nil)
			if v.PRSMutingConfiguration != nil {
				q14.BridgeCaptureLPPaPRSMutingConfiguration(v.PRSMutingConfiguration, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoicePrsid:
		q6.BridgeCaptureLPPaPRSID(&v.Prsid, s)
	case q6.OTDOACellInformationItemChoiceTpid:
		q6.BridgeCaptureLPPaTPID(&v.Tpid, s)
	case q6.OTDOACellInformationItemChoiceTpType:
		{
			f := s.Begin()
			s.Bool(v.TpType == nil)
			if v.TpType != nil {
				q6.BridgeCaptureLPPaTPType(v.TpType, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
		q6.BridgeCaptureLPPaNumberOfDlFramesExtended(&v.NumberOfDlFramesExtended, s)
	case q6.OTDOACellInformationItemChoiceCrsCPlength:
		{
			f := s.Begin()
			s.Bool(v.CrsCPlength == nil)
			if v.CrsCPlength != nil {
				q6.BridgeCaptureLPPaCPLength(v.CrsCPlength, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
		q9.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, s)
	case q6.OTDOACellInformationItemChoiceNPRSConfiguration:
		{
			f := s.Begin()
			s.Bool(v.NPRSConfiguration == nil)
			if v.NPRSConfiguration != nil {
				q15.BridgeCaptureLPPaNPRSConfiguration(v.NPRSConfiguration, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
		{
			f := s.Begin()
			s.Bool(v.OffsetNBChanneltoEARFCN == nil)
			if v.OffsetNBChanneltoEARFCN != nil {
				q6.BridgeCaptureLPPaOffsetNBChanneltoEARFCN(v.OffsetNBChanneltoEARFCN, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceOperationModeInfo:
		{
			f := s.Begin()
			s.Bool(v.OperationModeInfo == nil)
			if v.OperationModeInfo != nil {
				q6.BridgeCaptureLPPaOperationModeInfo(v.OperationModeInfo, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceNPRSID:
		{
			f := s.Begin()
			s.BigInt(v.NPRSID)
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceDLBandwidth:
		{
			f := s.Begin()
			s.Bool(v.DLBandwidth == nil)
			if v.DLBandwidth != nil {
				q6.BridgeCaptureLPPaDLBandwidth(v.DLBandwidth, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoicePRSOccasionGroup:
		{
			f := s.Begin()
			s.Bool(v.PRSOccasionGroup == nil)
			if v.PRSOccasionGroup != nil {
				q6.BridgeCaptureLPPaPRSOccasionGroup(v.PRSOccasionGroup, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
		{
			f := s.Begin()
			s.Bool(v.PRSFreqHoppingConfig == nil)
			if v.PRSFreqHoppingConfig != nil {
				q14.BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
		{
			f := s.Begin()
			s.Bool(v.RepetitionNumberofSIB1NB == nil)
			if v.RepetitionNumberofSIB1NB != nil {
				q6.BridgeCaptureLPPaRepetitionNumberofSIB1NB(v.RepetitionNumberofSIB1NB, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceNPRSSequenceInfo:
		q6.BridgeCaptureLPPaNPRSSequenceInfo(&v.NPRSSequenceInfo, s)
	case q6.OTDOACellInformationItemChoiceNPRSType2:
		{
			f := s.Begin()
			s.Bool(v.NPRSType2 == nil)
			if v.NPRSType2 != nil {
				q15.BridgeCaptureLPPaNPRSConfiguration(v.NPRSType2, s)
			}
			s.End(f, nil, false)
		}
	case q6.OTDOACellInformationItemChoiceTddConfiguration:
		{
			f := s.Begin()
			s.Bool(v.TddConfiguration == nil)
			if v.TddConfiguration != nil {
				BridgeCaptureLPPaTDDConfiguration(v.TddConfiguration, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellInformationItem(v *OTDOACellInformationItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	switch v.Choice {
	case q6.OTDOACellInformationItemChoicePCI:
		q11.BridgeCompareLPPaPCI(&v.PCI, s)
	case q6.OTDOACellInformationItemChoiceCellId:
		{
			f := s.Begin()
			s.Bool(v.CellId == nil)
			if v.CellId != nil {
				q12.BridgeCompareLPPaECGI(v.CellId, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceTAC:
		{
			f := s.Begin()
			s.Bool(v.TAC == nil)
			if v.TAC != nil {
				q10.BridgeCompareLPPaTAC(v.TAC, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceEARFCN:
		q11.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	case q6.OTDOACellInformationItemChoicePRSBandwidth:
		{
			f := s.Begin()
			s.Bool(v.PRSBandwidth == nil)
			if v.PRSBandwidth != nil {
				q11.BridgeCompareLPPaPRSBandwidth(v.PRSBandwidth, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoicePRSConfigurationIndex:
		q11.BridgeCompareLPPaPRSConfigurationIndex(&v.PRSConfigurationIndex, s)
	case q6.OTDOACellInformationItemChoiceCPLength:
		{
			f := s.Begin()
			s.Bool(v.CPLength == nil)
			if v.CPLength != nil {
				q11.BridgeCompareLPPaCPLength(v.CPLength, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfDlFrames:
		{
			f := s.Begin()
			s.Bool(v.NumberOfDlFrames == nil)
			if v.NumberOfDlFrames != nil {
				q11.BridgeCompareLPPaNumberOfDlFrames(v.NumberOfDlFrames, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		{
			f := s.Begin()
			s.Bool(v.NumberOfAntennaPorts == nil)
			if v.NumberOfAntennaPorts != nil {
				q11.BridgeCompareLPPaNumberOfAntennaPorts(v.NumberOfAntennaPorts, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceSFNInitialisationTime:
		{
			f := s.Begin()
			s.Bool(v.SFNInitialisationTime == nil)
			if v.SFNInitialisationTime != nil {
				q10.BridgeCompareLPPaSFNInitialisationTime(v.SFNInitialisationTime, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		{
			f := s.Begin()
			s.Bool(v.EUTRANAccessPointPosition == nil)
			if v.EUTRANAccessPointPosition != nil {
				q13.BridgeCompareLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoicePRSMutingConfiguration:
		{
			f := s.Begin()
			s.Bool(v.PRSMutingConfiguration == nil)
			if v.PRSMutingConfiguration != nil {
				q14.BridgeCompareLPPaPRSMutingConfiguration(v.PRSMutingConfiguration, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoicePrsid:
		q11.BridgeCompareLPPaPRSID(&v.Prsid, s)
	case q6.OTDOACellInformationItemChoiceTpid:
		q10.BridgeCompareLPPaTPID(&v.Tpid, s)
	case q6.OTDOACellInformationItemChoiceTpType:
		{
			f := s.Begin()
			s.Bool(v.TpType == nil)
			if v.TpType != nil {
				q10.BridgeCompareLPPaTPType(v.TpType, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
		q11.BridgeCompareLPPaNumberOfDlFramesExtended(&v.NumberOfDlFramesExtended, s)
	case q6.OTDOACellInformationItemChoiceCrsCPlength:
		{
			f := s.Begin()
			s.Bool(v.CrsCPlength == nil)
			if v.CrsCPlength != nil {
				q11.BridgeCompareLPPaCPLength(v.CrsCPlength, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
		q18.BridgeCompareLPPaMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, s)
	case q6.OTDOACellInformationItemChoiceNPRSConfiguration:
		{
			f := s.Begin()
			s.Bool(v.NPRSConfiguration == nil)
			if v.NPRSConfiguration != nil {
				q15.BridgeCompareLPPaNPRSConfiguration(v.NPRSConfiguration, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
		{
			f := s.Begin()
			s.Bool(v.OffsetNBChanneltoEARFCN == nil)
			if v.OffsetNBChanneltoEARFCN != nil {
				q11.BridgeCompareLPPaOffsetNBChanneltoEARFCN(v.OffsetNBChanneltoEARFCN, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceOperationModeInfo:
		{
			f := s.Begin()
			s.Bool(v.OperationModeInfo == nil)
			if v.OperationModeInfo != nil {
				q11.BridgeCompareLPPaOperationModeInfo(v.OperationModeInfo, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceNPRSID:
		{
			f := s.Begin()
			s.BigInt(v.NPRSID)
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceDLBandwidth:
		{
			f := s.Begin()
			s.Bool(v.DLBandwidth == nil)
			if v.DLBandwidth != nil {
				q11.BridgeCompareLPPaDLBandwidth(v.DLBandwidth, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoicePRSOccasionGroup:
		{
			f := s.Begin()
			s.Bool(v.PRSOccasionGroup == nil)
			if v.PRSOccasionGroup != nil {
				q11.BridgeCompareLPPaPRSOccasionGroup(v.PRSOccasionGroup, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
		{
			f := s.Begin()
			s.Bool(v.PRSFreqHoppingConfig == nil)
			if v.PRSFreqHoppingConfig != nil {
				q14.BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
		{
			f := s.Begin()
			s.Bool(v.RepetitionNumberofSIB1NB == nil)
			if v.RepetitionNumberofSIB1NB != nil {
				q10.BridgeCompareLPPaRepetitionNumberofSIB1NB(v.RepetitionNumberofSIB1NB, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceNPRSSequenceInfo:
		q11.BridgeCompareLPPaNPRSSequenceInfo(&v.NPRSSequenceInfo, s)
	case q6.OTDOACellInformationItemChoiceNPRSType2:
		{
			f := s.Begin()
			s.Bool(v.NPRSType2 == nil)
			if v.NPRSType2 != nil {
				q15.BridgeCompareLPPaNPRSConfiguration(v.NPRSType2, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.OTDOACellInformationItemChoiceTddConfiguration:
		{
			f := s.Begin()
			s.Bool(v.TddConfiguration == nil)
			if v.TddConfiguration != nil {
				BridgeCompareLPPaTDDConfiguration(v.TddConfiguration, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaTDDConfiguration(v *TDDConfiguration, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.SubframeAssignment))
	s.Bool(v.IEExtensions == nil)
	BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaTDDConfiguration(v *TDDConfiguration, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.SubframeAssignment))
	s.Bool(v.IEExtensions == nil)
	BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

// AddOTDOACellsElemCodec binds the complete source value type.
func AddOTDOACellsElemCodec() AddOTDOACellsElemValueCodec {
	return AddOTDOACellsElemValueCodec{path: "AddOTDOACellsElem", decode: func(data []byte, options q5.DecodeState) (AddOTDOACellsElem, error) {
		var value AddOTDOACellsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AddOTDOACellsElem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value AddOTDOACellsElem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AddOTDOACellsElem, options q5.DecodeState) (AddOTDOACellsElem, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaAddOTDOACellsElem(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v AddOTDOACellsElem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAddOTDOACellsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACellsElem"
		return sealed
	}(),
	}
}

// OTDOACellInformationItemCodec binds the complete source value type.
func OTDOACellInformationItemCodec() OTDOACellInformationItemValueCodec {
	return OTDOACellInformationItemValueCodec{path: "OTDOACellInformationItem", decode: func(data []byte, options q5.DecodeState) (OTDOACellInformationItem, error) {
		var value OTDOACellInformationItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return OTDOACellInformationItem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value OTDOACellInformationItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v OTDOACellInformationItem, options q5.DecodeState) (OTDOACellInformationItem, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaOTDOACellInformationItem(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OTDOACellInformationItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaOTDOACellInformationItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellInformationItem"
		return sealed
	}(),
	}
}

// TDDConfigurationCodec binds the complete source value type.
func TDDConfigurationCodec() TDDConfigurationValueCodec {
	return TDDConfigurationValueCodec{path: "TDDConfiguration", decode: func(data []byte, options q5.DecodeState) (TDDConfiguration, error) {
		var value TDDConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TDDConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value TDDConfiguration, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TDDConfiguration, options q5.DecodeState) (TDDConfiguration, q5.Snapshot) {
		s := q5.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureLPPaTDDConfiguration(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,
			false,
		)
		return v, root
	}, compare: func(v TDDConfiguration, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaTDDConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:TDDConfiguration"
		return sealed
	}(),
	}
}
func BridgeAddOTDOACellInformationAPERValueFieldContext(v *AddOTDOACellInformationAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellInformationAPERValueFieldReceived(v *AddOTDOACellInformationAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellInformationAPERValueFieldReplay(v *AddOTDOACellInformationAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellInformationAPERValueFieldWithoutReplay(v *AddOTDOACellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellInformationValueCodecFieldCapture(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, q5.DecodeState) (AddOTDOACellInformation, q5.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellInformationValueCodecFieldCompare(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellInformationValueCodecFieldContext(v *AddOTDOACellInformationValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellInformationValueCodecFieldDecode(v *AddOTDOACellInformationValueCodec) *func([]byte, q5.DecodeState) (AddOTDOACellInformation, error) {
	return &v.decode
}
func BridgeAddOTDOACellInformationValueCodecFieldEncode(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellInformationValueCodecFieldPath(v *AddOTDOACellInformationValueCodec) *q5.Path {
	return &v.path
}
func BridgeAddOTDOACellInformationValueCodecMethodEncodeBudget(v AddOTDOACellInformationValueCodec, a0 AddOTDOACellInformation, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellInformationValueCodecMethodEncodeChanged(v AddOTDOACellInformationValueCodec, a0 AddOTDOACellInformation, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAddOTDOACellsAPERValueFieldContext(v *AddOTDOACellsAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsAPERValueFieldReceived(v *AddOTDOACellsAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsAPERValueFieldReplay(v *AddOTDOACellsAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsAPERValueFieldWithoutReplay(v *AddOTDOACellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsElemAPERValueFieldContext(v *AddOTDOACellsElemAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsElemAPERValueFieldReceived(v *AddOTDOACellsElemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsElemAPERValueFieldReplay(v *AddOTDOACellsElemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsElemAPERValueFieldWithoutReplay(v *AddOTDOACellsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsElemFieldAddOTDOACellInfoIndef(v *AddOTDOACellsElem) *bool {
	return &v.addOTDOACellInfoIndef
}
func BridgeAddOTDOACellsElemFieldExtCount(v *AddOTDOACellsElem) *int64   { return &v.extCount }
func BridgeAddOTDOACellsElemFieldExtData(v *AddOTDOACellsElem) *[][]byte { return &v.extData }
func BridgeAddOTDOACellsElemFieldExtOrigin(v *AddOTDOACellsElem) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAddOTDOACellsElemFieldExtPresent(v *AddOTDOACellsElem) *[]bool     { return &v.extPresent }
func BridgeAddOTDOACellsElemFieldExtWire(v *AddOTDOACellsElem) *[]q5.WireSpan { return &v.extWire }
func BridgeAddOTDOACellsElemFieldIEExtensionsIndef(v *AddOTDOACellsElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAddOTDOACellsElemFieldPerExtPadding(v *AddOTDOACellsElem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeAddOTDOACellsElemFieldPerPadding(v *AddOTDOACellsElem) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeAddOTDOACellsElemFieldReceived(v *AddOTDOACellsElem) *bool { return &v.received }
func BridgeAddOTDOACellsElemFieldReceivedBytes(v *AddOTDOACellsElem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellsElemFieldReplay(v *AddOTDOACellsElem) *q5.Snapshot { return &v.replay }
func BridgeAddOTDOACellsElemFieldStream(v *AddOTDOACellsElem) *q5.WireSpan { return &v.stream }
func BridgeAddOTDOACellsElemFieldWithoutReplay(v *AddOTDOACellsElem) *bool { return &v.withoutReplay }
func BridgeAddOTDOACellsElemMethodMarshalAPERBudget(v *AddOTDOACellsElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERChanged(v *AddOTDOACellsElem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERChangedValue(v *AddOTDOACellsElem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERFreshValue(v *AddOTDOACellsElem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERLegacy(v *AddOTDOACellsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellsElemMethodMarshalAPERPlanned(v *AddOTDOACellsElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERTo(v *AddOTDOACellsElem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERFrom(v *AddOTDOACellsElem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERLegacy(v *AddOTDOACellsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERWithOptions(v *AddOTDOACellsElem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAddOTDOACellsElemValueCodecFieldCapture(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, q5.DecodeState) (AddOTDOACellsElem, q5.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellsElemValueCodecFieldCompare(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellsElemValueCodecFieldContext(v *AddOTDOACellsElemValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsElemValueCodecFieldDecode(v *AddOTDOACellsElemValueCodec) *func([]byte, q5.DecodeState) (AddOTDOACellsElem, error) {
	return &v.decode
}
func BridgeAddOTDOACellsElemValueCodecFieldEncode(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellsElemValueCodecFieldPath(v *AddOTDOACellsElemValueCodec) *q5.Path {
	return &v.path
}
func BridgeAddOTDOACellsElemValueCodecMethodEncodeBudget(v AddOTDOACellsElemValueCodec, a0 AddOTDOACellsElem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellsElemValueCodecMethodEncodeChanged(v AddOTDOACellsElemValueCodec, a0 AddOTDOACellsElem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAddOTDOACellsValueCodecFieldCapture(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, q5.DecodeState) (AddOTDOACells, q5.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellsValueCodecFieldCompare(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellsValueCodecFieldContext(v *AddOTDOACellsValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsValueCodecFieldDecode(v *AddOTDOACellsValueCodec) *func([]byte, q5.DecodeState) (AddOTDOACells, error) {
	return &v.decode
}
func BridgeAddOTDOACellsValueCodecFieldEncode(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellsValueCodecFieldPath(v *AddOTDOACellsValueCodec) *q5.Path { return &v.path }
func BridgeAddOTDOACellsValueCodecMethodEncodeBudget(v AddOTDOACellsValueCodec, a0 AddOTDOACells, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellsValueCodecMethodEncodeChanged(v AddOTDOACellsValueCodec, a0 AddOTDOACells, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationControlAPERValueFieldContext(v *AssistanceInformationControlAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlAPERValueFieldReceived(v *AssistanceInformationControlAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationControlAPERValueFieldReplay(v *AssistanceInformationControlAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlAPERValueFieldWithoutReplay(v *AssistanceInformationControlAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlFieldExtCount(v *AssistanceInformationControl) *int64 {
	return &v.extCount
}
func BridgeAssistanceInformationControlFieldExtData(v *AssistanceInformationControl) *[][]byte {
	return &v.extData
}
func BridgeAssistanceInformationControlFieldExtOrigin(v *AssistanceInformationControl) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationControlFieldExtPresent(v *AssistanceInformationControl) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationControlFieldExtWire(v *AssistanceInformationControl) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationControlFieldPerExtPadding(v *AssistanceInformationControl) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationControlFieldPerPadding(v *AssistanceInformationControl) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationControlFieldProtocolIEsIndef(v *AssistanceInformationControl) *bool {
	return &v.protocolIEsIndef
}
func BridgeAssistanceInformationControlFieldReceived(v *AssistanceInformationControl) *bool {
	return &v.received
}
func BridgeAssistanceInformationControlFieldReceivedBytes(v *AssistanceInformationControl) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationControlFieldReplay(v *AssistanceInformationControl) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlFieldStream(v *AssistanceInformationControl) *q5.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationControlFieldWithoutReplay(v *AssistanceInformationControl) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlMethodMarshalAPERBudget(v *AssistanceInformationControl, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERChanged(v *AssistanceInformationControl, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationControlMethodMarshalAPERChangedValue(v *AssistanceInformationControl, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationControlMethodMarshalAPERFreshValue(v *AssistanceInformationControl, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERLegacy(v *AssistanceInformationControl) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationControlMethodMarshalAPERPlanned(v *AssistanceInformationControl, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERTo(v *AssistanceInformationControl, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERFrom(v *AssistanceInformationControl, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERLegacy(v *AssistanceInformationControl, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERWithOptions(v *AssistanceInformationControl, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationControlValueCodecFieldCapture(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, q5.DecodeState) (AssistanceInformationControl, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationControlValueCodecFieldCompare(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationControlValueCodecFieldContext(v *AssistanceInformationControlValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlValueCodecFieldDecode(v *AssistanceInformationControlValueCodec) *func([]byte, q5.DecodeState) (AssistanceInformationControl, error) {
	return &v.decode
}
func BridgeAssistanceInformationControlValueCodecFieldEncode(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationControlValueCodecFieldPath(v *AssistanceInformationControlValueCodec) *q5.Path {
	return &v.path
}
func BridgeAssistanceInformationControlValueCodecMethodEncodeBudget(v AssistanceInformationControlValueCodec, a0 AssistanceInformationControl, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationControlValueCodecMethodEncodeChanged(v AssistanceInformationControlValueCodec, a0 AssistanceInformationControl, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellInformationAPERValueFieldContext(v *OTDOACellInformationAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationAPERValueFieldReceived(v *OTDOACellInformationAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOACellInformationAPERValueFieldReplay(v *OTDOACellInformationAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationAPERValueFieldWithoutReplay(v *OTDOACellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemAPERValueFieldContext(v *OTDOACellInformationItemAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationItemAPERValueFieldReceived(v *OTDOACellInformationItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOACellInformationItemAPERValueFieldReplay(v *OTDOACellInformationItemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationItemAPERValueFieldWithoutReplay(v *OTDOACellInformationItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemFieldKnownOpenBytes(v *OTDOACellInformationItem) *uint64 {
	return &v.knownOpenBytes
}
func BridgeOTDOACellInformationItemFieldPerOpenTypePadding(v *OTDOACellInformationItem) *q5.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeOTDOACellInformationItemFieldPerPadding(v *OTDOACellInformationItem) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellInformationItemFieldReceived(v *OTDOACellInformationItem) *bool {
	return &v.received
}
func BridgeOTDOACellInformationItemFieldReceivedBytes(v *OTDOACellInformationItem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellInformationItemFieldReplay(v *OTDOACellInformationItem) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationItemFieldStream(v *OTDOACellInformationItem) *q5.WireSpan {
	return &v.stream
}
func BridgeOTDOACellInformationItemFieldWithoutReplay(v *OTDOACellInformationItem) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemMethodMarshalAPERBudget(v *OTDOACellInformationItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERChanged(v *OTDOACellInformationItem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERChangedValue(v *OTDOACellInformationItem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERFreshValue(v *OTDOACellInformationItem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERLegacy(v *OTDOACellInformationItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellInformationItemMethodMarshalAPERPlanned(v *OTDOACellInformationItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERTo(v *OTDOACellInformationItem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(v *OTDOACellInformationItem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERLegacy(v *OTDOACellInformationItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERWithOptions(v *OTDOACellInformationItem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellInformationItemValueCodecFieldCapture(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, q5.DecodeState) (OTDOACellInformationItem, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellInformationItemValueCodecFieldCompare(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellInformationItemValueCodecFieldContext(v *OTDOACellInformationItemValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationItemValueCodecFieldDecode(v *OTDOACellInformationItemValueCodec) *func([]byte, q5.DecodeState) (OTDOACellInformationItem, error) {
	return &v.decode
}
func BridgeOTDOACellInformationItemValueCodecFieldEncode(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellInformationItemValueCodecFieldPath(v *OTDOACellInformationItemValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOACellInformationItemValueCodecMethodEncodeBudget(v OTDOACellInformationItemValueCodec, a0 OTDOACellInformationItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellInformationItemValueCodecMethodEncodeChanged(v OTDOACellInformationItemValueCodec, a0 OTDOACellInformationItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellInformationValueCodecFieldCapture(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, q5.DecodeState) (OTDOACellInformation, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellInformationValueCodecFieldCompare(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellInformationValueCodecFieldContext(v *OTDOACellInformationValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationValueCodecFieldDecode(v *OTDOACellInformationValueCodec) *func([]byte, q5.DecodeState) (OTDOACellInformation, error) {
	return &v.decode
}
func BridgeOTDOACellInformationValueCodecFieldEncode(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellInformationValueCodecFieldPath(v *OTDOACellInformationValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOACellInformationValueCodecMethodEncodeBudget(v OTDOACellInformationValueCodec, a0 OTDOACellInformation, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellInformationValueCodecMethodEncodeChanged(v OTDOACellInformationValueCodec, a0 OTDOACellInformation, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTDDConfigurationAPERValueFieldContext(v *TDDConfigurationAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeTDDConfigurationAPERValueFieldReceived(v *TDDConfigurationAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeTDDConfigurationAPERValueFieldReplay(v *TDDConfigurationAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationAPERValueFieldWithoutReplay(v *TDDConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationFieldExtCount(v *TDDConfiguration) *int64   { return &v.extCount }
func BridgeTDDConfigurationFieldExtData(v *TDDConfiguration) *[][]byte { return &v.extData }
func BridgeTDDConfigurationFieldExtOrigin(v *TDDConfiguration) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTDDConfigurationFieldExtPresent(v *TDDConfiguration) *[]bool     { return &v.extPresent }
func BridgeTDDConfigurationFieldExtWire(v *TDDConfiguration) *[]q5.WireSpan { return &v.extWire }
func BridgeTDDConfigurationFieldIEExtensionsIndef(v *TDDConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTDDConfigurationFieldPerExtPadding(v *TDDConfiguration) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeTDDConfigurationFieldPerPadding(v *TDDConfiguration) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeTDDConfigurationFieldReceived(v *TDDConfiguration) *bool { return &v.received }
func BridgeTDDConfigurationFieldReceivedBytes(v *TDDConfiguration) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeTDDConfigurationFieldReplay(v *TDDConfiguration) *q5.Snapshot { return &v.replay }
func BridgeTDDConfigurationFieldStream(v *TDDConfiguration) *q5.WireSpan { return &v.stream }
func BridgeTDDConfigurationFieldWithoutReplay(v *TDDConfiguration) *bool { return &v.withoutReplay }
func BridgeTDDConfigurationMethodMarshalAPERBudget(v *TDDConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERChanged(v *TDDConfiguration, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTDDConfigurationMethodMarshalAPERChangedValue(v *TDDConfiguration, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTDDConfigurationMethodMarshalAPERFreshValue(v *TDDConfiguration, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERLegacy(v *TDDConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTDDConfigurationMethodMarshalAPERPlanned(v *TDDConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERTo(v *TDDConfiguration, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationMethodUnmarshalAPERFrom(v *TDDConfiguration, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationMethodUnmarshalAPERLegacy(v *TDDConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTDDConfigurationMethodUnmarshalAPERWithOptions(v *TDDConfiguration, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTDDConfigurationValueCodecFieldCapture(v *TDDConfigurationValueCodec) *func(TDDConfiguration, q5.DecodeState) (TDDConfiguration, q5.Snapshot) {
	return &v.capture
}
func BridgeTDDConfigurationValueCodecFieldCompare(v *TDDConfigurationValueCodec) *func(TDDConfiguration, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTDDConfigurationValueCodecFieldContext(v *TDDConfigurationValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeTDDConfigurationValueCodecFieldDecode(v *TDDConfigurationValueCodec) *func([]byte, q5.DecodeState) (TDDConfiguration, error) {
	return &v.decode
}
func BridgeTDDConfigurationValueCodecFieldEncode(v *TDDConfigurationValueCodec) *func(TDDConfiguration, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTDDConfigurationValueCodecFieldPath(v *TDDConfigurationValueCodec) *q5.Path {
	return &v.path
}
func BridgeTDDConfigurationValueCodecMethodEncodeBudget(v TDDConfigurationValueCodec, a0 TDDConfiguration, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTDDConfigurationValueCodecMethodEncodeChanged(v TDDConfigurationValueCodec, a0 TDDConfiguration, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
