// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s12 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s12

import (
	q10 "fmt"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(v *q4.OTDOAInformationFailureIEContainer, s *q5.SemanticCapture) {
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
			BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(v *q4.OTDOAInformationFailureIEContainer, s *q5.SemanticComparison) {
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
			BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIESingleContainer(v *q6.OTDOAInformationTypeIEValueProtocolIESingleContainer, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIESingleContainer(v *q6.OTDOAInformationTypeIEValueProtocolIESingleContainer, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgePrivateMessageIEsValueCaptureLPPaPrivateIEContainer(v *q7.PrivateMessageIEsValuePrivateIEContainer, s *q5.SemanticCapture) {
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
			BridgePrivateMessageIEsValueCaptureLPPaPrivateIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgePrivateMessageIEsValueCompareLPPaPrivateIEContainer(v *q7.PrivateMessageIEsValuePrivateIEContainer, s *q5.SemanticComparison) {
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
			BridgePrivateMessageIEsValueCompareLPPaPrivateIEField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q8.ResultGERANItemExtIEsExtContainer, s *q5.SemanticCapture) {
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
			BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q8.ResultGERANItemExtIEsExtContainer, s *q5.SemanticComparison) {
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
			BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q8.ResultRSRPItemExtIEsExtContainer, s *q5.SemanticCapture) {
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
			BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q8.ResultRSRPItemExtIEsExtContainer, s *q5.SemanticComparison) {
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
			BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}

// OTDOAInformationFailureValueCodec is the concrete ValueCodec[OTDOAInformationFailure].
type OTDOAInformationFailureValueCodec struct {
	context q9.BridgeCodecContext
	capture func(OTDOAInformationFailure, q5.DecodeState,

	) (OTDOAInformationFailure, q5.Snapshot,

	)
	compare func(OTDOAInformationFailure, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (OTDOAInformationFailure,

		error)
	encode func(OTDOAInformationFailure,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationFailureValueCodec) New(value OTDOAInformationFailure,

) (OTDOAInformationFailureAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationFailureAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationFailureAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOAInformationFailureValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOAInformationFailureAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationFailureAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOAInformationFailureAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationFailureAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationFailureAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOAInformationFailureAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationFailureValueCodec) EncodeAPER(value OTDOAInformationFailureAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c OTDOAInformationFailureValueCodec) encodeBudget(value OTDOAInformationFailure,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationFailureValueCodec) encodeChanged(value OTDOAInformationFailure,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PrivateMessageValueCodec is the concrete ValueCodec[PrivateMessage].
type PrivateMessageValueCodec struct {
	context q9.BridgeCodecContext
	capture func(PrivateMessage, q5.DecodeState,

	) (PrivateMessage, q5.Snapshot,

	)
	compare func(PrivateMessage, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (PrivateMessage,

		error)
	encode func(PrivateMessage,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PrivateMessageValueCodec) New(value PrivateMessage,

) (PrivateMessageAPERValue, error) {
	if c.encode == nil {
		return PrivateMessageAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PrivateMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PrivateMessageAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PrivateMessageValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PrivateMessageAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PrivateMessageAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PrivateMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PrivateMessageAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PrivateMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PrivateMessageAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PrivateMessageValueCodec) EncodeAPER(value PrivateMessageAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c PrivateMessageValueCodec) encodeBudget(value PrivateMessage,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PrivateMessageValueCodec) encodeChanged(value PrivateMessage,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ResultGERANValueCodec is the concrete ValueCodec[ResultGERAN].
type ResultGERANValueCodec struct {
	context q9.BridgeCodecContext
	capture func(ResultGERAN, q5.DecodeState,

	) (ResultGERAN, q5.Snapshot,

	)
	compare func(ResultGERAN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ResultGERAN,

		error)
	encode func(ResultGERAN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ResultGERANValueCodec) New(value ResultGERAN,

) (ResultGERANAPERValue, error) {
	if c.encode == nil {
		return ResultGERANAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ResultGERANAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultGERANAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ResultGERANAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ResultGERANValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ResultGERANAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultGERANAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ResultGERANAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultGERANAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ResultGERANAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ResultGERANAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultGERANValueCodec) EncodeAPER(value ResultGERANAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c ResultGERANValueCodec) encodeBudget(value ResultGERAN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultGERANValueCodec) encodeChanged(value ResultGERAN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ResultGERANItemValueCodec is the concrete ValueCodec[ResultGERANItem].
type ResultGERANItemValueCodec struct {
	context q9.BridgeCodecContext
	capture func(ResultGERANItem, q5.DecodeState,

	) (ResultGERANItem, q5.Snapshot,

	)
	compare func(ResultGERANItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ResultGERANItem,

		error)
	encode func(ResultGERANItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ResultGERANItemValueCodec) New(value ResultGERANItem,

) (ResultGERANItemAPERValue, error) {
	if c.encode == nil {
		return ResultGERANItemAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ResultGERANItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultGERANItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ResultGERANItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ResultGERANItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ResultGERANItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultGERANItemAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ResultGERANItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultGERANItemAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ResultGERANItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ResultGERANItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultGERANItemValueCodec) EncodeAPER(value ResultGERANItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c ResultGERANItemValueCodec) encodeBudget(value ResultGERANItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultGERANItemValueCodec) encodeChanged(value ResultGERANItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ResultRSRPValueCodec is the concrete ValueCodec[ResultRSRP].
type ResultRSRPValueCodec struct {
	context q9.BridgeCodecContext
	capture func(ResultRSRP, q5.DecodeState,

	) (ResultRSRP, q5.Snapshot,

	)
	compare func(ResultRSRP, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ResultRSRP,

		error)
	encode func(ResultRSRP,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ResultRSRPValueCodec) New(value ResultRSRP,

) (ResultRSRPAPERValue, error) {
	if c.encode == nil {
		return ResultRSRPAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ResultRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ResultRSRPAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ResultRSRPValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ResultRSRPAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRPAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ResultRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRPAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ResultRSRPAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultRSRPValueCodec) EncodeAPER(value ResultRSRPAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c ResultRSRPValueCodec) encodeBudget(value ResultRSRP,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRPValueCodec) encodeChanged(value ResultRSRP,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ResultRSRPItemValueCodec is the concrete ValueCodec[ResultRSRPItem].
type ResultRSRPItemValueCodec struct {
	context q9.BridgeCodecContext
	capture func(ResultRSRPItem, q5.DecodeState,

	) (ResultRSRPItem, q5.Snapshot,

	)
	compare func(ResultRSRPItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ResultRSRPItem,

		error)
	encode func(ResultRSRPItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ResultRSRPItemValueCodec) New(value ResultRSRPItem,

) (ResultRSRPItemAPERValue, error) {
	if c.encode == nil {
		return ResultRSRPItemAPERValue{}, q5.OperationError(q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ResultRSRPItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRPItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ResultRSRPItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ResultRSRPItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ResultRSRPItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRPItemAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ResultRSRPItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRPItemAPERValue{}, q5.DecodeReport{}, q10.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRPItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ResultRSRPItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultRSRPItemValueCodec) EncodeAPER(value ResultRSRPItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q10.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c ResultRSRPItemValueCodec) encodeBudget(value ResultRSRPItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRPItemValueCodec) encodeChanged(value ResultRSRPItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(fields q4.OTDOAInformationFailureIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q4.BridgeOTDOAInformationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q4.BridgeOTDOAInformationFailureIEValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields q8.OTDOACellsExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.OTDOACellsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.OTDOACellsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeOTDOACellsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationTypeIEValueValidateLPPaIEContainer(fields q6.OTDOAInformationTypeIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q6.BridgeOTDOAInformationTypeIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q6.BridgeOTDOAInformationTypeIEValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaExtensionContainer(fields q8.OTDOAInformationTypeItemExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.OTDOAInformationTypeItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.OTDOAInformationTypeItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaExtensionContainer(fields q8.PRSFrequencyHoppingConfigurationItemIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.PRSFrequencyHoppingConfigurationItemIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.PRSFrequencyHoppingConfigurationItemIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePosSIBSegmentsExtIEsValueValidateLPPaExtensionContainer(fields q8.PosSIBSegmentsExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.PosSIBSegmentsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.PosSIBSegmentsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePosSIBSegmentsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePosSIBsExtIEsValueValidateLPPaExtensionContainer(fields q8.PosSIBsExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.PosSIBsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.PosSIBsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePosSIBsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeResultGERANItemExtIEsValueValidateLPPaExtensionContainer(fields q8.ResultGERANItemExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.ResultGERANItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.ResultGERANItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultGERANItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeResultRSRPItemExtIEsValueValidateLPPaExtensionContainer(fields q8.ResultRSRPItemExtIEsExtContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget) q11.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.ResultRSRPItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q11.ValidationReport {
			sealed := q11.ValidationReport{}
			*q11.BridgeValidationReportFieldErr(&sealed) = err
			*q11.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.ResultRSRPItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultRSRPItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// oTDOAInformationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q4.OTDOAInformationFailureIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q9.ProtocolIEID, q5.OpaqueOpenType) (q4.OTDOAInformationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q9.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q9.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(v *q4.OTDOAInformationFailureIEField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgeOTDOAInformationFailureIEFieldFieldStream(v))
	q9.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q9.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q4.BridgeOTDOAInformationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = q4.BridgeOTDOAInformationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q4.BridgeOTDOAInformationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q4.BridgeOTDOAInformationFailureIEFieldFieldReplay(v), *q4.BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEField(v *q4.OTDOAInformationFailureIEField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q4.BridgeOTDOAInformationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q4.BridgeOTDOAInformationFailureIEFieldFieldReplay(v), *q4.BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}

// oTDOAInformationTypeIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q6.OTDOAInformationTypeIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q9.ProtocolIEID, q5.OpaqueOpenType) (q6.OTDOAInformationTypeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q9.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q9.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIEField(v *q6.OTDOAInformationTypeIEField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q6.BridgeOTDOAInformationTypeIEFieldFieldStream(v))
	q9.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q9.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q6.BridgeOTDOAInformationTypeIEValueMethodCaptureFraming(v.Value))
	v.Value = q6.BridgeOTDOAInformationTypeIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q6.BridgeOTDOAInformationTypeIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q6.BridgeOTDOAInformationTypeIEFieldFieldReplay(v), *q6.BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIEField(v *q6.OTDOAInformationTypeIEField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q6.BridgeOTDOAInformationTypeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q6.BridgeOTDOAInformationTypeIEFieldFieldReplay(v), *q6.BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v))
}

// privateMessageIEsValueProtocolPrivateValue is the concrete protocolPrivateValue[PrivateMessageIEsValue].
type PrivateMessageIEsValueProtocolPrivateValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q7.PrivateMessageIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	matchesID(q7.PrivateIEID, *q5.DecodeBudget) bool
	decode(q7.PrivateIEID, q5.OpaqueOpenType) (q7.PrivateMessageIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	rule() q5.SourceRule
}

func BridgePrivateMessageIEsValueCaptureLPPaPrivateIEField(v *q7.PrivateMessageIEsValuePrivateIEField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q7.BridgePrivateMessageIEsValuePrivateIEFieldFieldStream(v))
	q7.BridgeCaptureLPPaPrivateIEID(&v.Id, s)
	q9.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q7.BridgePrivateMessageIEsValueMethodCaptureFraming(v.Value))
	v.Value = q7.BridgePrivateMessageIEsValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q7.BridgePrivateMessageIEsValueMethodCaptureSnapshot(v.Value))
	s.End(f, q7.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *q7.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}
func BridgePrivateMessageIEsValueCompareLPPaPrivateIEField(v *q7.PrivateMessageIEsValuePrivateIEField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q7.BridgeCompareLPPaPrivateIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q7.BridgePrivateMessageIEsValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q7.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *q7.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}

// resultGERANItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q13.ResultGERANItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q9.ProtocolIEID, q5.OpaqueOpenType) (q13.ResultGERANItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q9.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q9.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q8.ResultGERANItemExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q8.BridgeResultGERANItemExtIEsExtFieldFieldStream(v))
	q9.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q9.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q13.BridgeResultGERANItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q13.BridgeResultGERANItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q13.BridgeResultGERANItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q8.BridgeResultGERANItemExtIEsExtFieldFieldReplay(v), *q8.BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionField(v *q8.ResultGERANItemExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q13.BridgeResultGERANItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q8.BridgeResultGERANItemExtIEsExtFieldFieldReplay(v), *q8.BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v))
}

// resultRSRPItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q13.ResultRSRPItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q9.ProtocolIEID, q5.OpaqueOpenType) (q13.ResultRSRPItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q9.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q9.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q8.ResultRSRPItemExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q8.BridgeResultRSRPItemExtIEsExtFieldFieldStream(v))
	q9.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q9.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q13.BridgeResultRSRPItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q13.BridgeResultRSRPItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q13.BridgeResultRSRPItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q8.BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v), *q8.BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionField(v *q8.ResultRSRPItemExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q13.BridgeResultRSRPItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q8.BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v), *q8.BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v))
}

// OTDOAInformationFailureAPERValue is the concrete APERValue[OTDOAInformationFailure].
type OTDOAInformationFailureAPERValue struct {
	context q9.BridgeCodecContext
	Value   OTDOAInformationFailure

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationFailureAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOAInformationFailureAPERValue) WithoutReplay() OTDOAInformationFailureAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateMessageAPERValue is the concrete APERValue[PrivateMessage].
type PrivateMessageAPERValue struct {
	context q9.BridgeCodecContext
	Value   PrivateMessage

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PrivateMessageAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PrivateMessageAPERValue) WithoutReplay() PrivateMessageAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultGERANAPERValue is the concrete APERValue[ResultGERAN].
type ResultGERANAPERValue struct {
	context q9.BridgeCodecContext
	Value   ResultGERAN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ResultGERANAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ResultGERANAPERValue) WithoutReplay() ResultGERANAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultGERANItemAPERValue is the concrete APERValue[ResultGERANItem].
type ResultGERANItemAPERValue struct {
	context q9.BridgeCodecContext
	Value   ResultGERANItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ResultGERANItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ResultGERANItemAPERValue) WithoutReplay() ResultGERANItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRPAPERValue is the concrete APERValue[ResultRSRP].
type ResultRSRPAPERValue struct {
	context q9.BridgeCodecContext
	Value   ResultRSRP

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ResultRSRPAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ResultRSRPAPERValue) WithoutReplay() ResultRSRPAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRPItemAPERValue is the concrete APERValue[ResultRSRPItem].
type ResultRSRPItemAPERValue struct {
	context q9.BridgeCodecContext
	Value   ResultRSRPItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ResultRSRPItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ResultRSRPItemAPERValue) WithoutReplay() ResultRSRPItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOACellsExtIEsValueValidateLPPaIEContainer(fields q8.OTDOACellsExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgeOTDOACellsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgeOTDOACellsExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaIEContainer(fields q8.OTDOAInformationTypeItemExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaIEContainer(fields q8.PRSFrequencyHoppingConfigurationItemIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgePosSIBSegmentsExtIEsValueValidateLPPaIEContainer(fields q8.PosSIBSegmentsExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgePosSIBSegmentsExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgePosSIBsExtIEsValueValidateLPPaIEContainer(fields q8.PosSIBsExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgePosSIBsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgePosSIBsExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultGERANItemExtIEsValueValidateLPPaIEContainer(fields q8.ResultGERANItemExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeResultGERANItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeResultGERANItemExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultRSRPItemExtIEsValueValidateLPPaIEContainer(fields q8.ResultRSRPItemExtIEsIEContainer, rows []q9.FieldInfo, path string, budget *q5.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q9.ProtocolIEID]int, len(rows))
	counts := make(map[q9.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q10.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeResultRSRPItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeResultRSRPItemExtIEsValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.ValueIDMismatch, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.id", location.Path))}, Table: func() q9.TableID {
				sealed := q9.TableID{}
				*q9.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q9.FieldInfo
			related := []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.RepeatedIE, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q9.ValidationSeverityUnrecognized
			if _, globallyKnown := q8.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q9.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.NotAllowed), RelatedRules: q8.BridgeLppaHandlingRules(q9.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongCriticality, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q10.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q8.BridgeLppaValidationRule(q9.WrongCriticality), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.WrongOrder, Severity: q9.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.WrongOrder), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q9.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q9.MissingMandatory, Severity: q9.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q8.BridgeLppaValidationRule(q9.MissingMandatory), RelatedRules: []q5.SourceRule{q8.BridgeLppaAdoptedRule(q9.MissingMandatory), row.Rule}})
		}
		if row.Presence == q9.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q9.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// NewPrivateIEIDLocal creates a PrivateIEID with the local alternative.
func BridgeNewPrivateIEIDLocalLegacy(v int64) q7.PrivateIEID {
	return q7.PrivateIEID{
		Choice: q9.PrivateIEIDChoiceLocal,
		Local:  &v,
	}
}

// NewPrivateIEIDGlobal creates a PrivateIEID with the global alternative.
func BridgeNewPrivateIEIDGlobalLegacy(v q14.ObjectIdentifier) q7.PrivateIEID {
	return q7.PrivateIEID{
		Choice: q9.PrivateIEIDChoiceGlobal,
		Global: &v,
	}
}

// NewPrivateIEIDLocal constructs a checked complete value.
func NewPrivateIEIDLocal(v int64, options ...q5.BuildOption) (q7.PrivateIEID, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PrivateIEID{}, q5.OperationError(err, "PrivateIEIDLocal")
	}
	value := BridgeNewPrivateIEIDLocalLegacy(v)
	if _, err := q7.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PrivateIEID{}, q5.OperationError(err, "PrivateIEIDLocal")
	}
	return value, q5.OperationError(nil, "PrivateIEIDLocal")
}

// NewPrivateIEIDGlobal constructs a checked complete value.
func NewPrivateIEIDGlobal(v q14.ObjectIdentifier, options ...q5.BuildOption) (q7.PrivateIEID, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PrivateIEID{}, q5.OperationError(err, "PrivateIEIDGlobal")
	}
	value := BridgeNewPrivateIEIDGlobalLegacy(v)
	if _, err := q7.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PrivateIEID{}, q5.OperationError(err, "PrivateIEIDGlobal")
	}
	return value, q5.OperationError(nil, "PrivateIEIDGlobal")
}

// NewPRSMutingConfigurationTwo creates a PRSMutingConfiguration with the two alternative.
func BridgeNewPRSMutingConfigurationTwoLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice: q9.PRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewPRSMutingConfigurationFour creates a PRSMutingConfiguration with the four alternative.
func BridgeNewPRSMutingConfigurationFourLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice: q9.PRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewPRSMutingConfigurationSixteen creates a PRSMutingConfiguration with the sixteen alternative.
func BridgeNewPRSMutingConfigurationSixteenLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:  q9.PRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NewPRSMutingConfigurationThirtyTwo creates a PRSMutingConfiguration with the thirty-two alternative.
func BridgeNewPRSMutingConfigurationThirtyTwoLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:    q9.PRSMutingConfigurationChoiceThirtyTwo,
		ThirtyTwo: &v,
	}
}

// NewPRSMutingConfigurationSixtyFour creates a PRSMutingConfiguration with the sixty-four alternative.
func BridgeNewPRSMutingConfigurationSixtyFourLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:    q9.PRSMutingConfigurationChoiceSixtyFour,
		SixtyFour: &v,
	}
}

// NewPRSMutingConfigurationOneHundredAndTwentyEight creates a PRSMutingConfiguration with the one-hundred-and-twenty-eight alternative.
func BridgeNewPRSMutingConfigurationOneHundredAndTwentyEightLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:                   q9.PRSMutingConfigurationChoiceOneHundredAndTwentyEight,
		OneHundredAndTwentyEight: &v,
	}
}

// NewPRSMutingConfigurationTwoHundredAndFiftySix creates a PRSMutingConfiguration with the two-hundred-and-fifty-six alternative.
func BridgeNewPRSMutingConfigurationTwoHundredAndFiftySixLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:                q9.PRSMutingConfigurationChoiceTwoHundredAndFiftySix,
		TwoHundredAndFiftySix: &v,
	}
}

// NewPRSMutingConfigurationOneThousandAndTwentyFour creates a PRSMutingConfiguration with the one-thousand-and-twenty-four alternative.
func BridgeNewPRSMutingConfigurationOneThousandAndTwentyFourLegacy(v q14.BitString) q7.PRSMutingConfiguration {
	return q7.PRSMutingConfiguration{
		Choice:                   q9.PRSMutingConfigurationChoiceOneThousandAndTwentyFour,
		OneThousandAndTwentyFour: &v,
	}
}

type ResultRSRP = []ResultRSRPItem

// ResultRSRPItem represents the ASN.1 type ResultRSRP-Item (SEQUENCE).
type ResultRSRPItem struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	PCI               q9.PCI                              `asn1:"tag:0,context,implicit"`
	EARFCN            q9.EARFCN                           `asn1:"tag:1,context,implicit"`
	ECGI              *q15.ECGI                           `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRP         q9.ValueRSRP                        `asn1:"tag:3,context,implicit"`
	IEExtensions      q8.ResultRSRPItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                `asn1:"-" json:"-"`
	extCount          int64                               `asn1:"-" json:"-"`
	extPresent        []bool                              `asn1:"-" json:"-"`
	extData           [][]byte                            `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}
type ResultGERAN = []ResultGERANItem

// ResultGERANItem represents the ASN.1 type ResultGERAN-Item (SEQUENCE).
type ResultGERANItem struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	BCCH              q9.BCCH                              `asn1:"tag:0,context,implicit"`
	PhysCellIDGERAN   q9.PhysCellIDGERAN                   `asn1:"tag:1,context,implicit"`
	RSSI              q9.RSSI                              `asn1:"tag:2,context,implicit"`
	IEExtensions      q8.ResultGERANItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// NewSubframeallocationOneFrame creates a Subframeallocation with the oneFrame alternative.
func BridgeNewSubframeallocationOneFrameLegacy(v q14.BitString) q11.Subframeallocation {
	return q11.Subframeallocation{
		Choice:   q9.SubframeallocationChoiceOneFrame,
		OneFrame: &v,
	}
}

// NewSubframeallocationFourFrames creates a Subframeallocation with the fourFrames alternative.
func BridgeNewSubframeallocationFourFramesLegacy(v q14.BitString) q11.Subframeallocation {
	return q11.Subframeallocation{
		Choice:     q9.SubframeallocationChoiceFourFrames,
		FourFrames: &v,
	}
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-FDD alternative.
func BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDDLegacy(v q9.PhysCellIDUTRAFDD) q7.ResultUTRANItemPhysCellIDUTRAN {
	return q7.ResultUTRANItemPhysCellIDUTRAN{
		Choice:            q9.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD,
		PhysCellIDUTRAFDD: v,
	}
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-TDD alternative.
func BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDDLegacy(v q9.PhysCellIDUTRATDD) q7.ResultUTRANItemPhysCellIDUTRAN {
	return q7.ResultUTRANItemPhysCellIDUTRAN{
		Choice:            q9.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD,
		PhysCellIDUTRATDD: v,
	}
}

type BridgeAsn1cAPERResultRSRPListValue struct{ Value ResultRSRP }

// MarshalAPERResultRSRPTo appends a ResultRSRP list to bb.
func BridgeMarshalAPERResultRSRPTo(list ResultRSRP, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultRSRPListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q10.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q10.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q10.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ResultRSRPItem to APER format.
func (v *ResultRSRPItem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultRSRPItem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q15.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q5.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.PCI, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound17, true); err != nil {
		return q10.Errorf("encoding pCI: %w", err)
	}
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound20, true); err != nil {
		return q10.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := q15.BridgeECGIMethodMarshalAPERTo(v.ECGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q10.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRP, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound22, true); err != nil {
		return q10.Errorf("encoding valueRSRP: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q10.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q8.BridgeResultRSRPItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q10.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q10.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q10.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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

// UnmarshalAPER decodes ResultRSRPItem from APER format.
func (v *ResultRSRPItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultRSRPItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultRSRPItem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q14.WrapDecodePath(err, "ResultRSRPItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q14.WrapDecodePath(err, "ResultRSRPItem")
	}
	padding, err := q5.CaptureFinalBits(bb, "ResultRSRPItem")
	if err != nil {
		return q14.WrapDecodePath(err, "ResultRSRPItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultRSRPItem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItem{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return q14.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return q14.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		toleranceMark_ecgi := bb.EnterComponent("ECGI")
		var dec_ecgi q15.ECGI
		if err := q15.BridgeECGIMethodUnmarshalAPERFrom(&dec_ecgi, bb); err != nil {
			return q14.WrapDecodePath(err, "ECGI")
		}
		if err := q5.ChargeValue(bb, dec_ecgi); err != nil {
			return err
		}
		v.ECGI = &dec_ecgi
		bb.LeaveComponent(toleranceMark_ecgi)
	}
	val_valuersrp, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound22, true)
	if err != nil {
		return q14.WrapDecodePath(err, "ValueRSRP")
	}
	v.ValueRSRP = val_valuersrp
	if opt_ieextensions {
		tmp_ieextensions := make(q8.ResultRSRPItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q10.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q8.ResultRSRPItemExtIEsExtField
				if err := q8.BridgeResultRSRPItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q14.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q14.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("ExtData_[%d]", i))
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

type BridgeAsn1cAPERResultGERANListValue struct{ Value ResultGERAN }

// MarshalAPERResultGERANTo appends a ResultGERAN list to bb.
func BridgeMarshalAPERResultGERANTo(list ResultGERAN, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultGERANListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q10.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q10.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q10.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ResultGERANItem to APER format.
func (v *ResultGERANItem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultGERANItem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q15.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.BCCH, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound4, true); err != nil {
		return q10.Errorf("encoding bCCH: %w", err)
	}
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDGERAN, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound19, true); err != nil {
		return q10.Errorf("encoding physCellIDGERAN: %w", err)
	}
	if err := q5.EncodeIntegerBigBoundsAligned(bb, v.RSSI, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound19, true); err != nil {
		return q10.Errorf("encoding rSSI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q10.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q8.BridgeResultGERANItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q10.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q10.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q10.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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

// UnmarshalAPER decodes ResultGERANItem from APER format.
func (v *ResultGERANItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultGERANItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultGERANItem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q14.WrapDecodePath(err, "ResultGERANItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q14.WrapDecodePath(err, "ResultGERANItem")
	}
	padding, err := q5.CaptureFinalBits(bb, "ResultGERANItem")
	if err != nil {
		return q14.WrapDecodePath(err, "ResultGERANItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultGERANItem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItem{}
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
	val_bcch, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound4, true)
	if err != nil {
		return q14.WrapDecodePath(err, "BCCH")
	}
	v.BCCH = val_bcch
	val_physcellidgeran, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound19, true)
	if err != nil {
		return q14.WrapDecodePath(err, "PhysCellIDGERAN")
	}
	v.PhysCellIDGERAN = val_physcellidgeran
	val_rssi, err := q5.DecodeIntegerBigBoundsAligned(bb, q9.BridgeAsn1IntegerBound1, q9.BridgeAsn1IntegerBound19, true)
	if err != nil {
		return q14.WrapDecodePath(err, "RSSI")
	}
	v.RSSI = val_rssi
	if opt_ieextensions {
		tmp_ieextensions := make(q8.ResultGERANItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q10.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q8.ResultGERANItemExtIEsExtField
				if err := q8.BridgeResultGERANItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q14.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q14.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("ExtData_[%d]", i))
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
func (v *ResultGERANItem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultGERANItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultGERANItem) WithoutReplay() ResultGERANItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero ResultGERANItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRPItem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRPItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRPItem) WithoutReplay() ResultRSRPItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero ResultRSRPItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ResultGERANItem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultGERANItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultGERANItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultRSRPItem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultRSRPItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultRSRPItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ResultGERANItem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "ResultGERANItem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "ResultGERANItem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaResultGERANItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "ResultGERANItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "ResultGERANItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "ResultGERANItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "ResultGERANItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "ResultGERANItem")
}
func (v *ResultGERANItem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultGERANItem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultGERANItem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaResultGERANItem(v, &s)
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
func (v *ResultGERANItem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultGERANItem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultRSRPItem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "ResultRSRPItem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "ResultRSRPItem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRPItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "ResultRSRPItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "ResultRSRPItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "ResultRSRPItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "ResultRSRPItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "ResultRSRPItem")
}
func (v *ResultRSRPItem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRPItem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRPItem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaResultRSRPItem(v, &s)
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
func (v *ResultRSRPItem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRPItem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultGERANItem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "ResultGERANItem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded ResultGERANItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultGERANItem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = ResultGERANItem{}
		return report, q5.OperationError(err, "ResultGERANItem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "ResultGERANItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRPItem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "ResultRSRPItem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRPItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRPItem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRPItem{}
		return report, q5.OperationError(err, "ResultRSRPItem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "ResultRSRPItem")
}

// NewPRSMutingConfigurationTwo constructs a checked complete value.
func NewPRSMutingConfigurationTwo(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationTwo")
	}
	value := BridgeNewPRSMutingConfigurationTwoLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationTwo")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationTwo")
}

// NewPRSMutingConfigurationFour constructs a checked complete value.
func NewPRSMutingConfigurationFour(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationFour")
	}
	value := BridgeNewPRSMutingConfigurationFourLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationFour")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationFour")
}

// NewPRSMutingConfigurationSixteen constructs a checked complete value.
func NewPRSMutingConfigurationSixteen(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationSixteen")
	}
	value := BridgeNewPRSMutingConfigurationSixteenLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationSixteen")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationSixteen")
}

// NewPRSMutingConfigurationThirtyTwo constructs a checked complete value.
func NewPRSMutingConfigurationThirtyTwo(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationThirtyTwo")
	}
	value := BridgeNewPRSMutingConfigurationThirtyTwoLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationThirtyTwo")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationThirtyTwo")
}

// NewPRSMutingConfigurationSixtyFour constructs a checked complete value.
func NewPRSMutingConfigurationSixtyFour(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationSixtyFour")
	}
	value := BridgeNewPRSMutingConfigurationSixtyFourLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationSixtyFour")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationSixtyFour")
}

// NewPRSMutingConfigurationOneHundredAndTwentyEight constructs a checked complete value.
func NewPRSMutingConfigurationOneHundredAndTwentyEight(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationOneHundredAndTwentyEight")
	}
	value := BridgeNewPRSMutingConfigurationOneHundredAndTwentyEightLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationOneHundredAndTwentyEight")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationOneHundredAndTwentyEight")
}

// NewPRSMutingConfigurationTwoHundredAndFiftySix constructs a checked complete value.
func NewPRSMutingConfigurationTwoHundredAndFiftySix(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationTwoHundredAndFiftySix")
	}
	value := BridgeNewPRSMutingConfigurationTwoHundredAndFiftySixLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationTwoHundredAndFiftySix")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationTwoHundredAndFiftySix")
}

// NewPRSMutingConfigurationOneThousandAndTwentyFour constructs a checked complete value.
func NewPRSMutingConfigurationOneThousandAndTwentyFour(v q14.BitString, options ...q5.BuildOption) (q7.PRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationOneThousandAndTwentyFour")
	}
	value := BridgeNewPRSMutingConfigurationOneThousandAndTwentyFourLegacy(v)
	if _, err := q7.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.PRSMutingConfiguration{}, q5.OperationError(err, "PRSMutingConfigurationOneThousandAndTwentyFour")
	}
	return value, q5.OperationError(nil, "PRSMutingConfigurationOneThousandAndTwentyFour")
}

// NewSubframeallocationOneFrame constructs a checked complete value.
func NewSubframeallocationOneFrame(v q14.BitString, options ...q5.BuildOption) (q11.Subframeallocation, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q11.Subframeallocation{}, q5.OperationError(err, "SubframeallocationOneFrame")
	}
	value := BridgeNewSubframeallocationOneFrameLegacy(v)
	if _, err := q11.BridgeSubframeallocationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q11.Subframeallocation{}, q5.OperationError(err, "SubframeallocationOneFrame")
	}
	return value, q5.OperationError(nil, "SubframeallocationOneFrame")
}

// NewSubframeallocationFourFrames constructs a checked complete value.
func NewSubframeallocationFourFrames(v q14.BitString, options ...q5.BuildOption) (q11.Subframeallocation, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q11.Subframeallocation{}, q5.OperationError(err, "SubframeallocationFourFrames")
	}
	value := BridgeNewSubframeallocationFourFramesLegacy(v)
	if _, err := q11.BridgeSubframeallocationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q11.Subframeallocation{}, q5.OperationError(err, "SubframeallocationFourFrames")
	}
	return value, q5.OperationError(nil, "SubframeallocationFourFrames")
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD constructs a checked complete value.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD(v q9.PhysCellIDUTRAFDD, options ...q5.BuildOption) (q7.ResultUTRANItemPhysCellIDUTRAN, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.ResultUTRANItemPhysCellIDUTRAN{}, q5.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
	}
	value := BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDDLegacy(v)
	if _, err := q7.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.ResultUTRANItemPhysCellIDUTRAN{}, q5.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
	}
	return value, q5.OperationError(nil, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD constructs a checked complete value.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD(v q9.PhysCellIDUTRATDD, options ...q5.BuildOption) (q7.ResultUTRANItemPhysCellIDUTRAN, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q7.ResultUTRANItemPhysCellIDUTRAN{}, q5.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
	}
	value := BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDDLegacy(v)
	if _, err := q7.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q7.ResultUTRANItemPhysCellIDUTRAN{}, q5.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
	}
	return value, q5.OperationError(nil, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
}

// OTDOAInformationFailure represents the ASN.1 type OTDOAInformationFailure (SEQUENCE).
type OTDOAInformationFailure struct {
	replay           q5.Snapshot
	stream           q5.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q5.WireSpan
	ProtocolIEs      q4.OTDOAInformationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       q5.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []q5.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []q5.OpaqueOrigin
	extWire          []q5.WireSpan
}

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage struct {
	replay          q5.Snapshot
	stream          q5.WireSpan
	withoutReplay   bool
	received        bool
	receivedBytes   q5.WireSpan
	PrivateIEs      q7.PrivateMessageIEsValuePrivateIEContainer `asn1:"tag:0,context,implicit"`
	privateIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount        int64                                       `asn1:"-" json:"-"`
	extPresent      []bool                                      `asn1:"-" json:"-"`
	extData         [][]byte                                    `asn1:"-" json:"-"`
	perPadding      q5.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding   []q5.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin       []q5.OpaqueOrigin
	extWire         []q5.WireSpan
}

// MarshalAPER encodes OTDOAInformationFailure to APER format.
func (v *OTDOAInformationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationFailure) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q15.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
			return q10.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q4.BridgeOTDOAInformationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q10.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q10.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q10.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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

// UnmarshalAPER decodes OTDOAInformationFailure from APER format.
func (v *OTDOAInformationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationFailure) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q14.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q14.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	padding, err := q5.CaptureFinalBits(bb, "OTDOAInformationFailure")
	if err != nil {
		return q14.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationFailure) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationFailure{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q4.OTDOAInformationFailureIEContainer, 0)
	_, errCollection_protocolies := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q10.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q4.OTDOAInformationFailureIEField
			if err := q4.BridgeOTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q14.WrapDecodePath(err, q10.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
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
		return q14.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q14.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes PrivateMessage to APER format.
func (v *PrivateMessage) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PrivateMessage) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q15.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q5.EncodeCollection(bb, int64(len(v.PrivateIEs)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_privateies < 0 || fragmentOffset_privateies > int64(len(v.PrivateIEs)) || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(len(v.PrivateIEs[fragmentOffset_privateies:])) {
			return q10.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := q7.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q10.Errorf("encoding privateIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q10.Errorf("encoding privateIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q10.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateMessage) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q14.WrapDecodePath(err, "PrivateMessage")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q14.WrapDecodePath(err, "PrivateMessage")
	}
	padding, err := q5.CaptureFinalBits(bb, "PrivateMessage")
	if err != nil {
		return q14.WrapDecodePath(err, "PrivateMessage")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PrivateMessage) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessage{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.PrivateIEs = make(q7.PrivateMessageIEsValuePrivateIEContainer, 0)
	_, errCollection_privateies := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_privateies < 0 || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(^uint(0)>>1) || fragmentOffset_privateies > int64(^uint(0)>>1)-fragmentLength_privateies {
			return q10.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem q7.PrivateMessageIEsValuePrivateIEField
			if err := q7.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q14.WrapDecodePath(err, q10.Sprintf("PrivateIEs[%d]", fragmentOffset_privateies+i))
			}
			if next, err := q5.AppendValues(bb, v.PrivateIEs, elem); err != nil {
				return err
			} else {
				v.PrivateIEs = next
			}
		}
		return nil
	})
	if errCollection_privateies != nil {
		return q14.WrapDecodePath(errCollection_privateies, "PrivateIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q14.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q10.Errorf("extension count out of range")
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
			return q10.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q14.WrapDecodePath(err, q10.Sprintf("ExtData_[%d]", i))
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
func (v *OTDOAInformationFailure) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationFailure) WithoutReplay() OTDOAInformationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero OTDOAInformationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PrivateMessage) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateMessage", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateMessage) WithoutReplay() PrivateMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero PrivateMessage
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationFailure) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PrivateMessage) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PrivateMessage) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PrivateMessage) RemoveExtension(index uint64) error {
	if v == nil {
		return q14.WrapDecodePath(q5.ErrInvalidValue, q10.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q14.WrapDecodePath(err, q10.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *OTDOAInformationFailure) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "OTDOAInformationFailure")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "OTDOAInformationFailure")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "OTDOAInformationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "OTDOAInformationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "OTDOAInformationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "OTDOAInformationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "OTDOAInformationFailure")
}
func (v *OTDOAInformationFailure) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationFailure) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationFailure) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOAInformationFailure(v, &s)
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
func (v *OTDOAInformationFailure) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationFailure) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PrivateMessage) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "PrivateMessage")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "PrivateMessage")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaPrivateMessage(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "PrivateMessage")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "PrivateMessage")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "PrivateMessage")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "PrivateMessage")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "PrivateMessage")
}
func (v *PrivateMessage) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PrivateMessage) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PrivateMessage) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaPrivateMessage(v, &s)
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
func (v *PrivateMessage) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PrivateMessage) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *OTDOAInformationFailure) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "OTDOAInformationFailure")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationFailure(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationFailure{}
		return report, q5.OperationError(err, "OTDOAInformationFailure")
	}
	*v = decoded
	return report, q5.OperationError(nil, "OTDOAInformationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PrivateMessage) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "PrivateMessage")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded PrivateMessage
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPrivateMessage(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = PrivateMessage{}
		return report, q5.OperationError(err, "PrivateMessage")
	}
	*v = decoded
	return report, q5.OperationError(nil, "PrivateMessage")
}
func BridgeCaptureLPPaOTDOAInformationFailure(v *OTDOAInformationFailure, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationFailure(v *OTDOAInformationFailure, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationType(v *q6.OTDOAInformationType, s *q5.SemanticCapture) {
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
			BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaOTDOAInformationType(v *q6.OTDOAInformationType, s *q5.SemanticComparison) {
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
			BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaPrivateMessage(v *PrivateMessage, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgePrivateMessageIEsValueCaptureLPPaPrivateIEContainer(&v.PrivateIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPrivateMessage(v *PrivateMessage, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgePrivateMessageIEsValueCompareLPPaPrivateIEContainer(&v.PrivateIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultGERAN(v *ResultGERAN, s *q5.SemanticCapture) {
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
			BridgeCaptureLPPaResultGERANItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultGERAN(v *ResultGERAN, s *q5.SemanticComparison) {
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
			BridgeCompareLPPaResultGERANItem(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaResultGERANItem(v *ResultGERANItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q9.BridgeCaptureLPPaBCCH(&v.BCCH, s)
	q9.BridgeCaptureLPPaPhysCellIDGERAN(&v.PhysCellIDGERAN, s)
	q9.BridgeCaptureLPPaRSSI(&v.RSSI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultGERANItem(v *ResultGERANItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaBCCH(&v.BCCH, s)
	q12.BridgeCompareLPPaPhysCellIDGERAN(&v.PhysCellIDGERAN, s)
	q13.BridgeCompareLPPaRSSI(&v.RSSI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRP(v *ResultRSRP, s *q5.SemanticCapture) {
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
			BridgeCaptureLPPaResultRSRPItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultRSRP(v *ResultRSRP, s *q5.SemanticComparison) {
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
			BridgeCompareLPPaResultRSRPItem(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaResultRSRPItem(v *ResultRSRPItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q9.BridgeCaptureLPPaPCI(&v.PCI, s)
	q9.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			q15.BridgeCaptureLPPaECGI(v.ECGI, s)
		}
		s.End(f, nil, false)
	}
	q9.BridgeCaptureLPPaValueRSRP(&v.ValueRSRP, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRPItem(v *ResultRSRPItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaPCI(&v.PCI, s)
	q12.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			q15.BridgeCompareLPPaECGI(v.ECGI, s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	q13.BridgeCompareLPPaValueRSRP(&v.ValueRSRP, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

// ResultGERANItemCodec binds the complete source value type.
func ResultGERANItemCodec() ResultGERANItemValueCodec {
	return ResultGERANItemValueCodec{path: "ResultGERANItem", decode: func(data []byte, options q5.DecodeState) (ResultGERANItem, error) {
		var value ResultGERANItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultGERANItem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultGERANItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultGERANItem, options q5.DecodeState) (ResultGERANItem, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultGERANItem(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultGERANItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultGERANItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q9.BridgeCodecContext {
		sealed := q9.BridgeCodecContext{}
		*q9.BridgecodecContextFieldSource(&sealed) = "source-value:ResultGERANItem"
		return sealed
	}(),
	}
}

// ResultRSRPItemCodec binds the complete source value type.
func ResultRSRPItemCodec() ResultRSRPItemValueCodec {
	return ResultRSRPItemValueCodec{path: "ResultRSRPItem", decode: func(data []byte, options q5.DecodeState) (ResultRSRPItem, error) {
		var value ResultRSRPItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultRSRPItem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultRSRPItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultRSRPItem, options q5.DecodeState) (ResultRSRPItem, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultRSRPItem(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultRSRPItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultRSRPItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q9.BridgeCodecContext {
		sealed := q9.BridgeCodecContext{}
		*q9.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRPItem"
		return sealed
	}(),
	}
}
func BridgeOTDOAInformationFailureAPERValueFieldContext(v *OTDOAInformationFailureAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureAPERValueFieldReceived(v *OTDOAInformationFailureAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationFailureAPERValueFieldReplay(v *OTDOAInformationFailureAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureAPERValueFieldWithoutReplay(v *OTDOAInformationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureFieldExtCount(v *OTDOAInformationFailure) *int64 {
	return &v.extCount
}
func BridgeOTDOAInformationFailureFieldExtData(v *OTDOAInformationFailure) *[][]byte {
	return &v.extData
}
func BridgeOTDOAInformationFailureFieldExtOrigin(v *OTDOAInformationFailure) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationFailureFieldExtPresent(v *OTDOAInformationFailure) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationFailureFieldExtWire(v *OTDOAInformationFailure) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationFailureFieldPerExtPadding(v *OTDOAInformationFailure) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationFailureFieldPerPadding(v *OTDOAInformationFailure) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationFailureFieldProtocolIEsIndef(v *OTDOAInformationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationFailureFieldReceived(v *OTDOAInformationFailure) *bool { return &v.received }
func BridgeOTDOAInformationFailureFieldReceivedBytes(v *OTDOAInformationFailure) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationFailureFieldReplay(v *OTDOAInformationFailure) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureFieldStream(v *OTDOAInformationFailure) *q5.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationFailureFieldWithoutReplay(v *OTDOAInformationFailure) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v *OTDOAInformationFailure, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERChanged(v *OTDOAInformationFailure, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERChangedValue(v *OTDOAInformationFailure, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERFreshValue(v *OTDOAInformationFailure, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERLegacy(v *OTDOAInformationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationFailureMethodMarshalAPERPlanned(v *OTDOAInformationFailure, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERTo(v *OTDOAInformationFailure, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERFrom(v *OTDOAInformationFailure, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERLegacy(v *OTDOAInformationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERWithOptions(v *OTDOAInformationFailure, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationFailureValueCodecFieldCapture(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, q5.DecodeState) (OTDOAInformationFailure, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationFailureValueCodecFieldCompare(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationFailureValueCodecFieldContext(v *OTDOAInformationFailureValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureValueCodecFieldDecode(v *OTDOAInformationFailureValueCodec) *func([]byte, q5.DecodeState) (OTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeOTDOAInformationFailureValueCodecFieldEncode(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationFailureValueCodecFieldPath(v *OTDOAInformationFailureValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOAInformationFailureValueCodecMethodEncodeBudget(v OTDOAInformationFailureValueCodec, a0 OTDOAInformationFailure, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationFailureValueCodecMethodEncodeChanged(v OTDOAInformationFailureValueCodec, a0 OTDOAInformationFailure, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageAPERValueFieldContext(v *PrivateMessageAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageAPERValueFieldReceived(v *PrivateMessageAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePrivateMessageAPERValueFieldReplay(v *PrivateMessageAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePrivateMessageAPERValueFieldWithoutReplay(v *PrivateMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageFieldExtCount(v *PrivateMessage) *int64              { return &v.extCount }
func BridgePrivateMessageFieldExtData(v *PrivateMessage) *[][]byte            { return &v.extData }
func BridgePrivateMessageFieldExtOrigin(v *PrivateMessage) *[]q5.OpaqueOrigin { return &v.extOrigin }
func BridgePrivateMessageFieldExtPresent(v *PrivateMessage) *[]bool           { return &v.extPresent }
func BridgePrivateMessageFieldExtWire(v *PrivateMessage) *[]q5.WireSpan       { return &v.extWire }
func BridgePrivateMessageFieldPerExtPadding(v *PrivateMessage) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgePrivateMessageFieldPerPadding(v *PrivateMessage) *q5.FinalPadding { return &v.perPadding }
func BridgePrivateMessageFieldPrivateIEsIndef(v *PrivateMessage) *bool       { return &v.privateIEsIndef }
func BridgePrivateMessageFieldReceived(v *PrivateMessage) *bool              { return &v.received }
func BridgePrivateMessageFieldReceivedBytes(v *PrivateMessage) *q5.WireSpan  { return &v.receivedBytes }
func BridgePrivateMessageFieldReplay(v *PrivateMessage) *q5.Snapshot         { return &v.replay }
func BridgePrivateMessageFieldStream(v *PrivateMessage) *q5.WireSpan         { return &v.stream }
func BridgePrivateMessageFieldWithoutReplay(v *PrivateMessage) *bool         { return &v.withoutReplay }
func BridgePrivateMessageMethodMarshalAPERBudget(v *PrivateMessage, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERChanged(v *PrivateMessage, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERChangedValue(v *PrivateMessage, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERFreshValue(v *PrivateMessage, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERLegacy(v *PrivateMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateMessageMethodMarshalAPERPlanned(v *PrivateMessage, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERTo(v *PrivateMessage, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageMethodUnmarshalAPERFrom(v *PrivateMessage, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERLegacy(v *PrivateMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERWithOptions(v *PrivateMessage, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateMessageValueCodecFieldCapture(v *PrivateMessageValueCodec) *func(PrivateMessage, q5.DecodeState) (PrivateMessage, q5.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageValueCodecFieldCompare(v *PrivateMessageValueCodec) *func(PrivateMessage, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePrivateMessageValueCodecFieldContext(v *PrivateMessageValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageValueCodecFieldDecode(v *PrivateMessageValueCodec) *func([]byte, q5.DecodeState) (PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageValueCodecFieldEncode(v *PrivateMessageValueCodec) *func(PrivateMessage, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageValueCodecFieldPath(v *PrivateMessageValueCodec) *q5.Path { return &v.path }
func BridgePrivateMessageValueCodecMethodEncodeBudget(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePrivateMessageValueCodecMethodEncodeChanged(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultGERANAPERValueFieldContext(v *ResultGERANAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANAPERValueFieldReceived(v *ResultGERANAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeResultGERANAPERValueFieldReplay(v *ResultGERANAPERValue) *q5.Snapshot { return &v.replay }
func BridgeResultGERANAPERValueFieldWithoutReplay(v *ResultGERANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemAPERValueFieldContext(v *ResultGERANItemAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANItemAPERValueFieldReceived(v *ResultGERANItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeResultGERANItemAPERValueFieldReplay(v *ResultGERANItemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemAPERValueFieldWithoutReplay(v *ResultGERANItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemFieldExtCount(v *ResultGERANItem) *int64              { return &v.extCount }
func BridgeResultGERANItemFieldExtData(v *ResultGERANItem) *[][]byte            { return &v.extData }
func BridgeResultGERANItemFieldExtOrigin(v *ResultGERANItem) *[]q5.OpaqueOrigin { return &v.extOrigin }
func BridgeResultGERANItemFieldExtPresent(v *ResultGERANItem) *[]bool           { return &v.extPresent }
func BridgeResultGERANItemFieldExtWire(v *ResultGERANItem) *[]q5.WireSpan       { return &v.extWire }
func BridgeResultGERANItemFieldIEExtensionsIndef(v *ResultGERANItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultGERANItemFieldPerExtPadding(v *ResultGERANItem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultGERANItemFieldPerPadding(v *ResultGERANItem) *q5.FinalPadding { return &v.perPadding }
func BridgeResultGERANItemFieldReceived(v *ResultGERANItem) *bool              { return &v.received }
func BridgeResultGERANItemFieldReceivedBytes(v *ResultGERANItem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeResultGERANItemFieldReplay(v *ResultGERANItem) *q5.Snapshot { return &v.replay }
func BridgeResultGERANItemFieldStream(v *ResultGERANItem) *q5.WireSpan { return &v.stream }
func BridgeResultGERANItemFieldWithoutReplay(v *ResultGERANItem) *bool { return &v.withoutReplay }
func BridgeResultGERANItemMethodMarshalAPERBudget(v *ResultGERANItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERChanged(v *ResultGERANItem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultGERANItemMethodMarshalAPERChangedValue(v *ResultGERANItem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultGERANItemMethodMarshalAPERFreshValue(v *ResultGERANItem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERLegacy(v *ResultGERANItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultGERANItemMethodMarshalAPERPlanned(v *ResultGERANItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERTo(v *ResultGERANItem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemMethodUnmarshalAPERFrom(v *ResultGERANItem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemMethodUnmarshalAPERLegacy(v *ResultGERANItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultGERANItemMethodUnmarshalAPERWithOptions(v *ResultGERANItem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultGERANItemValueCodecFieldCapture(v *ResultGERANItemValueCodec) *func(ResultGERANItem, q5.DecodeState) (ResultGERANItem, q5.Snapshot) {
	return &v.capture
}
func BridgeResultGERANItemValueCodecFieldCompare(v *ResultGERANItemValueCodec) *func(ResultGERANItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeResultGERANItemValueCodecFieldContext(v *ResultGERANItemValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANItemValueCodecFieldDecode(v *ResultGERANItemValueCodec) *func([]byte, q5.DecodeState) (ResultGERANItem, error) {
	return &v.decode
}
func BridgeResultGERANItemValueCodecFieldEncode(v *ResultGERANItemValueCodec) *func(ResultGERANItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultGERANItemValueCodecFieldPath(v *ResultGERANItemValueCodec) *q5.Path { return &v.path }
func BridgeResultGERANItemValueCodecMethodEncodeBudget(v ResultGERANItemValueCodec, a0 ResultGERANItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultGERANItemValueCodecMethodEncodeChanged(v ResultGERANItemValueCodec, a0 ResultGERANItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultGERANValueCodecFieldCapture(v *ResultGERANValueCodec) *func(ResultGERAN, q5.DecodeState) (ResultGERAN, q5.Snapshot) {
	return &v.capture
}
func BridgeResultGERANValueCodecFieldCompare(v *ResultGERANValueCodec) *func(ResultGERAN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeResultGERANValueCodecFieldContext(v *ResultGERANValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANValueCodecFieldDecode(v *ResultGERANValueCodec) *func([]byte, q5.DecodeState) (ResultGERAN, error) {
	return &v.decode
}
func BridgeResultGERANValueCodecFieldEncode(v *ResultGERANValueCodec) *func(ResultGERAN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultGERANValueCodecFieldPath(v *ResultGERANValueCodec) *q5.Path { return &v.path }
func BridgeResultGERANValueCodecMethodEncodeBudget(v ResultGERANValueCodec, a0 ResultGERAN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultGERANValueCodecMethodEncodeChanged(v ResultGERANValueCodec, a0 ResultGERAN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPAPERValueFieldContext(v *ResultRSRPAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPAPERValueFieldReceived(v *ResultRSRPAPERValue) *q5.WireSpan { return &v.received }
func BridgeResultRSRPAPERValueFieldReplay(v *ResultRSRPAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeResultRSRPAPERValueFieldWithoutReplay(v *ResultRSRPAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemAPERValueFieldContext(v *ResultRSRPItemAPERValue) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPItemAPERValueFieldReceived(v *ResultRSRPItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeResultRSRPItemAPERValueFieldReplay(v *ResultRSRPItemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemAPERValueFieldWithoutReplay(v *ResultRSRPItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemFieldExtCount(v *ResultRSRPItem) *int64              { return &v.extCount }
func BridgeResultRSRPItemFieldExtData(v *ResultRSRPItem) *[][]byte            { return &v.extData }
func BridgeResultRSRPItemFieldExtOrigin(v *ResultRSRPItem) *[]q5.OpaqueOrigin { return &v.extOrigin }
func BridgeResultRSRPItemFieldExtPresent(v *ResultRSRPItem) *[]bool           { return &v.extPresent }
func BridgeResultRSRPItemFieldExtWire(v *ResultRSRPItem) *[]q5.WireSpan       { return &v.extWire }
func BridgeResultRSRPItemFieldIEExtensionsIndef(v *ResultRSRPItem) *bool      { return &v.iEExtensionsIndef }
func BridgeResultRSRPItemFieldPerExtPadding(v *ResultRSRPItem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultRSRPItemFieldPerPadding(v *ResultRSRPItem) *q5.FinalPadding { return &v.perPadding }
func BridgeResultRSRPItemFieldReceived(v *ResultRSRPItem) *bool              { return &v.received }
func BridgeResultRSRPItemFieldReceivedBytes(v *ResultRSRPItem) *q5.WireSpan  { return &v.receivedBytes }
func BridgeResultRSRPItemFieldReplay(v *ResultRSRPItem) *q5.Snapshot         { return &v.replay }
func BridgeResultRSRPItemFieldStream(v *ResultRSRPItem) *q5.WireSpan         { return &v.stream }
func BridgeResultRSRPItemFieldWithoutReplay(v *ResultRSRPItem) *bool         { return &v.withoutReplay }
func BridgeResultRSRPItemMethodMarshalAPERBudget(v *ResultRSRPItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERChanged(v *ResultRSRPItem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRPItemMethodMarshalAPERChangedValue(v *ResultRSRPItem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRPItemMethodMarshalAPERFreshValue(v *ResultRSRPItem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERLegacy(v *ResultRSRPItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRPItemMethodMarshalAPERPlanned(v *ResultRSRPItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERTo(v *ResultRSRPItem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemMethodUnmarshalAPERFrom(v *ResultRSRPItem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemMethodUnmarshalAPERLegacy(v *ResultRSRPItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRPItemMethodUnmarshalAPERWithOptions(v *ResultRSRPItem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRPItemValueCodecFieldCapture(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, q5.DecodeState) (ResultRSRPItem, q5.Snapshot) {
	return &v.capture
}
func BridgeResultRSRPItemValueCodecFieldCompare(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRPItemValueCodecFieldContext(v *ResultRSRPItemValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPItemValueCodecFieldDecode(v *ResultRSRPItemValueCodec) *func([]byte, q5.DecodeState) (ResultRSRPItem, error) {
	return &v.decode
}
func BridgeResultRSRPItemValueCodecFieldEncode(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRPItemValueCodecFieldPath(v *ResultRSRPItemValueCodec) *q5.Path { return &v.path }
func BridgeResultRSRPItemValueCodecMethodEncodeBudget(v ResultRSRPItemValueCodec, a0 ResultRSRPItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRPItemValueCodecMethodEncodeChanged(v ResultRSRPItemValueCodec, a0 ResultRSRPItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPValueCodecFieldCapture(v *ResultRSRPValueCodec) *func(ResultRSRP, q5.DecodeState) (ResultRSRP, q5.Snapshot) {
	return &v.capture
}
func BridgeResultRSRPValueCodecFieldCompare(v *ResultRSRPValueCodec) *func(ResultRSRP, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRPValueCodecFieldContext(v *ResultRSRPValueCodec) *q9.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPValueCodecFieldDecode(v *ResultRSRPValueCodec) *func([]byte, q5.DecodeState) (ResultRSRP, error) {
	return &v.decode
}
func BridgeResultRSRPValueCodecFieldEncode(v *ResultRSRPValueCodec) *func(ResultRSRP, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRPValueCodecFieldPath(v *ResultRSRPValueCodec) *q5.Path { return &v.path }
func BridgeResultRSRPValueCodecMethodEncodeBudget(v ResultRSRPValueCodec, a0 ResultRSRP, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRPValueCodecMethodEncodeChanged(v ResultRSRPValueCodec, a0 ResultRSRP, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
