// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s12 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s12

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(v *s10.OTDOAInformationFailureIEContainer, s *aper.SemanticCapture) {
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
func BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(v *s10.OTDOAInformationFailureIEContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIESingleContainer(v *s07.OTDOAInformationTypeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIESingleContainer(v *s07.OTDOAInformationTypeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgePrivateMessageIEsValueCaptureLPPaPrivateIEContainer(v *s08.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticCapture) {
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
func BridgePrivateMessageIEsValueCompareLPPaPrivateIEContainer(v *s08.PrivateMessageIEsValuePrivateIEContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.ResultGERANItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.ResultGERANItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.ResultRSRPItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.ResultRSRPItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}

// OTDOAInformationFailureValueCodec is the concrete ValueCodec[OTDOAInformationFailure].
type OTDOAInformationFailureValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOAInformationFailure, aper.DecodeState,

	) (OTDOAInformationFailure, aper.Snapshot,

	)
	compare func(OTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOAInformationFailure,

		error)
	encode func(OTDOAInformationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationFailureValueCodec) New(value OTDOAInformationFailure,

) (OTDOAInformationFailureAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationFailureAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationFailureValueCodec) EncodeAPER(value OTDOAInformationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c OTDOAInformationFailureValueCodec) encodeBudget(value OTDOAInformationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationFailureValueCodec) encodeChanged(value OTDOAInformationFailure,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PrivateMessageValueCodec is the concrete ValueCodec[PrivateMessage].
type PrivateMessageValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PrivateMessage, aper.DecodeState,

	) (PrivateMessage, aper.Snapshot,

	)
	compare func(PrivateMessage, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PrivateMessage,

		error)
	encode func(PrivateMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PrivateMessageValueCodec) New(value PrivateMessage,

) (PrivateMessageAPERValue, error) {
	if c.encode == nil {
		return PrivateMessageAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PrivateMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PrivateMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PrivateMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PrivateMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PrivateMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PrivateMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PrivateMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PrivateMessageValueCodec) EncodeAPER(value PrivateMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c PrivateMessageValueCodec) encodeBudget(value PrivateMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PrivateMessageValueCodec) encodeChanged(value PrivateMessage,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultGERANValueCodec is the concrete ValueCodec[ResultGERAN].
type ResultGERANValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultGERAN, aper.DecodeState,

	) (ResultGERAN, aper.Snapshot,

	)
	compare func(ResultGERAN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultGERAN,

		error)
	encode func(ResultGERAN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultGERANValueCodec) New(value ResultGERAN,

) (ResultGERANAPERValue, error) {
	if c.encode == nil {
		return ResultGERANAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultGERANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultGERANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultGERANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultGERANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultGERANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultGERANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultGERANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultGERANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultGERANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultGERANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultGERANValueCodec) EncodeAPER(value ResultGERANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ResultGERANValueCodec) encodeBudget(value ResultGERAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultGERANValueCodec) encodeChanged(value ResultGERAN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultGERANItemValueCodec is the concrete ValueCodec[ResultGERANItem].
type ResultGERANItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultGERANItem, aper.DecodeState,

	) (ResultGERANItem, aper.Snapshot,

	)
	compare func(ResultGERANItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultGERANItem,

		error)
	encode func(ResultGERANItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultGERANItemValueCodec) New(value ResultGERANItem,

) (ResultGERANItemAPERValue, error) {
	if c.encode == nil {
		return ResultGERANItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultGERANItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultGERANItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultGERANItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultGERANItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultGERANItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultGERANItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultGERANItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultGERANItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultGERANItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultGERANItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultGERANItemValueCodec) EncodeAPER(value ResultGERANItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ResultGERANItemValueCodec) encodeBudget(value ResultGERANItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultGERANItemValueCodec) encodeChanged(value ResultGERANItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultRSRPValueCodec is the concrete ValueCodec[ResultRSRP].
type ResultRSRPValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultRSRP, aper.DecodeState,

	) (ResultRSRP, aper.Snapshot,

	)
	compare func(ResultRSRP, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultRSRP,

		error)
	encode func(ResultRSRP,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultRSRPValueCodec) New(value ResultRSRP,

) (ResultRSRPAPERValue, error) {
	if c.encode == nil {
		return ResultRSRPAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultRSRPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultRSRPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultRSRPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultRSRPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultRSRPValueCodec) EncodeAPER(value ResultRSRPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ResultRSRPValueCodec) encodeBudget(value ResultRSRP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRPValueCodec) encodeChanged(value ResultRSRP,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultRSRPItemValueCodec is the concrete ValueCodec[ResultRSRPItem].
type ResultRSRPItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultRSRPItem, aper.DecodeState,

	) (ResultRSRPItem, aper.Snapshot,

	)
	compare func(ResultRSRPItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultRSRPItem,

		error)
	encode func(ResultRSRPItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultRSRPItemValueCodec) New(value ResultRSRPItem,

) (ResultRSRPItemAPERValue, error) {
	if c.encode == nil {
		return ResultRSRPItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultRSRPItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRPItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultRSRPItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultRSRPItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultRSRPItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRPItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultRSRPItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRPItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRPItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultRSRPItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultRSRPItemValueCodec) EncodeAPER(value ResultRSRPItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ResultRSRPItemValueCodec) encodeBudget(value ResultRSRPItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRPItemValueCodec) encodeChanged(value ResultRSRPItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(fields s10.OTDOAInformationFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s10.BridgeOTDOAInformationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s10.BridgeOTDOAInformationFailureIEValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields s04.OTDOACellsExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.OTDOACellsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.OTDOACellsExtIEsIEContainer, len(fields))
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
func BridgeOTDOAInformationTypeIEValueValidateLPPaIEContainer(fields s07.OTDOAInformationTypeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s07.BridgeOTDOAInformationTypeIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeOTDOAInformationTypeIEValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaExtensionContainer(fields s04.OTDOAInformationTypeItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.OTDOAInformationTypeItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.OTDOAInformationTypeItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaExtensionContainer(fields s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.PRSFrequencyHoppingConfigurationItemIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.PRSFrequencyHoppingConfigurationItemIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePosSIBSegmentsExtIEsValueValidateLPPaExtensionContainer(fields s04.PosSIBSegmentsExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.PosSIBSegmentsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.PosSIBSegmentsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePosSIBSegmentsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgePosSIBsExtIEsValueValidateLPPaExtensionContainer(fields s04.PosSIBsExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.PosSIBsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.PosSIBsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgePosSIBsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeResultGERANItemExtIEsValueValidateLPPaExtensionContainer(fields s04.ResultGERANItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.ResultGERANItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.ResultGERANItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultGERANItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// oTDOAInformationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationFailureIEValue].
type OTDOAInformationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.OTDOAInformationFailureIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.OTDOAInformationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(v *s10.OTDOAInformationFailureIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s10.BridgeOTDOAInformationFailureIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s10.BridgeOTDOAInformationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = s10.BridgeOTDOAInformationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s10.BridgeOTDOAInformationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s10.BridgeOTDOAInformationFailureIEFieldFieldReplay(v), *s10.BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEField(v *s10.OTDOAInformationFailureIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s10.BridgeOTDOAInformationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeOTDOAInformationFailureIEFieldFieldReplay(v), *s10.BridgeOTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}

// oTDOAInformationTypeIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.OTDOAInformationTypeIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.OTDOAInformationTypeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOAInformationTypeIEValueCaptureLPPaProtocolIEField(v *s07.OTDOAInformationTypeIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s07.BridgeOTDOAInformationTypeIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s07.BridgeOTDOAInformationTypeIEValueMethodCaptureFraming(v.Value))
	v.Value = s07.BridgeOTDOAInformationTypeIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s07.BridgeOTDOAInformationTypeIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s07.BridgeOTDOAInformationTypeIEFieldFieldReplay(v), *s07.BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationTypeIEValueCompareLPPaProtocolIEField(v *s07.OTDOAInformationTypeIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s07.BridgeOTDOAInformationTypeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s07.BridgeOTDOAInformationTypeIEFieldFieldReplay(v), *s07.BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v))
}

// privateMessageIEsValueProtocolPrivateValue is the concrete protocolPrivateValue[PrivateMessageIEsValue].
type PrivateMessageIEsValueProtocolPrivateValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.PrivateMessageIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s08.PrivateIEID, *aper.DecodeBudget) bool
	decode(s08.PrivateIEID, aper.OpaqueOpenType) (s08.PrivateMessageIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}

func BridgePrivateMessageIEsValueCaptureLPPaPrivateIEField(v *s08.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s08.BridgePrivateMessageIEsValuePrivateIEFieldFieldStream(v))
	s08.BridgeCaptureLPPaPrivateIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s08.BridgePrivateMessageIEsValueMethodCaptureFraming(v.Value))
	v.Value = s08.BridgePrivateMessageIEsValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s08.BridgePrivateMessageIEsValueMethodCaptureSnapshot(v.Value))
	s.End(f, s08.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s08.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}
func BridgePrivateMessageIEsValueCompareLPPaPrivateIEField(v *s08.PrivateMessageIEsValuePrivateIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s08.BridgeCompareLPPaPrivateIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s08.BridgePrivateMessageIEsValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s08.BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v), *s08.BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v))
}

// resultGERANItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultGERANItemExtIEsValue].
type ResultGERANItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ResultGERANItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ResultGERANItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.ResultGERANItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeResultGERANItemExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeResultGERANItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeResultGERANItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeResultGERANItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeResultGERANItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionField(v *s04.ResultGERANItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeResultGERANItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeResultGERANItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultGERANItemExtIEsExtFieldFieldWithoutReplay(v))
}

// resultRSRPItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultRSRPItemExtIEsValue].
type ResultRSRPItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ResultRSRPItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ResultRSRPItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.ResultRSRPItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeResultRSRPItemExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeResultRSRPItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeResultRSRPItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeResultRSRPItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionField(v *s04.ResultRSRPItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeResultRSRPItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeResultRSRPItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultRSRPItemExtIEsExtFieldFieldWithoutReplay(v))
}

// OTDOAInformationFailureAPERValue is the concrete APERValue[OTDOAInformationFailure].
type OTDOAInformationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOAInformationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationFailureAPERValue) WithoutReplay() OTDOAInformationFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateMessageAPERValue is the concrete APERValue[PrivateMessage].
type PrivateMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   PrivateMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PrivateMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PrivateMessageAPERValue) WithoutReplay() PrivateMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultGERANAPERValue is the concrete APERValue[ResultGERAN].
type ResultGERANAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultGERAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultGERANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultGERANAPERValue) WithoutReplay() ResultGERANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultGERANItemAPERValue is the concrete APERValue[ResultGERANItem].
type ResultGERANItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultGERANItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultGERANItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultGERANItemAPERValue) WithoutReplay() ResultGERANItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRPAPERValue is the concrete APERValue[ResultRSRP].
type ResultRSRPAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultRSRP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultRSRPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRPAPERValue) WithoutReplay() ResultRSRPAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRPItemAPERValue is the concrete APERValue[ResultRSRPItem].
type ResultRSRPItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultRSRPItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultRSRPItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRPItemAPERValue) WithoutReplay() ResultRSRPItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOACellsExtIEsValueValidateLPPaIEContainer(fields s04.OTDOACellsExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeOTDOACellsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeOTDOACellsExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaIEContainer(fields s04.OTDOAInformationTypeItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaIEContainer(fields s04.PRSFrequencyHoppingConfigurationItemIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgePosSIBSegmentsExtIEsValueValidateLPPaIEContainer(fields s04.PosSIBSegmentsExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgePosSIBSegmentsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgePosSIBSegmentsExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgePosSIBsExtIEsValueValidateLPPaIEContainer(fields s04.PosSIBsExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s03.BridgePosSIBsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgePosSIBsExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeResultGERANItemExtIEsValueValidateLPPaIEContainer(fields s04.ResultGERANItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s03.BridgeResultGERANItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeResultGERANItemExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// NewPrivateIEIDLocal creates a PrivateIEID with the local alternative.
func BridgeNewPrivateIEIDLocalLegacy(v int64) s08.PrivateIEID {
	return s08.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceLocal,
		Local:  &v,
	}
}

// NewPrivateIEIDGlobal creates a PrivateIEID with the global alternative.
func BridgeNewPrivateIEIDGlobalLegacy(v runtime.ObjectIdentifier) s08.PrivateIEID {
	return s08.PrivateIEID{
		Choice: s00.PrivateIEIDChoiceGlobal,
		Global: &v,
	}
}

// NewPrivateIEIDLocal constructs a checked complete value.
func NewPrivateIEIDLocal(v int64, options ...aper.BuildOption) (s08.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	value := BridgeNewPrivateIEIDLocalLegacy(v)
	if _, err := s08.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDLocal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDLocal")
}

// NewPrivateIEIDGlobal constructs a checked complete value.
func NewPrivateIEIDGlobal(v runtime.ObjectIdentifier, options ...aper.BuildOption) (s08.PrivateIEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	value := BridgeNewPrivateIEIDGlobalLegacy(v)
	if _, err := s08.BridgePrivateIEIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PrivateIEID{}, aper.OperationError(err, "PrivateIEIDGlobal")
	}
	return value, aper.OperationError(nil, "PrivateIEIDGlobal")
}

// NewPRSMutingConfigurationTwo creates a PRSMutingConfiguration with the two alternative.
func BridgeNewPRSMutingConfigurationTwoLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice: s00.PRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewPRSMutingConfigurationFour creates a PRSMutingConfiguration with the four alternative.
func BridgeNewPRSMutingConfigurationFourLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice: s00.PRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewPRSMutingConfigurationSixteen creates a PRSMutingConfiguration with the sixteen alternative.
func BridgeNewPRSMutingConfigurationSixteenLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:  s00.PRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NewPRSMutingConfigurationThirtyTwo creates a PRSMutingConfiguration with the thirty-two alternative.
func BridgeNewPRSMutingConfigurationThirtyTwoLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:    s00.PRSMutingConfigurationChoiceThirtyTwo,
		ThirtyTwo: &v,
	}
}

// NewPRSMutingConfigurationSixtyFour creates a PRSMutingConfiguration with the sixty-four alternative.
func BridgeNewPRSMutingConfigurationSixtyFourLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:    s00.PRSMutingConfigurationChoiceSixtyFour,
		SixtyFour: &v,
	}
}

// NewPRSMutingConfigurationOneHundredAndTwentyEight creates a PRSMutingConfiguration with the one-hundred-and-twenty-eight alternative.
func BridgeNewPRSMutingConfigurationOneHundredAndTwentyEightLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:                   s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight,
		OneHundredAndTwentyEight: &v,
	}
}

// NewPRSMutingConfigurationTwoHundredAndFiftySix creates a PRSMutingConfiguration with the two-hundred-and-fifty-six alternative.
func BridgeNewPRSMutingConfigurationTwoHundredAndFiftySixLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:                s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix,
		TwoHundredAndFiftySix: &v,
	}
}

// NewPRSMutingConfigurationFiveHundredAndTwelve creates a PRSMutingConfiguration with the five-hundred-and-twelve alternative.
func BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:               s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve,
		FiveHundredAndTwelve: &v,
	}
}

// NewPRSMutingConfigurationOneThousandAndTwentyFour creates a PRSMutingConfiguration with the one-thousand-and-twenty-four alternative.
func BridgeNewPRSMutingConfigurationOneThousandAndTwentyFourLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:                   s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour,
		OneThousandAndTwentyFour: &v,
	}
}

type ResultRSRP = []ResultRSRPItem

// ResultRSRPItem represents the ASN.1 type ResultRSRP-Item (SEQUENCE).
type ResultRSRPItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	PCI               s00.PCI                              `asn1:"tag:0,context,implicit"`
	EARFCN            s00.EARFCN                           `asn1:"tag:1,context,implicit"`
	ECGI              *s05.ECGI                            `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRP         s00.ValueRSRP                        `asn1:"tag:3,context,implicit"`
	IEExtensions      s04.ResultRSRPItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ResultGERAN = []ResultGERANItem

// ResultGERANItem represents the ASN.1 type ResultGERAN-Item (SEQUENCE).
type ResultGERANItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	BCCH              s00.BCCH                              `asn1:"tag:0,context,implicit"`
	PhysCellIDGERAN   s00.PhysCellIDGERAN                   `asn1:"tag:1,context,implicit"`
	RSSI              s00.RSSI                              `asn1:"tag:2,context,implicit"`
	IEExtensions      s04.ResultGERANItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NewSubframeallocationOneFrame creates a Subframeallocation with the oneFrame alternative.
func BridgeNewSubframeallocationOneFrameLegacy(v runtime.BitString) s09.Subframeallocation {
	return s09.Subframeallocation{
		Choice:   s00.SubframeallocationChoiceOneFrame,
		OneFrame: &v,
	}
}

// NewSubframeallocationFourFrames creates a Subframeallocation with the fourFrames alternative.
func BridgeNewSubframeallocationFourFramesLegacy(v runtime.BitString) s09.Subframeallocation {
	return s09.Subframeallocation{
		Choice:     s00.SubframeallocationChoiceFourFrames,
		FourFrames: &v,
	}
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-FDD alternative.
func BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDDLegacy(v s00.PhysCellIDUTRAFDD) s08.ResultUTRANItemPhysCellIDUTRAN {
	return s08.ResultUTRANItemPhysCellIDUTRAN{
		Choice:            s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD,
		PhysCellIDUTRAFDD: v,
	}
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD creates a ResultUTRANItemPhysCellIDUTRAN with the physCellIDUTRA-TDD alternative.
func BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDDLegacy(v s00.PhysCellIDUTRATDD) s08.ResultUTRANItemPhysCellIDUTRAN {
	return s08.ResultUTRANItemPhysCellIDUTRAN{
		Choice:            s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD,
		PhysCellIDUTRATDD: v,
	}
}

type BridgeAsn1cAPERResultRSRPListValue struct{ Value ResultRSRP }

// MarshalAPERResultRSRPTo appends a ResultRSRP list to bb.
func BridgeMarshalAPERResultRSRPTo(list ResultRSRP, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultRSRPListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ResultRSRPItem to APER format.
func (v *ResultRSRPItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultRSRPItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PCI, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := s05.BridgeECGIMethodMarshalAPERTo(v.ECGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRP, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound22, true); err != nil {
		return fmt.Errorf("encoding valueRSRP: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeResultRSRPItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ResultRSRPItem from APER format.
func (v *ResultRSRPItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultRSRPItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultRSRPItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRPItem")
	}
	bb.EnterComponent("ResultRSRPItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRPItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultRSRPItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRPItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultRSRPItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRPItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		toleranceMark_ecgi := bb.EnterComponent("ECGI")
		var dec_ecgi s05.ECGI
		if err := s05.BridgeECGIMethodUnmarshalAPERFrom(&dec_ecgi, bb); err != nil {
			return runtime.WrapDecodePath(err, "ECGI")
		}
		if err := aper.ChargeValue(bb, dec_ecgi); err != nil {
			return err
		}
		v.ECGI = &dec_ecgi
		bb.LeaveComponent(toleranceMark_ecgi)
	}
	val_valuersrp, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound22, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ValueRSRP")
	}
	v.ValueRSRP = val_valuersrp
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.ResultRSRPItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.ResultRSRPItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeResultRSRPItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
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
func BridgeMarshalAPERResultGERANTo(list ResultGERAN, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultGERANListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ResultGERANItem to APER format.
func (v *ResultGERANItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultGERANItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.BCCH, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound4, true); err != nil {
		return fmt.Errorf("encoding bCCH: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDGERAN, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true); err != nil {
		return fmt.Errorf("encoding physCellIDGERAN: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.RSSI, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true); err != nil {
		return fmt.Errorf("encoding rSSI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeResultGERANItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ResultGERANItem from APER format.
func (v *ResultGERANItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultGERANItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultGERANItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultGERANItem")
	}
	bb.EnterComponent("ResultGERANItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultGERANItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultGERANItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERANItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultGERANItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultGERANItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_bcch, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "BCCH")
	}
	v.BCCH = val_bcch
	val_physcellidgeran, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIDGERAN")
	}
	v.PhysCellIDGERAN = val_physcellidgeran
	val_rssi, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "RSSI")
	}
	v.RSSI = val_rssi
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.ResultGERANItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.ResultGERANItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeResultGERANItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
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
func (v *ResultGERANItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultGERANItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultGERANItem) WithoutReplay() ResultGERANItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultGERANItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRPItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRPItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRPItem) WithoutReplay() ResultRSRPItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultRSRPItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ResultGERANItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultGERANItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultGERANItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultGERANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultRSRPItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultRSRPItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultRSRPItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRPItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ResultGERANItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultGERANItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultGERANItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultGERANItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultGERANItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultGERANItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultGERANItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultGERANItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultGERANItem")
}
func (v *ResultGERANItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultGERANItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultGERANItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ResultGERANItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultGERANItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
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

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ResultRSRPItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultRSRPItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultRSRPItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRPItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultRSRPItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultRSRPItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultRSRPItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultRSRPItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultRSRPItem")
}
func (v *ResultRSRPItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRPItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRPItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ResultRSRPItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRPItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
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
func (v *ResultGERANItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultGERANItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultGERANItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultGERANItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultGERANItem{}
		return report, aper.OperationError(err, "ResultGERANItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultGERANItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRPItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultRSRPItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRPItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRPItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRPItem{}
		return report, aper.OperationError(err, "ResultRSRPItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultRSRPItem")
}

// NewPRSMutingConfigurationTwo constructs a checked complete value.
func NewPRSMutingConfigurationTwo(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationTwo")
	}
	value := BridgeNewPRSMutingConfigurationTwoLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationTwo")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationTwo")
}

// NewPRSMutingConfigurationFour constructs a checked complete value.
func NewPRSMutingConfigurationFour(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFour")
	}
	value := BridgeNewPRSMutingConfigurationFourLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFour")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationFour")
}

// NewPRSMutingConfigurationSixteen constructs a checked complete value.
func NewPRSMutingConfigurationSixteen(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationSixteen")
	}
	value := BridgeNewPRSMutingConfigurationSixteenLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationSixteen")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationSixteen")
}

// NewPRSMutingConfigurationThirtyTwo constructs a checked complete value.
func NewPRSMutingConfigurationThirtyTwo(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationThirtyTwo")
	}
	value := BridgeNewPRSMutingConfigurationThirtyTwoLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationThirtyTwo")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationThirtyTwo")
}

// NewPRSMutingConfigurationSixtyFour constructs a checked complete value.
func NewPRSMutingConfigurationSixtyFour(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationSixtyFour")
	}
	value := BridgeNewPRSMutingConfigurationSixtyFourLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationSixtyFour")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationSixtyFour")
}

// NewPRSMutingConfigurationOneHundredAndTwentyEight constructs a checked complete value.
func NewPRSMutingConfigurationOneHundredAndTwentyEight(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationOneHundredAndTwentyEight")
	}
	value := BridgeNewPRSMutingConfigurationOneHundredAndTwentyEightLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationOneHundredAndTwentyEight")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationOneHundredAndTwentyEight")
}

// NewPRSMutingConfigurationTwoHundredAndFiftySix constructs a checked complete value.
func NewPRSMutingConfigurationTwoHundredAndFiftySix(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationTwoHundredAndFiftySix")
	}
	value := BridgeNewPRSMutingConfigurationTwoHundredAndFiftySixLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationTwoHundredAndFiftySix")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationTwoHundredAndFiftySix")
}

// NewPRSMutingConfigurationFiveHundredAndTwelve constructs a checked complete value.
func NewPRSMutingConfigurationFiveHundredAndTwelve(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	value := BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationFiveHundredAndTwelve")
}

// NewPRSMutingConfigurationOneThousandAndTwentyFour constructs a checked complete value.
func NewPRSMutingConfigurationOneThousandAndTwentyFour(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationOneThousandAndTwentyFour")
	}
	value := BridgeNewPRSMutingConfigurationOneThousandAndTwentyFourLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationOneThousandAndTwentyFour")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationOneThousandAndTwentyFour")
}

// NewSubframeallocationOneFrame constructs a checked complete value.
func NewSubframeallocationOneFrame(v runtime.BitString, options ...aper.BuildOption) (s09.Subframeallocation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s09.Subframeallocation{}, aper.OperationError(err, "SubframeallocationOneFrame")
	}
	value := BridgeNewSubframeallocationOneFrameLegacy(v)
	if _, err := s09.BridgeSubframeallocationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s09.Subframeallocation{}, aper.OperationError(err, "SubframeallocationOneFrame")
	}
	return value, aper.OperationError(nil, "SubframeallocationOneFrame")
}

// NewSubframeallocationFourFrames constructs a checked complete value.
func NewSubframeallocationFourFrames(v runtime.BitString, options ...aper.BuildOption) (s09.Subframeallocation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s09.Subframeallocation{}, aper.OperationError(err, "SubframeallocationFourFrames")
	}
	value := BridgeNewSubframeallocationFourFramesLegacy(v)
	if _, err := s09.BridgeSubframeallocationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s09.Subframeallocation{}, aper.OperationError(err, "SubframeallocationFourFrames")
	}
	return value, aper.OperationError(nil, "SubframeallocationFourFrames")
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD constructs a checked complete value.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD(v s00.PhysCellIDUTRAFDD, options ...aper.BuildOption) (s08.ResultUTRANItemPhysCellIDUTRAN, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.ResultUTRANItemPhysCellIDUTRAN{}, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
	}
	value := BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDDLegacy(v)
	if _, err := s08.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.ResultUTRANItemPhysCellIDUTRAN{}, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
	}
	return value, aper.OperationError(nil, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRAFDD")
}

// NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD constructs a checked complete value.
func NewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD(v s00.PhysCellIDUTRATDD, options ...aper.BuildOption) (s08.ResultUTRANItemPhysCellIDUTRAN, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.ResultUTRANItemPhysCellIDUTRAN{}, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
	}
	value := BridgeNewResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDDLegacy(v)
	if _, err := s08.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.ResultUTRANItemPhysCellIDUTRAN{}, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
	}
	return value, aper.OperationError(nil, "ResultUTRANItemPhysCellIDUTRANPhysCellIDUTRATDD")
}

// OTDOAInformationFailure represents the ASN.1 type OTDOAInformationFailure (SEQUENCE).
type OTDOAInformationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s10.OTDOAInformationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// PrivateMessage represents the ASN.1 type PrivateMessage (SEQUENCE).
type PrivateMessage struct {
	replay          aper.Snapshot
	stream          aper.WireSpan
	withoutReplay   bool
	received        bool
	receivedBytes   aper.WireSpan
	PrivateIEs      s08.PrivateMessageIEsValuePrivateIEContainer `asn1:"tag:0,context,implicit"`
	privateIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount        int64                                        `asn1:"-" json:"-"`
	extPresent      []bool                                       `asn1:"-" json:"-"`
	extData         [][]byte                                     `asn1:"-" json:"-"`
	perPadding      aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding   []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin       []aper.OpaqueOrigin
	extWire         []aper.WireSpan
}

// MarshalAPER encodes OTDOAInformationFailure to APER format.
func (v *OTDOAInformationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s10.BridgeOTDOAInformationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes OTDOAInformationFailure from APER format.
func (v *OTDOAInformationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	bb.EnterComponent("OTDOAInformationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOAInformationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s10.OTDOAInformationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.OTDOAInformationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s10.BridgeOTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
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
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PrivateMessage) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.PrivateIEs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_privateies < 0 || fragmentOffset_privateies > int64(len(v.PrivateIEs)) || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(len(v.PrivateIEs[fragmentOffset_privateies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PrivateIEs[fragmentOffset_privateies : fragmentOffset_privateies+fragmentLength_privateies] {
			if err := s08.BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding privateIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding privateIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes PrivateMessage from APER format.
func (v *PrivateMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateMessage) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	bb.EnterComponent("PrivateMessage")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	padding, err := aper.CaptureFinalBits(bb, "PrivateMessage")
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateMessage")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PrivateMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessage{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_privateies := bb.EnterComponent("PrivateIEs")
	v.PrivateIEs = make(s08.PrivateMessageIEsValuePrivateIEContainer, 0)
	_, errCollection_privateies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_privateies, fragmentLength_privateies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_privateies < 0 || fragmentLength_privateies < 0 || fragmentLength_privateies > int64(^uint(0)>>1) || fragmentOffset_privateies > int64(^uint(0)>>1)-fragmentLength_privateies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_privateies; i++ {
			var elem s08.PrivateMessageIEsValuePrivateIEField
			elementMark := bb.EnterIndex(fragmentOffset_privateies + i)
			if err := s08.BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateIEs[%d]", fragmentOffset_privateies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.PrivateIEs, elem); err != nil {
				return err
			} else {
				v.PrivateIEs = next
			}
		}
		return nil
	})
	if errCollection_privateies != nil {
		return runtime.WrapDecodePath(errCollection_privateies, "PrivateIEs")
	}
	bb.LeaveComponent(toleranceMark_privateies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
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
func (v *OTDOAInformationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationFailure) WithoutReplay() OTDOAInformationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOAInformationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PrivateMessage) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateMessage", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateMessage) WithoutReplay() PrivateMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PrivateMessage
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PrivateMessage) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PrivateMessage) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PrivateMessage) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PrivateMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOAInformationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationFailure")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOAInformationFailure")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOAInformationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOAInformationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOAInformationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOAInformationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOAInformationFailure")
}
func (v *OTDOAInformationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationFailure) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *OTDOAInformationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
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

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *PrivateMessage) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PrivateMessage")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PrivateMessage")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPrivateMessage(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PrivateMessage")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PrivateMessage")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PrivateMessage")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PrivateMessage")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PrivateMessage")
}
func (v *PrivateMessage) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PrivateMessage) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PrivateMessage) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *PrivateMessage) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PrivateMessage) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
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
func (v *OTDOAInformationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationFailure")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationFailure{}
		return report, aper.OperationError(err, "OTDOAInformationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOAInformationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PrivateMessage) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PrivateMessage")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PrivateMessage
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPrivateMessage(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PrivateMessage{}
		return report, aper.OperationError(err, "PrivateMessage")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PrivateMessage")
}
func BridgeCaptureLPPaOTDOAInformationFailure(v *OTDOAInformationFailure, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaOTDOAInformationFailure(v *OTDOAInformationFailure, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationType(v *s07.OTDOAInformationType, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaOTDOAInformationType(v *s07.OTDOAInformationType, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaPrivateMessage(v *PrivateMessage, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaPrivateMessage(v *PrivateMessage, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgePrivateMessageIEsValueCompareLPPaPrivateIEContainer(&v.PrivateIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultGERAN(v *ResultGERAN, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaResultGERAN(v *ResultGERAN, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaResultGERANItem(v *ResultGERANItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaBCCH(&v.BCCH, s)
	s00.BridgeCaptureLPPaPhysCellIDGERAN(&v.PhysCellIDGERAN, s)
	s00.BridgeCaptureLPPaRSSI(&v.RSSI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultGERANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultGERANItem(v *ResultGERANItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaBCCH(&v.BCCH, s)
	s02.BridgeCompareLPPaPhysCellIDGERAN(&v.PhysCellIDGERAN, s)
	s03.BridgeCompareLPPaRSSI(&v.RSSI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultGERANItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRP(v *ResultRSRP, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaResultRSRP(v *ResultRSRP, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaResultRSRPItem(v *ResultRSRPItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPCI(&v.PCI, s)
	s00.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			s05.BridgeCaptureLPPaECGI(v.ECGI, s)
		}
		s.End(f, nil, false)
	}
	s00.BridgeCaptureLPPaValueRSRP(&v.ValueRSRP, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRPItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRPItem(v *ResultRSRPItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPCI(&v.PCI, s)
	s02.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			s05.BridgeCompareLPPaECGI(v.ECGI, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s03.BridgeCompareLPPaValueRSRP(&v.ValueRSRP, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRPItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

// ResultGERANItemCodec binds the complete source value type.
func ResultGERANItemCodec() ResultGERANItemValueCodec {
	return ResultGERANItemValueCodec{path: "ResultGERANItem", decode: func(data []byte, options aper.DecodeState) (ResultGERANItem, error) {
		var value ResultGERANItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultGERANItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultGERANItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultGERANItem, options aper.DecodeState) (ResultGERANItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultGERANItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultGERANItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultGERANItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultGERANItem"
		return sealed
	}(),
	}
}

// ResultRSRPItemCodec binds the complete source value type.
func ResultRSRPItemCodec() ResultRSRPItemValueCodec {
	return ResultRSRPItemValueCodec{path: "ResultRSRPItem", decode: func(data []byte, options aper.DecodeState) (ResultRSRPItem, error) {
		var value ResultRSRPItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultRSRPItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultRSRPItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultRSRPItem, options aper.DecodeState) (ResultRSRPItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultRSRPItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultRSRPItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultRSRPItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRPItem"
		return sealed
	}(),
	}
}
func BridgeOTDOAInformationFailureAPERValueFieldContext(v *OTDOAInformationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureAPERValueFieldReceived(v *OTDOAInformationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationFailureAPERValueFieldReplay(v *OTDOAInformationFailureAPERValue) *aper.Snapshot {
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
func BridgeOTDOAInformationFailureFieldExtOrigin(v *OTDOAInformationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationFailureFieldExtPresent(v *OTDOAInformationFailure) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationFailureFieldExtWire(v *OTDOAInformationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationFailureFieldPerExtPadding(v *OTDOAInformationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationFailureFieldPerPadding(v *OTDOAInformationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationFailureFieldProtocolIEsIndef(v *OTDOAInformationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationFailureFieldReceived(v *OTDOAInformationFailure) *bool { return &v.received }
func BridgeOTDOAInformationFailureFieldReceivedBytes(v *OTDOAInformationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationFailureFieldReplay(v *OTDOAInformationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationFailureFieldStream(v *OTDOAInformationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationFailureFieldWithoutReplay(v *OTDOAInformationFailure) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v *OTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERChanged(v *OTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERChangedValue(v *OTDOAInformationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERFreshValue(v *OTDOAInformationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERLegacy(v *OTDOAInformationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationFailureMethodMarshalAPERPlanned(v *OTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationFailureMethodMarshalAPERTo(v *OTDOAInformationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERFrom(v *OTDOAInformationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERLegacy(v *OTDOAInformationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationFailureMethodUnmarshalAPERWithOptions(v *OTDOAInformationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationFailureValueCodecFieldCapture(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, aper.DecodeState) (OTDOAInformationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationFailureValueCodecFieldCompare(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationFailureValueCodecFieldContext(v *OTDOAInformationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureValueCodecFieldDecode(v *OTDOAInformationFailureValueCodec) *func([]byte, aper.DecodeState) (OTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeOTDOAInformationFailureValueCodecFieldEncode(v *OTDOAInformationFailureValueCodec) *func(OTDOAInformationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationFailureValueCodecFieldPath(v *OTDOAInformationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationFailureValueCodecMethodEncodeBudget(v OTDOAInformationFailureValueCodec, a0 OTDOAInformationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationFailureValueCodecMethodEncodeChanged(v OTDOAInformationFailureValueCodec, a0 OTDOAInformationFailure, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageAPERValueFieldContext(v *PrivateMessageAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageAPERValueFieldReceived(v *PrivateMessageAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateMessageAPERValueFieldReplay(v *PrivateMessageAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageAPERValueFieldWithoutReplay(v *PrivateMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageFieldExtCount(v *PrivateMessage) *int64                { return &v.extCount }
func BridgePrivateMessageFieldExtData(v *PrivateMessage) *[][]byte              { return &v.extData }
func BridgePrivateMessageFieldExtOrigin(v *PrivateMessage) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgePrivateMessageFieldExtPresent(v *PrivateMessage) *[]bool             { return &v.extPresent }
func BridgePrivateMessageFieldExtWire(v *PrivateMessage) *[]aper.WireSpan       { return &v.extWire }
func BridgePrivateMessageFieldPerExtPadding(v *PrivateMessage) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePrivateMessageFieldPerPadding(v *PrivateMessage) *aper.FinalPadding { return &v.perPadding }
func BridgePrivateMessageFieldPrivateIEsIndef(v *PrivateMessage) *bool         { return &v.privateIEsIndef }
func BridgePrivateMessageFieldReceived(v *PrivateMessage) *bool                { return &v.received }
func BridgePrivateMessageFieldReceivedBytes(v *PrivateMessage) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePrivateMessageFieldReplay(v *PrivateMessage) *aper.Snapshot { return &v.replay }
func BridgePrivateMessageFieldStream(v *PrivateMessage) *aper.WireSpan { return &v.stream }
func BridgePrivateMessageFieldWithoutReplay(v *PrivateMessage) *bool   { return &v.withoutReplay }
func BridgePrivateMessageMethodMarshalAPERBudget(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERChanged(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERChangedValue(v *PrivateMessage, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateMessageMethodMarshalAPERFreshValue(v *PrivateMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERLegacy(v *PrivateMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateMessageMethodMarshalAPERPlanned(v *PrivateMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePrivateMessageMethodMarshalAPERTo(v *PrivateMessage, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageMethodUnmarshalAPERFrom(v *PrivateMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERLegacy(v *PrivateMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateMessageMethodUnmarshalAPERWithOptions(v *PrivateMessage, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateMessageValueCodecFieldCapture(v *PrivateMessageValueCodec) *func(PrivateMessage, aper.DecodeState) (PrivateMessage, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageValueCodecFieldCompare(v *PrivateMessageValueCodec) *func(PrivateMessage, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePrivateMessageValueCodecFieldContext(v *PrivateMessageValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageValueCodecFieldDecode(v *PrivateMessageValueCodec) *func([]byte, aper.DecodeState) (PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageValueCodecFieldEncode(v *PrivateMessageValueCodec) *func(PrivateMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageValueCodecFieldPath(v *PrivateMessageValueCodec) *aper.Path { return &v.path }
func BridgePrivateMessageValueCodecMethodEncodeBudget(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePrivateMessageValueCodecMethodEncodeChanged(v PrivateMessageValueCodec, a0 PrivateMessage, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultGERANAPERValueFieldContext(v *ResultGERANAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANAPERValueFieldReceived(v *ResultGERANAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultGERANAPERValueFieldReplay(v *ResultGERANAPERValue) *aper.Snapshot { return &v.replay }
func BridgeResultGERANAPERValueFieldWithoutReplay(v *ResultGERANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemAPERValueFieldContext(v *ResultGERANItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANItemAPERValueFieldReceived(v *ResultGERANItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultGERANItemAPERValueFieldReplay(v *ResultGERANItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultGERANItemAPERValueFieldWithoutReplay(v *ResultGERANItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANItemFieldExtCount(v *ResultGERANItem) *int64   { return &v.extCount }
func BridgeResultGERANItemFieldExtData(v *ResultGERANItem) *[][]byte { return &v.extData }
func BridgeResultGERANItemFieldExtOrigin(v *ResultGERANItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeResultGERANItemFieldExtPresent(v *ResultGERANItem) *[]bool       { return &v.extPresent }
func BridgeResultGERANItemFieldExtWire(v *ResultGERANItem) *[]aper.WireSpan { return &v.extWire }
func BridgeResultGERANItemFieldIEExtensionsIndef(v *ResultGERANItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultGERANItemFieldPerExtPadding(v *ResultGERANItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultGERANItemFieldPerPadding(v *ResultGERANItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeResultGERANItemFieldReceived(v *ResultGERANItem) *bool { return &v.received }
func BridgeResultGERANItemFieldReceivedBytes(v *ResultGERANItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultGERANItemFieldReplay(v *ResultGERANItem) *aper.Snapshot { return &v.replay }
func BridgeResultGERANItemFieldStream(v *ResultGERANItem) *aper.WireSpan { return &v.stream }
func BridgeResultGERANItemFieldWithoutReplay(v *ResultGERANItem) *bool   { return &v.withoutReplay }
func BridgeResultGERANItemMethodMarshalAPERBudget(v *ResultGERANItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERChanged(v *ResultGERANItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultGERANItemMethodMarshalAPERChangedValue(v *ResultGERANItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultGERANItemMethodMarshalAPERFreshValue(v *ResultGERANItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERLegacy(v *ResultGERANItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultGERANItemMethodMarshalAPERPlanned(v *ResultGERANItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultGERANItemMethodMarshalAPERTo(v *ResultGERANItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultGERANItemMethodUnmarshalAPERFrom(v *ResultGERANItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultGERANItemMethodUnmarshalAPERLegacy(v *ResultGERANItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultGERANItemMethodUnmarshalAPERWithOptions(v *ResultGERANItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultGERANItemValueCodecFieldCapture(v *ResultGERANItemValueCodec) *func(ResultGERANItem, aper.DecodeState) (ResultGERANItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultGERANItemValueCodecFieldCompare(v *ResultGERANItemValueCodec) *func(ResultGERANItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultGERANItemValueCodecFieldContext(v *ResultGERANItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANItemValueCodecFieldDecode(v *ResultGERANItemValueCodec) *func([]byte, aper.DecodeState) (ResultGERANItem, error) {
	return &v.decode
}
func BridgeResultGERANItemValueCodecFieldEncode(v *ResultGERANItemValueCodec) *func(ResultGERANItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultGERANItemValueCodecFieldPath(v *ResultGERANItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeResultGERANItemValueCodecMethodEncodeBudget(v ResultGERANItemValueCodec, a0 ResultGERANItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultGERANItemValueCodecMethodEncodeChanged(v ResultGERANItemValueCodec, a0 ResultGERANItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultGERANValueCodecFieldCapture(v *ResultGERANValueCodec) *func(ResultGERAN, aper.DecodeState) (ResultGERAN, aper.Snapshot) {
	return &v.capture
}
func BridgeResultGERANValueCodecFieldCompare(v *ResultGERANValueCodec) *func(ResultGERAN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultGERANValueCodecFieldContext(v *ResultGERANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultGERANValueCodecFieldDecode(v *ResultGERANValueCodec) *func([]byte, aper.DecodeState) (ResultGERAN, error) {
	return &v.decode
}
func BridgeResultGERANValueCodecFieldEncode(v *ResultGERANValueCodec) *func(ResultGERAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultGERANValueCodecFieldPath(v *ResultGERANValueCodec) *aper.Path { return &v.path }
func BridgeResultGERANValueCodecMethodEncodeBudget(v ResultGERANValueCodec, a0 ResultGERAN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultGERANValueCodecMethodEncodeChanged(v ResultGERANValueCodec, a0 ResultGERAN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPAPERValueFieldContext(v *ResultRSRPAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPAPERValueFieldReceived(v *ResultRSRPAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRPAPERValueFieldReplay(v *ResultRSRPAPERValue) *aper.Snapshot { return &v.replay }
func BridgeResultRSRPAPERValueFieldWithoutReplay(v *ResultRSRPAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemAPERValueFieldContext(v *ResultRSRPItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPItemAPERValueFieldReceived(v *ResultRSRPItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRPItemAPERValueFieldReplay(v *ResultRSRPItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRPItemAPERValueFieldWithoutReplay(v *ResultRSRPItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRPItemFieldExtCount(v *ResultRSRPItem) *int64                { return &v.extCount }
func BridgeResultRSRPItemFieldExtData(v *ResultRSRPItem) *[][]byte              { return &v.extData }
func BridgeResultRSRPItemFieldExtOrigin(v *ResultRSRPItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeResultRSRPItemFieldExtPresent(v *ResultRSRPItem) *[]bool             { return &v.extPresent }
func BridgeResultRSRPItemFieldExtWire(v *ResultRSRPItem) *[]aper.WireSpan       { return &v.extWire }
func BridgeResultRSRPItemFieldIEExtensionsIndef(v *ResultRSRPItem) *bool        { return &v.iEExtensionsIndef }
func BridgeResultRSRPItemFieldPerExtPadding(v *ResultRSRPItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultRSRPItemFieldPerPadding(v *ResultRSRPItem) *aper.FinalPadding { return &v.perPadding }
func BridgeResultRSRPItemFieldReceived(v *ResultRSRPItem) *bool                { return &v.received }
func BridgeResultRSRPItemFieldReceivedBytes(v *ResultRSRPItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRPItemFieldReplay(v *ResultRSRPItem) *aper.Snapshot { return &v.replay }
func BridgeResultRSRPItemFieldStream(v *ResultRSRPItem) *aper.WireSpan { return &v.stream }
func BridgeResultRSRPItemFieldWithoutReplay(v *ResultRSRPItem) *bool   { return &v.withoutReplay }
func BridgeResultRSRPItemMethodMarshalAPERBudget(v *ResultRSRPItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERChanged(v *ResultRSRPItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRPItemMethodMarshalAPERChangedValue(v *ResultRSRPItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRPItemMethodMarshalAPERFreshValue(v *ResultRSRPItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERLegacy(v *ResultRSRPItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRPItemMethodMarshalAPERPlanned(v *ResultRSRPItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRPItemMethodMarshalAPERTo(v *ResultRSRPItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRPItemMethodUnmarshalAPERFrom(v *ResultRSRPItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRPItemMethodUnmarshalAPERLegacy(v *ResultRSRPItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRPItemMethodUnmarshalAPERWithOptions(v *ResultRSRPItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRPItemValueCodecFieldCapture(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, aper.DecodeState) (ResultRSRPItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultRSRPItemValueCodecFieldCompare(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRPItemValueCodecFieldContext(v *ResultRSRPItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPItemValueCodecFieldDecode(v *ResultRSRPItemValueCodec) *func([]byte, aper.DecodeState) (ResultRSRPItem, error) {
	return &v.decode
}
func BridgeResultRSRPItemValueCodecFieldEncode(v *ResultRSRPItemValueCodec) *func(ResultRSRPItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRPItemValueCodecFieldPath(v *ResultRSRPItemValueCodec) *aper.Path { return &v.path }
func BridgeResultRSRPItemValueCodecMethodEncodeBudget(v ResultRSRPItemValueCodec, a0 ResultRSRPItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRPItemValueCodecMethodEncodeChanged(v ResultRSRPItemValueCodec, a0 ResultRSRPItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPValueCodecFieldCapture(v *ResultRSRPValueCodec) *func(ResultRSRP, aper.DecodeState) (ResultRSRP, aper.Snapshot) {
	return &v.capture
}
func BridgeResultRSRPValueCodecFieldCompare(v *ResultRSRPValueCodec) *func(ResultRSRP, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRPValueCodecFieldContext(v *ResultRSRPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRPValueCodecFieldDecode(v *ResultRSRPValueCodec) *func([]byte, aper.DecodeState) (ResultRSRP, error) {
	return &v.decode
}
func BridgeResultRSRPValueCodecFieldEncode(v *ResultRSRPValueCodec) *func(ResultRSRP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRPValueCodecFieldPath(v *ResultRSRPValueCodec) *aper.Path { return &v.path }
func BridgeResultRSRPValueCodecMethodEncodeBudget(v ResultRSRPValueCodec, a0 ResultRSRP, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRPValueCodecMethodEncodeChanged(v ResultRSRPValueCodec, a0 ResultRSRP, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
