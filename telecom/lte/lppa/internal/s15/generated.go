// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s15 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s15

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
)

func BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.TDDConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.TDDConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}

// AddOTDOACellsValueCodec is the concrete ValueCodec[AddOTDOACells].
type AddOTDOACellsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AddOTDOACells, aper.DecodeState,

	) (AddOTDOACells, aper.Snapshot,

	)
	compare func(AddOTDOACells, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AddOTDOACells,

		error)
	encode func(AddOTDOACells,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AddOTDOACellsValueCodec) New(value AddOTDOACells,

) (AddOTDOACellsAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AddOTDOACellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AddOTDOACellsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AddOTDOACellsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AddOTDOACellsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AddOTDOACellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AddOTDOACellsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AddOTDOACellsValueCodec) EncodeAPER(value AddOTDOACellsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AddOTDOACellsValueCodec) encodeBudget(value AddOTDOACells,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellsValueCodec) encodeChanged(value AddOTDOACells,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AddOTDOACellInformationValueCodec is the concrete ValueCodec[AddOTDOACellInformation].
type AddOTDOACellInformationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AddOTDOACellInformation, aper.DecodeState,

	) (AddOTDOACellInformation, aper.Snapshot,

	)
	compare func(AddOTDOACellInformation, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AddOTDOACellInformation,

		error)
	encode func(AddOTDOACellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AddOTDOACellInformationValueCodec) New(value AddOTDOACellInformation,

) (AddOTDOACellInformationAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellInformationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AddOTDOACellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AddOTDOACellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AddOTDOACellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AddOTDOACellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AddOTDOACellInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AddOTDOACellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AddOTDOACellInformationValueCodec) EncodeAPER(value AddOTDOACellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AddOTDOACellInformationValueCodec) encodeBudget(value AddOTDOACellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellInformationValueCodec) encodeChanged(value AddOTDOACellInformation,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AddOTDOACellsElemValueCodec is the concrete ValueCodec[AddOTDOACellsElem].
type AddOTDOACellsElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AddOTDOACellsElem, aper.DecodeState,

	) (AddOTDOACellsElem, aper.Snapshot,

	)
	compare func(AddOTDOACellsElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AddOTDOACellsElem,

		error)
	encode func(AddOTDOACellsElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AddOTDOACellsElemValueCodec) New(value AddOTDOACellsElem,

) (AddOTDOACellsElemAPERValue, error) {
	if c.encode == nil {
		return AddOTDOACellsElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AddOTDOACellsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AddOTDOACellsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AddOTDOACellsElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AddOTDOACellsElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AddOTDOACellsElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AddOTDOACellsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AddOTDOACellsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AddOTDOACellsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AddOTDOACellsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AddOTDOACellsElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AddOTDOACellsElemValueCodec) EncodeAPER(value AddOTDOACellsElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AddOTDOACellsElemValueCodec) encodeBudget(value AddOTDOACellsElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AddOTDOACellsElemValueCodec) encodeChanged(value AddOTDOACellsElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AssistanceInformationControlValueCodec is the concrete ValueCodec[AssistanceInformationControl].
type AssistanceInformationControlValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformationControl, aper.DecodeState,

	) (AssistanceInformationControl, aper.Snapshot,

	)
	compare func(AssistanceInformationControl, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformationControl,

		error)
	encode func(AssistanceInformationControl,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationControlValueCodec) New(value AssistanceInformationControl,

) (AssistanceInformationControlAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationControlAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationControlAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationControlAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationControlValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationControlAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationControlAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationControlAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationControlAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationControlAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationControlAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationControlValueCodec) EncodeAPER(value AssistanceInformationControlAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationControlValueCodec) encodeBudget(value AssistanceInformationControl,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationControlValueCodec) encodeChanged(value AssistanceInformationControl,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOACellInformationValueCodec is the concrete ValueCodec[OTDOACellInformation].
type OTDOACellInformationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOACellInformation, aper.DecodeState,

	) (OTDOACellInformation, aper.Snapshot,

	)
	compare func(OTDOACellInformation, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOACellInformation,

		error)
	encode func(OTDOACellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOACellInformationValueCodec) New(value OTDOACellInformation,

) (OTDOACellInformationAPERValue, error) {
	if c.encode == nil {
		return OTDOACellInformationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOACellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOACellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOACellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOACellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOACellInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOACellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOACellInformationValueCodec) EncodeAPER(value OTDOACellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOACellInformationValueCodec) encodeBudget(value OTDOACellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellInformationValueCodec) encodeChanged(value OTDOACellInformation,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOACellInformationItemValueCodec is the concrete ValueCodec[OTDOACellInformationItem].
type OTDOACellInformationItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOACellInformationItem, aper.DecodeState,

	) (OTDOACellInformationItem, aper.Snapshot,

	)
	compare func(OTDOACellInformationItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOACellInformationItem,

		error)
	encode func(OTDOACellInformationItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOACellInformationItemValueCodec) New(value OTDOACellInformationItem,

) (OTDOACellInformationItemAPERValue, error) {
	if c.encode == nil {
		return OTDOACellInformationItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOACellInformationItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellInformationItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOACellInformationItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOACellInformationItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOACellInformationItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellInformationItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOACellInformationItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellInformationItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellInformationItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOACellInformationItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOACellInformationItemValueCodec) EncodeAPER(value OTDOACellInformationItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOACellInformationItemValueCodec) encodeBudget(value OTDOACellInformationItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellInformationItemValueCodec) encodeChanged(value OTDOACellInformationItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TDDConfigurationValueCodec is the concrete ValueCodec[TDDConfiguration].
type TDDConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(TDDConfiguration, aper.DecodeState,

	) (TDDConfiguration, aper.Snapshot,

	)
	compare func(TDDConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (TDDConfiguration,

		error)
	encode func(TDDConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TDDConfigurationValueCodec) New(value TDDConfiguration,

) (TDDConfigurationAPERValue, error) {
	if c.encode == nil {
		return TDDConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TDDConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TDDConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TDDConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TDDConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TDDConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TDDConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TDDConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TDDConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TDDConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TDDConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TDDConfigurationValueCodec) EncodeAPER(value TDDConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TDDConfigurationValueCodec) encodeBudget(value TDDConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TDDConfigurationValueCodec) encodeChanged(value TDDConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(fields s14.AssistanceInformationControlIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s14.BridgeAssistanceInformationControlIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s14.BridgeAssistanceInformationControlIEValueMethodRule(field.Value)
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
func BridgeSystemInformationExtIEsValueValidateLPPaExtensionContainer(fields s04.SystemInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.SystemInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.SystemInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSystemInformationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// assistanceInformationControlIEValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.AssistanceInformationControlIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.AssistanceInformationControlIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// systemInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SystemInformationExtIEsValue].
type SystemInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.SystemInformationExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.SystemInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTDDConfigurationExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.TDDConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeTDDConfigurationExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeTDDConfigurationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeTDDConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeTDDConfigurationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v), *s04.BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTDDConfigurationExtIEsValueCompareLPPaProtocolExtensionField(v *s04.TDDConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeTDDConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeTDDConfigurationExtIEsExtFieldFieldReplay(v), *s04.BridgeTDDConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// AddOTDOACellsAPERValue is the concrete APERValue[AddOTDOACells].
type AddOTDOACellsAPERValue struct {
	context s00.BridgeCodecContext
	Value   AddOTDOACells

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AddOTDOACellsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellsAPERValue) WithoutReplay() AddOTDOACellsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellInformationAPERValue is the concrete APERValue[AddOTDOACellInformation].
type AddOTDOACellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   AddOTDOACellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AddOTDOACellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellInformationAPERValue) WithoutReplay() AddOTDOACellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellsElemAPERValue is the concrete APERValue[AddOTDOACellsElem].
type AddOTDOACellsElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   AddOTDOACellsElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AddOTDOACellsElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellsElemAPERValue) WithoutReplay() AddOTDOACellsElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationControlAPERValue is the concrete APERValue[AssistanceInformationControl].
type AssistanceInformationControlAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformationControl

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationControlAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationControlAPERValue) WithoutReplay() AssistanceInformationControlAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellInformationAPERValue is the concrete APERValue[OTDOACellInformation].
type OTDOACellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOACellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOACellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellInformationAPERValue) WithoutReplay() OTDOACellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellInformationItemAPERValue is the concrete APERValue[OTDOACellInformationItem].
type OTDOACellInformationItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOACellInformationItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOACellInformationItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellInformationItemAPERValue) WithoutReplay() OTDOACellInformationItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TDDConfigurationAPERValue is the concrete APERValue[TDDConfiguration].
type TDDConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TDDConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TDDConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TDDConfigurationAPERValue) WithoutReplay() TDDConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeSystemInformationExtIEsValueValidateLPPaIEContainer(fields s04.SystemInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s03.BridgeSystemInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeSystemInformationExtIEsValueMethodRule(field.Value)
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

type AddOTDOACells = []AddOTDOACellsElem
type AddOTDOACellInformation = []OTDOACellInformationItem
type OTDOACellInformation = []OTDOACellInformationItem

// OTDOACellInformationItem represents the ASN.1 CHOICE type OTDOACell-Information-Item.
type OTDOACellInformationItem struct {
	knownOpenBytes             uint64
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              aper.WireSpan
	Choice                     int
	perPadding                 aper.CompletePadding                  `json:"-"`
	perOpenTypePadding         aper.CompletePadding                  `json:"-"`
	UnknownExtension           *aper.ChoiceExtension                 `json:"UnknownExtension,omitempty"`
	PCI                        s00.PCI                               `json:"PCI,omitzero"`
	CellId                     *s05.ECGI                             `json:"CellId,omitempty"`
	TAC                        *s00.TAC                              `json:"TAC,omitempty"`
	EARFCN                     s00.EARFCN                            `json:"EARFCN,omitzero"`
	PRSBandwidth               *s00.PRSBandwidth                     `json:"PRSBandwidth,omitempty"`
	PRSConfigurationIndex      s00.PRSConfigurationIndex             `json:"PRSConfigurationIndex,omitzero"`
	CPLength                   *s00.CPLength                         `json:"CPLength,omitempty"`
	NumberOfDlFrames           *s00.NumberOfDlFrames                 `json:"NumberOfDlFrames,omitempty"`
	NumberOfAntennaPorts       *s00.NumberOfAntennaPorts             `json:"NumberOfAntennaPorts,omitempty"`
	SFNInitialisationTime      *s00.SFNInitialisationTime            `json:"SFNInitialisationTime,omitempty"`
	EUTRANAccessPointPosition  *s06.EUTRANAccessPointPosition        `json:"EUTRANAccessPointPosition,omitempty"`
	PRSMutingConfiguration     *s08.PRSMutingConfiguration           `json:"PRSMutingConfiguration,omitempty"`
	Prsid                      s00.PRSID                             `json:"Prsid,omitzero"`
	Tpid                       s00.TPID                              `json:"Tpid,omitzero"`
	TpType                     *s00.TPType                           `json:"TpType,omitempty"`
	NumberOfDlFramesExtended   s00.NumberOfDlFramesExtended          `json:"NumberOfDlFramesExtended,omitzero"`
	CrsCPlength                *s00.CPLength                         `json:"CrsCPlength,omitempty"`
	MBSFNsubframeConfiguration s09.MBSFNsubframeConfiguration        `json:"MBSFNsubframeConfiguration,omitzero"`
	NPRSConfiguration          *s07.NPRSConfiguration                `json:"NPRSConfiguration,omitempty"`
	OffsetNBChanneltoEARFCN    *s00.OffsetNBChanneltoEARFCN          `json:"OffsetNBChanneltoEARFCN,omitempty"`
	OperationModeInfo          *s00.OperationModeInfo                `json:"OperationModeInfo,omitempty"`
	NPRSID                     *big.Int                              `json:"NPRSID,omitempty"`
	DLBandwidth                *s00.DLBandwidth                      `json:"DLBandwidth,omitempty"`
	PRSOccasionGroup           *s00.PRSOccasionGroup                 `json:"PRSOccasionGroup,omitempty"`
	PRSFreqHoppingConfig       *s08.PRSFrequencyHoppingConfiguration `json:"PRSFreqHoppingConfig,omitempty"`
	RepetitionNumberofSIB1NB   *s00.RepetitionNumberofSIB1NB         `json:"RepetitionNumberofSIB1NB,omitempty"`
	NPRSSequenceInfo           s00.NPRSSequenceInfo                  `json:"NPRSSequenceInfo,omitzero"`
	NPRSType2                  *s07.NPRSConfiguration                `json:"NPRSType2,omitempty"`
	TddConfiguration           *TDDConfiguration                     `json:"TddConfiguration,omitempty"`
}

// TDDConfiguration represents the ASN.1 type TDDConfiguration (SEQUENCE).
type TDDConfiguration struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	SubframeAssignment int64                                  `asn1:"tag:0,context,implicit"`
	IEExtensions       s04.TDDConfigurationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                   `asn1:"-" json:"-"`
	extCount           int64                                  `asn1:"-" json:"-"`
	extPresent         []bool                                 `asn1:"-" json:"-"`
	extData            [][]byte                               `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// AddOTDOACellsElem represents the ASN.1 type Add-OTDOACells-Elem (SEQUENCE).
type AddOTDOACellsElem struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         aper.WireSpan
	AddOTDOACellInfo      AddOTDOACellInformation             `asn1:"tag:0,context,implicit"`
	addOTDOACellInfoIndef bool                                `asn1:"-" json:"-"`
	IEExtensions          s03.AddOTDOACellsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                `asn1:"-" json:"-"`
	extCount              int64                               `asn1:"-" json:"-"`
	extPresent            []bool                              `asn1:"-" json:"-"`
	extData               [][]byte                            `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type BridgeAsn1cAPERAddOTDOACellsListValue struct{ Value AddOTDOACells }
type BridgeAsn1cAPERAddOTDOACellInformationListValue struct{ Value AddOTDOACellInformation }
type BridgeAsn1cAPEROTDOACellInformationListValue struct{ Value OTDOACellInformation }

// MarshalAPER encodes OTDOACellInformationItem to APER format.
func (v *OTDOACellInformationItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *OTDOACellInformationItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "OTDOACellInformationItem:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "OTDOACellInformationItem:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 18 {
			return fmt.Errorf("%s extension index %d is known to this schema", "OTDOACellInformationItem:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "OTDOACellInformationItem:", v.Choice)
	}
	isExtension := v.Choice > 11
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 11 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-11-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.OTDOACellInformationItemChoicePRSMutingConfiguration:
			if v.PRSMutingConfiguration == nil {
				return fmt.Errorf("choice alternative pRSMutingConfiguration is nil")
			}
			if err := s08.BridgePRSMutingConfigurationMethodMarshalAPERTo(v.PRSMutingConfiguration, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding pRSMutingConfiguration: %w", err)
			}
		case s00.OTDOACellInformationItemChoicePrsid:
			if err := aper.EncodeIntegerBigBoundsAligned(inner, v.Prsid, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return fmt.Errorf("encoding prsid: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceTpid:
			if err := aper.EncodeIntegerBigBoundsAligned(inner, v.Tpid, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return fmt.Errorf("encoding tpid: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceTpType:
			if v.TpType == nil {
				return fmt.Errorf("choice alternative tpType is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.TpType), 1, true); err != nil {
				return fmt.Errorf("encoding tpType: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			if err := aper.EncodeIntegerBigBoundsAligned(inner, v.NumberOfDlFramesExtended, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound9, true); err != nil {
				return fmt.Errorf("encoding numberOfDlFrames-Extended: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceCrsCPlength:
			if v.CrsCPlength == nil {
				return fmt.Errorf("choice alternative crsCPlength is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.CrsCPlength), 2, true); err != nil {
				return fmt.Errorf("encoding crsCPlength: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			if err := aper.EncodeCollection(inner, int64(len(v.MBSFNsubframeConfiguration)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_mbsfnsubframeconfiguration < 0 || fragmentOffset_mbsfnsubframeconfiguration > int64(len(v.MBSFNsubframeConfiguration)) || fragmentLength_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration > int64(len(v.MBSFNsubframeConfiguration[fragmentOffset_mbsfnsubframeconfiguration:])) {
					return fmt.Errorf("collection fragment outside value")
				}
				for _, elem := range v.MBSFNsubframeConfiguration[fragmentOffset_mbsfnsubframeconfiguration : fragmentOffset_mbsfnsubframeconfiguration+fragmentLength_mbsfnsubframeconfiguration] {
					if err := s09.BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(&elem, inner, len(fresh) != 0 && fresh[0]); err != nil {
						return fmt.Errorf("encoding mBSFNsubframeConfiguration element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding mBSFNsubframeConfiguration: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceNPRSConfiguration:
			if v.NPRSConfiguration == nil {
				return fmt.Errorf("choice alternative nPRSConfiguration is nil")
			}
			if err := s07.BridgeNPRSConfigurationMethodMarshalAPERTo(v.NPRSConfiguration, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding nPRSConfiguration: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			if v.OffsetNBChanneltoEARFCN == nil {
				return fmt.Errorf("choice alternative offsetNBChanneltoEARFCN is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.OffsetNBChanneltoEARFCN), 21, true); err != nil {
				return fmt.Errorf("encoding offsetNBChanneltoEARFCN: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceOperationModeInfo:
			if v.OperationModeInfo == nil {
				return fmt.Errorf("choice alternative operationModeInfo is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.OperationModeInfo), 3, true); err != nil {
				return fmt.Errorf("encoding operationModeInfo: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceNPRSID:
			if err := aper.EncodeIntegerBigBoundsAligned(inner, v.NPRSID, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return fmt.Errorf("encoding nPRS-ID: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceDLBandwidth:
			if v.DLBandwidth == nil {
				return fmt.Errorf("choice alternative dL-Bandwidth is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.DLBandwidth), 6, true); err != nil {
				return fmt.Errorf("encoding dL-Bandwidth: %w", err)
			}
		case s00.OTDOACellInformationItemChoicePRSOccasionGroup:
			if v.PRSOccasionGroup == nil {
				return fmt.Errorf("choice alternative pRSOccasionGroup is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.PRSOccasionGroup), 7, true); err != nil {
				return fmt.Errorf("encoding pRSOccasionGroup: %w", err)
			}
		case s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			if v.PRSFreqHoppingConfig == nil {
				return fmt.Errorf("choice alternative pRSFreqHoppingConfig is nil")
			}
			if err := s08.BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERTo(v.PRSFreqHoppingConfig, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding pRSFreqHoppingConfig: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			if v.RepetitionNumberofSIB1NB == nil {
				return fmt.Errorf("choice alternative repetitionNumberofSIB1-NB is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.RepetitionNumberofSIB1NB), 3, true); err != nil {
				return fmt.Errorf("encoding repetitionNumberofSIB1-NB: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceNPRSSequenceInfo:
			if err := aper.EncodeIntegerBigBoundsAligned(inner, v.NPRSSequenceInfo, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound11, true); err != nil {
				return fmt.Errorf("encoding nPRSSequenceInfo: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceNPRSType2:
			if v.NPRSType2 == nil {
				return fmt.Errorf("choice alternative nPRSType2 is nil")
			}
			if err := s07.BridgeNPRSConfigurationMethodMarshalAPERTo(v.NPRSType2, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding nPRSType2: %w", err)
			}
		case s00.OTDOACellInformationItemChoiceTddConfiguration:
			if v.TddConfiguration == nil {
				return fmt.Errorf("choice alternative tddConfiguration is nil")
			}
			if err := v.TddConfiguration.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding tddConfiguration: %w", err)
			}
		default:
			return fmt.Errorf("unknown OTDOACellInformationItem extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.perOpenTypePadding)
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 10); err != nil {
		return err
	}
	switch v.Choice {
	case s00.OTDOACellInformationItemChoicePCI:
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PCI, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
			return fmt.Errorf("encoding pCI: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceCellId:
		if v.CellId == nil {
			return fmt.Errorf("choice alternative cellId is nil")
		}
		if err := s05.BridgeECGIMethodMarshalAPERTo(v.CellId, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellId: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceTAC:
		if v.TAC == nil {
			return fmt.Errorf("choice alternative tAC is nil")
		}
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.TAC), 2, 2, true); err != nil {
			return fmt.Errorf("encoding tAC: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceEARFCN:
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
			return fmt.Errorf("encoding eARFCN: %w", err)
		}
	case s00.OTDOACellInformationItemChoicePRSBandwidth:
		if v.PRSBandwidth == nil {
			return fmt.Errorf("choice alternative pRS-Bandwidth is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.PRSBandwidth), 6, true); err != nil {
			return fmt.Errorf("encoding pRS-Bandwidth: %w", err)
		}
	case s00.OTDOACellInformationItemChoicePRSConfigurationIndex:
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PRSConfigurationIndex, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
			return fmt.Errorf("encoding pRS-ConfigurationIndex: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceCPLength:
		if v.CPLength == nil {
			return fmt.Errorf("choice alternative cPLength is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CPLength), 2, true); err != nil {
			return fmt.Errorf("encoding cPLength: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfDlFrames:
		if v.NumberOfDlFrames == nil {
			return fmt.Errorf("choice alternative numberOfDlFrames is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.NumberOfDlFrames), 4, true); err != nil {
			return fmt.Errorf("encoding numberOfDlFrames: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		if v.NumberOfAntennaPorts == nil {
			return fmt.Errorf("choice alternative numberOfAntennaPorts is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.NumberOfAntennaPorts), 2, true); err != nil {
			return fmt.Errorf("encoding numberOfAntennaPorts: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceSFNInitialisationTime:
		if v.SFNInitialisationTime == nil {
			return fmt.Errorf("choice alternative sFNInitialisationTime is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.SFNInitialisationTime.Bytes, v.SFNInitialisationTime.BitLength, 64, 64, true); err != nil {
			return fmt.Errorf("encoding sFNInitialisationTime: %w", err)
		}
	case s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		if v.EUTRANAccessPointPosition == nil {
			return fmt.Errorf("choice alternative e-UTRANAccessPointPosition is nil")
		}
		if err := s06.BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v.EUTRANAccessPointPosition, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	default:
		return fmt.Errorf("unknown OTDOACellInformationItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes OTDOACellInformationItem from APER format.
func (v *OTDOACellInformationItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACellInformationItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellInformationItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	bb.EnterComponent("OTDOACellInformationItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOACellInformationItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformationItem")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *OTDOACellInformationItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellInformationItem{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 18)
		if extIdx < 18 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
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
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 11 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.OTDOACellInformationItemChoicePRSMutingConfiguration:
			extensionPath = "PRSMutingConfiguration"
			toleranceMark_prsmutingconfiguration := inner.EnterComponent("PRSMutingConfiguration")
			var dec_prsmutingconfiguration s08.PRSMutingConfiguration
			if err := s08.BridgePRSMutingConfigurationMethodUnmarshalAPERFrom(&dec_prsmutingconfiguration, inner); err != nil {
				return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
			}
			if err := aper.ChargeValue(inner, dec_prsmutingconfiguration); err != nil {
				return err
			}
			v.PRSMutingConfiguration = &dec_prsmutingconfiguration
			inner.LeaveComponent(toleranceMark_prsmutingconfiguration)
		case s00.OTDOACellInformationItemChoicePrsid:
			extensionPath = "Prsid"
			val_prsid, err := aper.DecodeIntegerBigBoundsAligned(inner, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "Prsid")
			}
			v.Prsid = val_prsid
		case s00.OTDOACellInformationItemChoiceTpid:
			extensionPath = "Tpid"
			val_tpid, err := aper.DecodeIntegerBigBoundsAligned(inner, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "Tpid")
			}
			v.Tpid = val_tpid
		case s00.OTDOACellInformationItemChoiceTpType:
			extensionPath = "TpType"
			val_tptype, err := aper.DecodeEnumeratedAligned(inner, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TpType"})
			if err != nil {
				return runtime.WrapDecodePath(err, "TpType")
			}
			tmp_tptype := s00.TPType(val_tptype)
			if err := aper.ChargeValue(inner, tmp_tptype); err != nil {
				return err
			}
			v.TpType = (*s00.TPType)(bb.OwnInt64(int64(tmp_tptype)))
		case s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
			extensionPath = "NumberOfDlFramesExtended"
			val_numberofdlframesextended, err := aper.DecodeIntegerBigBoundsAligned(inner, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound9, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NumberOfDlFramesExtended")
			}
			v.NumberOfDlFramesExtended = val_numberofdlframesextended
		case s00.OTDOACellInformationItemChoiceCrsCPlength:
			extensionPath = "CrsCPlength"
			val_crscplength, err := aper.DecodeEnumeratedAligned(inner, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CrsCPlength"})
			if err != nil {
				return runtime.WrapDecodePath(err, "CrsCPlength")
			}
			tmp_crscplength := s00.CPLength(val_crscplength)
			if err := aper.ChargeValue(inner, tmp_crscplength); err != nil {
				return err
			}
			v.CrsCPlength = (*s00.CPLength)(bb.OwnInt64(int64(tmp_crscplength)))
		case s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
			extensionPath = "MBSFNsubframeConfiguration"
			toleranceMark_mbsfnsubframeconfiguration := inner.EnterComponent("MBSFNsubframeConfiguration")
			tmp_mbsfnsubframeconfiguration := make(s09.MBSFNsubframeConfiguration, 0)
			_, errCollection_mbsfnsubframeconfiguration := aper.DecodeCollection(inner, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnsubframeconfiguration, fragmentLength_mbsfnsubframeconfiguration int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
				if fragmentOffset_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration < 0 || fragmentLength_mbsfnsubframeconfiguration > int64(^uint(0)>>1) || fragmentOffset_mbsfnsubframeconfiguration > int64(^uint(0)>>1)-fragmentLength_mbsfnsubframeconfiguration {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_mbsfnsubframeconfiguration; i++ {
					var elem s09.MBSFNsubframeConfigurationValue
					elementMark := inner.EnterIndex(fragmentOffset_mbsfnsubframeconfiguration + i)
					if err := s09.BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(&elem, inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNsubframeConfiguration[%d]", fragmentOffset_mbsfnsubframeconfiguration+i))
					}
					inner.LeaveComponent(elementMark)
					if next, err := aper.AppendValues(inner, tmp_mbsfnsubframeconfiguration, elem); err != nil {
						return err
					} else {
						tmp_mbsfnsubframeconfiguration = next
					}
				}
				return nil
			})
			if errCollection_mbsfnsubframeconfiguration != nil {
				return runtime.WrapDecodePath(errCollection_mbsfnsubframeconfiguration, "MBSFNsubframeConfiguration")
			}
			v.MBSFNsubframeConfiguration = tmp_mbsfnsubframeconfiguration
			inner.LeaveComponent(toleranceMark_mbsfnsubframeconfiguration)
		case s00.OTDOACellInformationItemChoiceNPRSConfiguration:
			extensionPath = "NPRSConfiguration"
			toleranceMark_nprsconfiguration := inner.EnterComponent("NPRSConfiguration")
			var dec_nprsconfiguration s07.NPRSConfiguration
			if err := s07.BridgeNPRSConfigurationMethodUnmarshalAPERFrom(&dec_nprsconfiguration, inner); err != nil {
				return runtime.WrapDecodePath(err, "NPRSConfiguration")
			}
			if err := aper.ChargeValue(inner, dec_nprsconfiguration); err != nil {
				return err
			}
			v.NPRSConfiguration = &dec_nprsconfiguration
			inner.LeaveComponent(toleranceMark_nprsconfiguration)
		case s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
			extensionPath = "OffsetNBChanneltoEARFCN"
			val_offsetnbchanneltoearfcn, err := aper.DecodeEnumeratedAligned(inner, 21, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OffsetNBChanneltoEARFCN"})
			if err != nil {
				return runtime.WrapDecodePath(err, "OffsetNBChanneltoEARFCN")
			}
			tmp_offsetnbchanneltoearfcn := s00.OffsetNBChanneltoEARFCN(val_offsetnbchanneltoearfcn)
			if err := aper.ChargeValue(inner, tmp_offsetnbchanneltoearfcn); err != nil {
				return err
			}
			v.OffsetNBChanneltoEARFCN = (*s00.OffsetNBChanneltoEARFCN)(bb.OwnInt64(int64(tmp_offsetnbchanneltoearfcn)))
		case s00.OTDOACellInformationItemChoiceOperationModeInfo:
			extensionPath = "OperationModeInfo"
			val_operationmodeinfo, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OperationModeInfo"})
			if err != nil {
				return runtime.WrapDecodePath(err, "OperationModeInfo")
			}
			tmp_operationmodeinfo := s00.OperationModeInfo(val_operationmodeinfo)
			if err := aper.ChargeValue(inner, tmp_operationmodeinfo); err != nil {
				return err
			}
			v.OperationModeInfo = (*s00.OperationModeInfo)(bb.OwnInt64(int64(tmp_operationmodeinfo)))
		case s00.OTDOACellInformationItemChoiceNPRSID:
			extensionPath = "NPRSID"
			val_nprsid, err := aper.DecodeIntegerBigBoundsAligned(inner, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NPRSID")
			}
			v.NPRSID = val_nprsid
		case s00.OTDOACellInformationItemChoiceDLBandwidth:
			extensionPath = "DLBandwidth"
			val_dlbandwidth, err := aper.DecodeEnumeratedAligned(inner, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DLBandwidth"})
			if err != nil {
				return runtime.WrapDecodePath(err, "DLBandwidth")
			}
			tmp_dlbandwidth := s00.DLBandwidth(val_dlbandwidth)
			if err := aper.ChargeValue(inner, tmp_dlbandwidth); err != nil {
				return err
			}
			v.DLBandwidth = (*s00.DLBandwidth)(bb.OwnInt64(int64(tmp_dlbandwidth)))
		case s00.OTDOACellInformationItemChoicePRSOccasionGroup:
			extensionPath = "PRSOccasionGroup"
			val_prsoccasiongroup, err := aper.DecodeEnumeratedAligned(inner, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PRSOccasionGroup"})
			if err != nil {
				return runtime.WrapDecodePath(err, "PRSOccasionGroup")
			}
			tmp_prsoccasiongroup := s00.PRSOccasionGroup(val_prsoccasiongroup)
			if err := aper.ChargeValue(inner, tmp_prsoccasiongroup); err != nil {
				return err
			}
			v.PRSOccasionGroup = (*s00.PRSOccasionGroup)(bb.OwnInt64(int64(tmp_prsoccasiongroup)))
		case s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
			extensionPath = "PRSFreqHoppingConfig"
			toleranceMark_prsfreqhoppingconfig := inner.EnterComponent("PRSFreqHoppingConfig")
			var dec_prsfreqhoppingconfig s08.PRSFrequencyHoppingConfiguration
			if err := s08.BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERFrom(&dec_prsfreqhoppingconfig, inner); err != nil {
				return runtime.WrapDecodePath(err, "PRSFreqHoppingConfig")
			}
			if err := aper.ChargeValue(inner, dec_prsfreqhoppingconfig); err != nil {
				return err
			}
			v.PRSFreqHoppingConfig = &dec_prsfreqhoppingconfig
			inner.LeaveComponent(toleranceMark_prsfreqhoppingconfig)
		case s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
			extensionPath = "RepetitionNumberofSIB1NB"
			val_repetitionnumberofsib1nb, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RepetitionNumberofSIB1NB"})
			if err != nil {
				return runtime.WrapDecodePath(err, "RepetitionNumberofSIB1NB")
			}
			tmp_repetitionnumberofsib1nb := s00.RepetitionNumberofSIB1NB(val_repetitionnumberofsib1nb)
			if err := aper.ChargeValue(inner, tmp_repetitionnumberofsib1nb); err != nil {
				return err
			}
			v.RepetitionNumberofSIB1NB = (*s00.RepetitionNumberofSIB1NB)(bb.OwnInt64(int64(tmp_repetitionnumberofsib1nb)))
		case s00.OTDOACellInformationItemChoiceNPRSSequenceInfo:
			extensionPath = "NPRSSequenceInfo"
			val_nprssequenceinfo, err := aper.DecodeIntegerBigBoundsAligned(inner, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound11, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "NPRSSequenceInfo")
			}
			v.NPRSSequenceInfo = val_nprssequenceinfo
		case s00.OTDOACellInformationItemChoiceNPRSType2:
			extensionPath = "NPRSType2"
			toleranceMark_nprstype2 := inner.EnterComponent("NPRSType2")
			var dec_nprstype2 s07.NPRSConfiguration
			if err := s07.BridgeNPRSConfigurationMethodUnmarshalAPERFrom(&dec_nprstype2, inner); err != nil {
				return runtime.WrapDecodePath(err, "NPRSType2")
			}
			if err := aper.ChargeValue(inner, dec_nprstype2); err != nil {
				return err
			}
			v.NPRSType2 = &dec_nprstype2
			inner.LeaveComponent(toleranceMark_nprstype2)
		case s00.OTDOACellInformationItemChoiceTddConfiguration:
			extensionPath = "TddConfiguration"
			toleranceMark_tddconfiguration := inner.EnterComponent("TddConfiguration")
			var dec_tddconfiguration TDDConfiguration
			if err := dec_tddconfiguration.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TddConfiguration")
			}
			if err := aper.ChargeValue(inner, dec_tddconfiguration); err != nil {
				return err
			}
			v.TddConfiguration = &dec_tddconfiguration
			inner.LeaveComponent(toleranceMark_tddconfiguration)
		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 10)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.OTDOACellInformationItemChoicePCI:
		val_pci, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PCI")
		}
		v.PCI = val_pci
	case s00.OTDOACellInformationItemChoiceCellId:
		toleranceMark_cellid := bb.EnterComponent("CellId")
		var dec_cellid s05.ECGI
		if err := s05.BridgeECGIMethodUnmarshalAPERFrom(&dec_cellid, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellId")
		}
		if err := aper.ChargeValue(bb, dec_cellid); err != nil {
			return err
		}
		v.CellId = &dec_cellid
		bb.LeaveComponent(toleranceMark_cellid)
	case s00.OTDOACellInformationItemChoiceTAC:
		val_tac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "TAC")
		}
		tmp_tac := s00.TAC(val_tac)
		if err := aper.ChargeValue(bb, tmp_tac); err != nil {
			return err
		}
		v.TAC = &tmp_tac
	case s00.OTDOACellInformationItemChoiceEARFCN:
		val_earfcn, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "EARFCN")
		}
		v.EARFCN = val_earfcn
	case s00.OTDOACellInformationItemChoicePRSBandwidth:
		val_prsbandwidth, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PRSBandwidth"})
		if err != nil {
			return runtime.WrapDecodePath(err, "PRSBandwidth")
		}
		tmp_prsbandwidth := s00.PRSBandwidth(val_prsbandwidth)
		if err := aper.ChargeValue(bb, tmp_prsbandwidth); err != nil {
			return err
		}
		v.PRSBandwidth = (*s00.PRSBandwidth)(bb.OwnInt64(int64(tmp_prsbandwidth)))
	case s00.OTDOACellInformationItemChoicePRSConfigurationIndex:
		val_prsconfigurationindex, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PRSConfigurationIndex")
		}
		v.PRSConfigurationIndex = val_prsconfigurationindex
	case s00.OTDOACellInformationItemChoiceCPLength:
		val_cplength, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CPLength"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CPLength")
		}
		tmp_cplength := s00.CPLength(val_cplength)
		if err := aper.ChargeValue(bb, tmp_cplength); err != nil {
			return err
		}
		v.CPLength = (*s00.CPLength)(bb.OwnInt64(int64(tmp_cplength)))
	case s00.OTDOACellInformationItemChoiceNumberOfDlFrames:
		val_numberofdlframes, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfDlFrames"})
		if err != nil {
			return runtime.WrapDecodePath(err, "NumberOfDlFrames")
		}
		tmp_numberofdlframes := s00.NumberOfDlFrames(val_numberofdlframes)
		if err := aper.ChargeValue(bb, tmp_numberofdlframes); err != nil {
			return err
		}
		v.NumberOfDlFrames = (*s00.NumberOfDlFrames)(bb.OwnInt64(int64(tmp_numberofdlframes)))
	case s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		val_numberofantennaports, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfAntennaPorts"})
		if err != nil {
			return runtime.WrapDecodePath(err, "NumberOfAntennaPorts")
		}
		tmp_numberofantennaports := s00.NumberOfAntennaPorts(val_numberofantennaports)
		if err := aper.ChargeValue(bb, tmp_numberofantennaports); err != nil {
			return err
		}
		v.NumberOfAntennaPorts = (*s00.NumberOfAntennaPorts)(bb.OwnInt64(int64(tmp_numberofantennaports)))
	case s00.OTDOACellInformationItemChoiceSFNInitialisationTime:
		bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := aper.DecodeBitStringAligned(bb, 64, 64, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SFNInitialisationTime")
		}
		tmp_sfninitialisationtime := runtime.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
		if err := aper.ChargeValue(bb, tmp_sfninitialisationtime); err != nil {
			return err
		}
		v.SFNInitialisationTime = &tmp_sfninitialisationtime
	case s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		toleranceMark_eutranaccesspointposition := bb.EnterComponent("EUTRANAccessPointPosition")
		var dec_eutranaccesspointposition s06.EUTRANAccessPointPosition
		if err := s06.BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(&dec_eutranaccesspointposition, bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		if err := aper.ChargeValue(bb, dec_eutranaccesspointposition); err != nil {
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
func BridgeMarshalAPERSystemInformationTo(list s14.SystemInformation, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s14.BridgeAsn1cAPERSystemInformationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s14.BridgeSystemInformationElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes TDDConfiguration to APER format.
func (v *TDDConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TDDConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SubframeAssignment), 7, true); err != nil {
		return fmt.Errorf("encoding subframeAssignment: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeTDDConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TDDConfiguration from APER format.
func (v *TDDConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TDDConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TDDConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TDDConfiguration")
	}
	bb.EnterComponent("TDDConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TDDConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "TDDConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "TDDConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TDDConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TDDConfiguration{}
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
	val_subframeassignment, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SubframeAssignment"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SubframeAssignment")
	}
	v.SubframeAssignment = val_subframeassignment
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.TDDConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.TDDConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeTDDConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes AddOTDOACellsElem to APER format.
func (v *AddOTDOACellsElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AddOTDOACellsElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.AddOTDOACellInfo)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_addotdoacellinfo < 0 || fragmentOffset_addotdoacellinfo > int64(len(v.AddOTDOACellInfo)) || fragmentLength_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo > int64(len(v.AddOTDOACellInfo[fragmentOffset_addotdoacellinfo:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.AddOTDOACellInfo[fragmentOffset_addotdoacellinfo : fragmentOffset_addotdoacellinfo+fragmentLength_addotdoacellinfo] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding add-OTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding add-OTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeAddOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AddOTDOACellsElem from APER format.
func (v *AddOTDOACellsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AddOTDOACellsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AddOTDOACellsElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	bb.EnterComponent("AddOTDOACellsElem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "AddOTDOACellsElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AddOTDOACellsElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AddOTDOACellsElem{}
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
	toleranceMark_addotdoacellinfo := bb.EnterComponent("AddOTDOACellInfo")
	v.AddOTDOACellInfo = make(AddOTDOACellInformation, 0)
	_, errCollection_addotdoacellinfo := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_addotdoacellinfo, fragmentLength_addotdoacellinfo int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo < 0 || fragmentLength_addotdoacellinfo > int64(^uint(0)>>1) || fragmentOffset_addotdoacellinfo > int64(^uint(0)>>1)-fragmentLength_addotdoacellinfo {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_addotdoacellinfo; i++ {
			var elem OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_addotdoacellinfo + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("AddOTDOACellInfo[%d]", fragmentOffset_addotdoacellinfo+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.AddOTDOACellInfo, elem); err != nil {
				return err
			} else {
				v.AddOTDOACellInfo = next
			}
		}
		return nil
	})
	if errCollection_addotdoacellinfo != nil {
		return runtime.WrapDecodePath(errCollection_addotdoacellinfo, "AddOTDOACellInfo")
	}
	bb.LeaveComponent(toleranceMark_addotdoacellinfo)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s03.AddOTDOACellsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.AddOTDOACellsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s03.BridgeAddOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *AddOTDOACellsElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellsElem) WithoutReplay() AddOTDOACellsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AddOTDOACellsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellInformationItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellInformationItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellInformationItem) WithoutReplay() OTDOACellInformationItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOACellInformationItem
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TDDConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "TDDConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TDDConfiguration) WithoutReplay() TDDConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero TDDConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AddOTDOACellsElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AddOTDOACellsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AddOTDOACellsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AddOTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TDDConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TDDConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TDDConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TDDConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AddOTDOACellsElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellsElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AddOTDOACellsElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AddOTDOACellsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AddOTDOACellsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AddOTDOACellsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AddOTDOACellsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AddOTDOACellsElem")
}
func (v *AddOTDOACellsElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellsElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellsElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *AddOTDOACellsElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellsElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *OTDOACellInformationItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOACellInformationItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOACellInformationItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellInformationItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOACellInformationItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOACellInformationItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOACellInformationItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOACellInformationItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOACellInformationItem")
}
func (v *OTDOACellInformationItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellInformationItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellInformationItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *OTDOACellInformationItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *TDDConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TDDConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "TDDConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaTDDConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "TDDConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "TDDConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "TDDConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "TDDConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "TDDConfiguration")
}
func (v *TDDConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *TDDConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *TDDConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *TDDConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *TDDConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AddOTDOACellsElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellsElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellsElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellsElem{}
		return report, aper.OperationError(err, "AddOTDOACellsElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AddOTDOACellsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellInformationItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOACellInformationItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellInformationItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellInformationItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellInformationItem{}
		return report, aper.OperationError(err, "OTDOACellInformationItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOACellInformationItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *TDDConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TDDConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded TDDConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaTDDConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = TDDConfiguration{}
		return report, aper.OperationError(err, "TDDConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TDDConfiguration")
}

// NewOTDOACellInformationItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewOTDOACellInformationItemUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	value := OTDOACellInformationItem{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemUnknownExtension")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemUnknownExtension")
}

// AssistanceInformationControl represents the ASN.1 type AssistanceInformationControl (SEQUENCE).
type AssistanceInformationControl struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s14.AssistanceInformationControlIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes AssistanceInformationControl to APER format.
func (v *AssistanceInformationControl) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationControl) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s14.BridgeAssistanceInformationControlIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformationControl from APER format.
func (v *AssistanceInformationControl) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationControl with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationControl) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationControl")
	}
	bb.EnterComponent("AssistanceInformationControl")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationControl")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformationControl")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationControl")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationControl) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationControl{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.AssistanceInformationControlIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.AssistanceInformationControlIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.BridgeAssistanceInformationControlIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationControl) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationControl", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationControl) WithoutReplay() AssistanceInformationControl {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformationControl
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationControl) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationControl) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationControl) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationControl.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AssistanceInformationControl) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationControl")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformationControl")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationControl(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformationControl")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformationControl")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformationControl")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformationControl")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformationControl")
}
func (v *AssistanceInformationControl) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationControl) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationControl) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *AssistanceInformationControl) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationControl) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationControl) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationControl")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationControl
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationControl(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationControl{}
		return report, aper.OperationError(err, "AssistanceInformationControl")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformationControl")
}
func BridgeCaptureLPPaAddOTDOACellInformation(v *AddOTDOACellInformation, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaAddOTDOACellInformation(v *AddOTDOACellInformation, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaAddOTDOACells(v *AddOTDOACells, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaAddOTDOACells(v *AddOTDOACells, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaAddOTDOACellsElem(v *AddOTDOACellsElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeCaptureLPPaAddOTDOACellInformation(&v.AddOTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAddOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellsElem(v *AddOTDOACellsElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeCompareLPPaAddOTDOACellInformation(&v.AddOTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAddOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationControl(v *AssistanceInformationControl, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s14.BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationControl(v *AssistanceInformationControl, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s14.BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellInformation(v *OTDOACellInformation, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaOTDOACellInformation(v *OTDOACellInformation, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOACellInformationItem(v *OTDOACellInformationItem, s *aper.SemanticCapture) {
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
	case s00.OTDOACellInformationItemChoicePCI:
		s00.BridgeCaptureLPPaPCI(&v.PCI, s)
	case s00.OTDOACellInformationItemChoiceCellId:
		{
			f := s.Begin()
			s.Bool(v.CellId == nil)
			if v.CellId != nil {
				s05.BridgeCaptureLPPaECGI(v.CellId, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceTAC:
		{
			f := s.Begin()
			s.Bool(v.TAC == nil)
			if v.TAC != nil {
				s00.BridgeCaptureLPPaTAC(v.TAC, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceEARFCN:
		s00.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	case s00.OTDOACellInformationItemChoicePRSBandwidth:
		{
			f := s.Begin()
			s.Bool(v.PRSBandwidth == nil)
			if v.PRSBandwidth != nil {
				s00.BridgeCaptureLPPaPRSBandwidth(v.PRSBandwidth, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoicePRSConfigurationIndex:
		s00.BridgeCaptureLPPaPRSConfigurationIndex(&v.PRSConfigurationIndex, s)
	case s00.OTDOACellInformationItemChoiceCPLength:
		{
			f := s.Begin()
			s.Bool(v.CPLength == nil)
			if v.CPLength != nil {
				s00.BridgeCaptureLPPaCPLength(v.CPLength, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfDlFrames:
		{
			f := s.Begin()
			s.Bool(v.NumberOfDlFrames == nil)
			if v.NumberOfDlFrames != nil {
				s00.BridgeCaptureLPPaNumberOfDlFrames(v.NumberOfDlFrames, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		{
			f := s.Begin()
			s.Bool(v.NumberOfAntennaPorts == nil)
			if v.NumberOfAntennaPorts != nil {
				s00.BridgeCaptureLPPaNumberOfAntennaPorts(v.NumberOfAntennaPorts, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceSFNInitialisationTime:
		{
			f := s.Begin()
			s.Bool(v.SFNInitialisationTime == nil)
			if v.SFNInitialisationTime != nil {
				s00.BridgeCaptureLPPaSFNInitialisationTime(v.SFNInitialisationTime, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		{
			f := s.Begin()
			s.Bool(v.EUTRANAccessPointPosition == nil)
			if v.EUTRANAccessPointPosition != nil {
				s06.BridgeCaptureLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoicePRSMutingConfiguration:
		{
			f := s.Begin()
			s.Bool(v.PRSMutingConfiguration == nil)
			if v.PRSMutingConfiguration != nil {
				s08.BridgeCaptureLPPaPRSMutingConfiguration(v.PRSMutingConfiguration, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoicePrsid:
		s00.BridgeCaptureLPPaPRSID(&v.Prsid, s)
	case s00.OTDOACellInformationItemChoiceTpid:
		s00.BridgeCaptureLPPaTPID(&v.Tpid, s)
	case s00.OTDOACellInformationItemChoiceTpType:
		{
			f := s.Begin()
			s.Bool(v.TpType == nil)
			if v.TpType != nil {
				s00.BridgeCaptureLPPaTPType(v.TpType, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
		s00.BridgeCaptureLPPaNumberOfDlFramesExtended(&v.NumberOfDlFramesExtended, s)
	case s00.OTDOACellInformationItemChoiceCrsCPlength:
		{
			f := s.Begin()
			s.Bool(v.CrsCPlength == nil)
			if v.CrsCPlength != nil {
				s00.BridgeCaptureLPPaCPLength(v.CrsCPlength, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
		s09.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, s)
	case s00.OTDOACellInformationItemChoiceNPRSConfiguration:
		{
			f := s.Begin()
			s.Bool(v.NPRSConfiguration == nil)
			if v.NPRSConfiguration != nil {
				s07.BridgeCaptureLPPaNPRSConfiguration(v.NPRSConfiguration, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
		{
			f := s.Begin()
			s.Bool(v.OffsetNBChanneltoEARFCN == nil)
			if v.OffsetNBChanneltoEARFCN != nil {
				s00.BridgeCaptureLPPaOffsetNBChanneltoEARFCN(v.OffsetNBChanneltoEARFCN, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceOperationModeInfo:
		{
			f := s.Begin()
			s.Bool(v.OperationModeInfo == nil)
			if v.OperationModeInfo != nil {
				s00.BridgeCaptureLPPaOperationModeInfo(v.OperationModeInfo, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceNPRSID:
		{
			f := s.Begin()
			s.BigInt(v.NPRSID)
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceDLBandwidth:
		{
			f := s.Begin()
			s.Bool(v.DLBandwidth == nil)
			if v.DLBandwidth != nil {
				s00.BridgeCaptureLPPaDLBandwidth(v.DLBandwidth, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoicePRSOccasionGroup:
		{
			f := s.Begin()
			s.Bool(v.PRSOccasionGroup == nil)
			if v.PRSOccasionGroup != nil {
				s00.BridgeCaptureLPPaPRSOccasionGroup(v.PRSOccasionGroup, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
		{
			f := s.Begin()
			s.Bool(v.PRSFreqHoppingConfig == nil)
			if v.PRSFreqHoppingConfig != nil {
				s08.BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
		{
			f := s.Begin()
			s.Bool(v.RepetitionNumberofSIB1NB == nil)
			if v.RepetitionNumberofSIB1NB != nil {
				s00.BridgeCaptureLPPaRepetitionNumberofSIB1NB(v.RepetitionNumberofSIB1NB, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceNPRSSequenceInfo:
		s00.BridgeCaptureLPPaNPRSSequenceInfo(&v.NPRSSequenceInfo, s)
	case s00.OTDOACellInformationItemChoiceNPRSType2:
		{
			f := s.Begin()
			s.Bool(v.NPRSType2 == nil)
			if v.NPRSType2 != nil {
				s07.BridgeCaptureLPPaNPRSConfiguration(v.NPRSType2, s)
			}
			s.End(f, nil, false)
		}
	case s00.OTDOACellInformationItemChoiceTddConfiguration:
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
func BridgeCompareLPPaOTDOACellInformationItem(v *OTDOACellInformationItem, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.OTDOACellInformationItemChoicePCI:
		s02.BridgeCompareLPPaPCI(&v.PCI, s)
	case s00.OTDOACellInformationItemChoiceCellId:
		{
			f := s.Begin()
			s.Bool(v.CellId == nil)
			if v.CellId != nil {
				s05.BridgeCompareLPPaECGI(v.CellId, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceTAC:
		{
			f := s.Begin()
			s.Bool(v.TAC == nil)
			if v.TAC != nil {
				s03.BridgeCompareLPPaTAC(v.TAC, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceEARFCN:
		s02.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	case s00.OTDOACellInformationItemChoicePRSBandwidth:
		{
			f := s.Begin()
			s.Bool(v.PRSBandwidth == nil)
			if v.PRSBandwidth != nil {
				s02.BridgeCompareLPPaPRSBandwidth(v.PRSBandwidth, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoicePRSConfigurationIndex:
		s02.BridgeCompareLPPaPRSConfigurationIndex(&v.PRSConfigurationIndex, s)
	case s00.OTDOACellInformationItemChoiceCPLength:
		{
			f := s.Begin()
			s.Bool(v.CPLength == nil)
			if v.CPLength != nil {
				s02.BridgeCompareLPPaCPLength(v.CPLength, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfDlFrames:
		{
			f := s.Begin()
			s.Bool(v.NumberOfDlFrames == nil)
			if v.NumberOfDlFrames != nil {
				s02.BridgeCompareLPPaNumberOfDlFrames(v.NumberOfDlFrames, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts:
		{
			f := s.Begin()
			s.Bool(v.NumberOfAntennaPorts == nil)
			if v.NumberOfAntennaPorts != nil {
				s02.BridgeCompareLPPaNumberOfAntennaPorts(v.NumberOfAntennaPorts, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceSFNInitialisationTime:
		{
			f := s.Begin()
			s.Bool(v.SFNInitialisationTime == nil)
			if v.SFNInitialisationTime != nil {
				s03.BridgeCompareLPPaSFNInitialisationTime(v.SFNInitialisationTime, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition:
		{
			f := s.Begin()
			s.Bool(v.EUTRANAccessPointPosition == nil)
			if v.EUTRANAccessPointPosition != nil {
				s06.BridgeCompareLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoicePRSMutingConfiguration:
		{
			f := s.Begin()
			s.Bool(v.PRSMutingConfiguration == nil)
			if v.PRSMutingConfiguration != nil {
				s08.BridgeCompareLPPaPRSMutingConfiguration(v.PRSMutingConfiguration, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoicePrsid:
		s02.BridgeCompareLPPaPRSID(&v.Prsid, s)
	case s00.OTDOACellInformationItemChoiceTpid:
		s03.BridgeCompareLPPaTPID(&v.Tpid, s)
	case s00.OTDOACellInformationItemChoiceTpType:
		{
			f := s.Begin()
			s.Bool(v.TpType == nil)
			if v.TpType != nil {
				s03.BridgeCompareLPPaTPType(v.TpType, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended:
		s02.BridgeCompareLPPaNumberOfDlFramesExtended(&v.NumberOfDlFramesExtended, s)
	case s00.OTDOACellInformationItemChoiceCrsCPlength:
		{
			f := s.Begin()
			s.Bool(v.CrsCPlength == nil)
			if v.CrsCPlength != nil {
				s02.BridgeCompareLPPaCPLength(v.CrsCPlength, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration:
		s10.BridgeCompareLPPaMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, s)
	case s00.OTDOACellInformationItemChoiceNPRSConfiguration:
		{
			f := s.Begin()
			s.Bool(v.NPRSConfiguration == nil)
			if v.NPRSConfiguration != nil {
				s07.BridgeCompareLPPaNPRSConfiguration(v.NPRSConfiguration, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN:
		{
			f := s.Begin()
			s.Bool(v.OffsetNBChanneltoEARFCN == nil)
			if v.OffsetNBChanneltoEARFCN != nil {
				s02.BridgeCompareLPPaOffsetNBChanneltoEARFCN(v.OffsetNBChanneltoEARFCN, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceOperationModeInfo:
		{
			f := s.Begin()
			s.Bool(v.OperationModeInfo == nil)
			if v.OperationModeInfo != nil {
				s02.BridgeCompareLPPaOperationModeInfo(v.OperationModeInfo, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceNPRSID:
		{
			f := s.Begin()
			s.BigInt(v.NPRSID)
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceDLBandwidth:
		{
			f := s.Begin()
			s.Bool(v.DLBandwidth == nil)
			if v.DLBandwidth != nil {
				s02.BridgeCompareLPPaDLBandwidth(v.DLBandwidth, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoicePRSOccasionGroup:
		{
			f := s.Begin()
			s.Bool(v.PRSOccasionGroup == nil)
			if v.PRSOccasionGroup != nil {
				s02.BridgeCompareLPPaPRSOccasionGroup(v.PRSOccasionGroup, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig:
		{
			f := s.Begin()
			s.Bool(v.PRSFreqHoppingConfig == nil)
			if v.PRSFreqHoppingConfig != nil {
				s08.BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB:
		{
			f := s.Begin()
			s.Bool(v.RepetitionNumberofSIB1NB == nil)
			if v.RepetitionNumberofSIB1NB != nil {
				s03.BridgeCompareLPPaRepetitionNumberofSIB1NB(v.RepetitionNumberofSIB1NB, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceNPRSSequenceInfo:
		s02.BridgeCompareLPPaNPRSSequenceInfo(&v.NPRSSequenceInfo, s)
	case s00.OTDOACellInformationItemChoiceNPRSType2:
		{
			f := s.Begin()
			s.Bool(v.NPRSType2 == nil)
			if v.NPRSType2 != nil {
				s07.BridgeCompareLPPaNPRSConfiguration(v.NPRSType2, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.OTDOACellInformationItemChoiceTddConfiguration:
		{
			f := s.Begin()
			s.Bool(v.TddConfiguration == nil)
			if v.TddConfiguration != nil {
				BridgeCompareLPPaTDDConfiguration(v.TddConfiguration, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaTDDConfiguration(v *TDDConfiguration, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaTDDConfiguration(v *TDDConfiguration, s *aper.SemanticComparison) {
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
	return AddOTDOACellsElemValueCodec{path: "AddOTDOACellsElem", decode: func(data []byte, options aper.DecodeState) (AddOTDOACellsElem, error) {
		var value AddOTDOACellsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AddOTDOACellsElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AddOTDOACellsElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AddOTDOACellsElem, options aper.DecodeState) (AddOTDOACellsElem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaAddOTDOACellsElem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v AddOTDOACellsElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAddOTDOACellsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACellsElem"
		return sealed
	}(),
	}
}

// OTDOACellInformationItemCodec binds the complete source value type.
func OTDOACellInformationItemCodec() OTDOACellInformationItemValueCodec {
	return OTDOACellInformationItemValueCodec{path: "OTDOACellInformationItem", decode: func(data []byte, options aper.DecodeState) (OTDOACellInformationItem, error) {
		var value OTDOACellInformationItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return OTDOACellInformationItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value OTDOACellInformationItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v OTDOACellInformationItem, options aper.DecodeState) (OTDOACellInformationItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaOTDOACellInformationItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OTDOACellInformationItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaOTDOACellInformationItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellInformationItem"
		return sealed
	}(),
	}
}

// TDDConfigurationCodec binds the complete source value type.
func TDDConfigurationCodec() TDDConfigurationValueCodec {
	return TDDConfigurationValueCodec{path: "TDDConfiguration", decode: func(data []byte, options aper.DecodeState) (TDDConfiguration, error) {
		var value TDDConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TDDConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TDDConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TDDConfiguration, options aper.DecodeState) (TDDConfiguration, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureLPPaTDDConfiguration(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,
			false,
		)
		return v, root
	}, compare: func(v TDDConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaTDDConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TDDConfiguration"
		return sealed
	}(),
	}
}
func BridgeAddOTDOACellInformationAPERValueFieldContext(v *AddOTDOACellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellInformationAPERValueFieldReceived(v *AddOTDOACellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellInformationAPERValueFieldReplay(v *AddOTDOACellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellInformationAPERValueFieldWithoutReplay(v *AddOTDOACellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellInformationValueCodecFieldCapture(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, aper.DecodeState) (AddOTDOACellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellInformationValueCodecFieldCompare(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellInformationValueCodecFieldContext(v *AddOTDOACellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellInformationValueCodecFieldDecode(v *AddOTDOACellInformationValueCodec) *func([]byte, aper.DecodeState) (AddOTDOACellInformation, error) {
	return &v.decode
}
func BridgeAddOTDOACellInformationValueCodecFieldEncode(v *AddOTDOACellInformationValueCodec) *func(AddOTDOACellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellInformationValueCodecFieldPath(v *AddOTDOACellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeAddOTDOACellInformationValueCodecMethodEncodeBudget(v AddOTDOACellInformationValueCodec, a0 AddOTDOACellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellInformationValueCodecMethodEncodeChanged(v AddOTDOACellInformationValueCodec, a0 AddOTDOACellInformation, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAddOTDOACellsAPERValueFieldContext(v *AddOTDOACellsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsAPERValueFieldReceived(v *AddOTDOACellsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsAPERValueFieldReplay(v *AddOTDOACellsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsAPERValueFieldWithoutReplay(v *AddOTDOACellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsElemAPERValueFieldContext(v *AddOTDOACellsElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsElemAPERValueFieldReceived(v *AddOTDOACellsElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsElemAPERValueFieldReplay(v *AddOTDOACellsElemAPERValue) *aper.Snapshot {
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
func BridgeAddOTDOACellsElemFieldExtOrigin(v *AddOTDOACellsElem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAddOTDOACellsElemFieldExtPresent(v *AddOTDOACellsElem) *[]bool       { return &v.extPresent }
func BridgeAddOTDOACellsElemFieldExtWire(v *AddOTDOACellsElem) *[]aper.WireSpan { return &v.extWire }
func BridgeAddOTDOACellsElemFieldIEExtensionsIndef(v *AddOTDOACellsElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAddOTDOACellsElemFieldPerExtPadding(v *AddOTDOACellsElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAddOTDOACellsElemFieldPerPadding(v *AddOTDOACellsElem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAddOTDOACellsElemFieldReceived(v *AddOTDOACellsElem) *bool { return &v.received }
func BridgeAddOTDOACellsElemFieldReceivedBytes(v *AddOTDOACellsElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellsElemFieldReplay(v *AddOTDOACellsElem) *aper.Snapshot { return &v.replay }
func BridgeAddOTDOACellsElemFieldStream(v *AddOTDOACellsElem) *aper.WireSpan { return &v.stream }
func BridgeAddOTDOACellsElemFieldWithoutReplay(v *AddOTDOACellsElem) *bool   { return &v.withoutReplay }
func BridgeAddOTDOACellsElemMethodMarshalAPERBudget(v *AddOTDOACellsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERChanged(v *AddOTDOACellsElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERChangedValue(v *AddOTDOACellsElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERFreshValue(v *AddOTDOACellsElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERLegacy(v *AddOTDOACellsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellsElemMethodMarshalAPERPlanned(v *AddOTDOACellsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellsElemMethodMarshalAPERTo(v *AddOTDOACellsElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERFrom(v *AddOTDOACellsElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERLegacy(v *AddOTDOACellsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellsElemMethodUnmarshalAPERWithOptions(v *AddOTDOACellsElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAddOTDOACellsElemValueCodecFieldCapture(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, aper.DecodeState) (AddOTDOACellsElem, aper.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellsElemValueCodecFieldCompare(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellsElemValueCodecFieldContext(v *AddOTDOACellsElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsElemValueCodecFieldDecode(v *AddOTDOACellsElemValueCodec) *func([]byte, aper.DecodeState) (AddOTDOACellsElem, error) {
	return &v.decode
}
func BridgeAddOTDOACellsElemValueCodecFieldEncode(v *AddOTDOACellsElemValueCodec) *func(AddOTDOACellsElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellsElemValueCodecFieldPath(v *AddOTDOACellsElemValueCodec) *aper.Path {
	return &v.path
}
func BridgeAddOTDOACellsElemValueCodecMethodEncodeBudget(v AddOTDOACellsElemValueCodec, a0 AddOTDOACellsElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellsElemValueCodecMethodEncodeChanged(v AddOTDOACellsElemValueCodec, a0 AddOTDOACellsElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAddOTDOACellsValueCodecFieldCapture(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, aper.DecodeState) (AddOTDOACells, aper.Snapshot) {
	return &v.capture
}
func BridgeAddOTDOACellsValueCodecFieldCompare(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAddOTDOACellsValueCodecFieldContext(v *AddOTDOACellsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAddOTDOACellsValueCodecFieldDecode(v *AddOTDOACellsValueCodec) *func([]byte, aper.DecodeState) (AddOTDOACells, error) {
	return &v.decode
}
func BridgeAddOTDOACellsValueCodecFieldEncode(v *AddOTDOACellsValueCodec) *func(AddOTDOACells, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAddOTDOACellsValueCodecFieldPath(v *AddOTDOACellsValueCodec) *aper.Path { return &v.path }
func BridgeAddOTDOACellsValueCodecMethodEncodeBudget(v AddOTDOACellsValueCodec, a0 AddOTDOACells, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAddOTDOACellsValueCodecMethodEncodeChanged(v AddOTDOACellsValueCodec, a0 AddOTDOACells, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationControlAPERValueFieldContext(v *AssistanceInformationControlAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlAPERValueFieldReceived(v *AssistanceInformationControlAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationControlAPERValueFieldReplay(v *AssistanceInformationControlAPERValue) *aper.Snapshot {
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
func BridgeAssistanceInformationControlFieldExtOrigin(v *AssistanceInformationControl) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationControlFieldExtPresent(v *AssistanceInformationControl) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationControlFieldExtWire(v *AssistanceInformationControl) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationControlFieldPerExtPadding(v *AssistanceInformationControl) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationControlFieldPerPadding(v *AssistanceInformationControl) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationControlFieldProtocolIEsIndef(v *AssistanceInformationControl) *bool {
	return &v.protocolIEsIndef
}
func BridgeAssistanceInformationControlFieldReceived(v *AssistanceInformationControl) *bool {
	return &v.received
}
func BridgeAssistanceInformationControlFieldReceivedBytes(v *AssistanceInformationControl) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationControlFieldReplay(v *AssistanceInformationControl) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlFieldStream(v *AssistanceInformationControl) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationControlFieldWithoutReplay(v *AssistanceInformationControl) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlMethodMarshalAPERBudget(v *AssistanceInformationControl, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERChanged(v *AssistanceInformationControl, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationControlMethodMarshalAPERChangedValue(v *AssistanceInformationControl, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationControlMethodMarshalAPERFreshValue(v *AssistanceInformationControl, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERLegacy(v *AssistanceInformationControl) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationControlMethodMarshalAPERPlanned(v *AssistanceInformationControl, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationControlMethodMarshalAPERTo(v *AssistanceInformationControl, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERFrom(v *AssistanceInformationControl, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERLegacy(v *AssistanceInformationControl, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationControlMethodUnmarshalAPERWithOptions(v *AssistanceInformationControl, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationControlValueCodecFieldCapture(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, aper.DecodeState) (AssistanceInformationControl, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationControlValueCodecFieldCompare(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationControlValueCodecFieldContext(v *AssistanceInformationControlValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlValueCodecFieldDecode(v *AssistanceInformationControlValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformationControl, error) {
	return &v.decode
}
func BridgeAssistanceInformationControlValueCodecFieldEncode(v *AssistanceInformationControlValueCodec) *func(AssistanceInformationControl, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationControlValueCodecFieldPath(v *AssistanceInformationControlValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationControlValueCodecMethodEncodeBudget(v AssistanceInformationControlValueCodec, a0 AssistanceInformationControl, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationControlValueCodecMethodEncodeChanged(v AssistanceInformationControlValueCodec, a0 AssistanceInformationControl, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellInformationAPERValueFieldContext(v *OTDOACellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationAPERValueFieldReceived(v *OTDOACellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOACellInformationAPERValueFieldReplay(v *OTDOACellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationAPERValueFieldWithoutReplay(v *OTDOACellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemAPERValueFieldContext(v *OTDOACellInformationItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationItemAPERValueFieldReceived(v *OTDOACellInformationItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOACellInformationItemAPERValueFieldReplay(v *OTDOACellInformationItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationItemAPERValueFieldWithoutReplay(v *OTDOACellInformationItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemFieldKnownOpenBytes(v *OTDOACellInformationItem) *uint64 {
	return &v.knownOpenBytes
}
func BridgeOTDOACellInformationItemFieldPerOpenTypePadding(v *OTDOACellInformationItem) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeOTDOACellInformationItemFieldPerPadding(v *OTDOACellInformationItem) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellInformationItemFieldReceived(v *OTDOACellInformationItem) *bool {
	return &v.received
}
func BridgeOTDOACellInformationItemFieldReceivedBytes(v *OTDOACellInformationItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellInformationItemFieldReplay(v *OTDOACellInformationItem) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationItemFieldStream(v *OTDOACellInformationItem) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOACellInformationItemFieldWithoutReplay(v *OTDOACellInformationItem) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationItemMethodMarshalAPERBudget(v *OTDOACellInformationItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERChanged(v *OTDOACellInformationItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERChangedValue(v *OTDOACellInformationItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERFreshValue(v *OTDOACellInformationItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERLegacy(v *OTDOACellInformationItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellInformationItemMethodMarshalAPERPlanned(v *OTDOACellInformationItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellInformationItemMethodMarshalAPERTo(v *OTDOACellInformationItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(v *OTDOACellInformationItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERLegacy(v *OTDOACellInformationItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellInformationItemMethodUnmarshalAPERWithOptions(v *OTDOACellInformationItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellInformationItemValueCodecFieldCapture(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, aper.DecodeState) (OTDOACellInformationItem, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellInformationItemValueCodecFieldCompare(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellInformationItemValueCodecFieldContext(v *OTDOACellInformationItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationItemValueCodecFieldDecode(v *OTDOACellInformationItemValueCodec) *func([]byte, aper.DecodeState) (OTDOACellInformationItem, error) {
	return &v.decode
}
func BridgeOTDOACellInformationItemValueCodecFieldEncode(v *OTDOACellInformationItemValueCodec) *func(OTDOACellInformationItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellInformationItemValueCodecFieldPath(v *OTDOACellInformationItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOACellInformationItemValueCodecMethodEncodeBudget(v OTDOACellInformationItemValueCodec, a0 OTDOACellInformationItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellInformationItemValueCodecMethodEncodeChanged(v OTDOACellInformationItemValueCodec, a0 OTDOACellInformationItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellInformationValueCodecFieldCapture(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, aper.DecodeState) (OTDOACellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellInformationValueCodecFieldCompare(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellInformationValueCodecFieldContext(v *OTDOACellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellInformationValueCodecFieldDecode(v *OTDOACellInformationValueCodec) *func([]byte, aper.DecodeState) (OTDOACellInformation, error) {
	return &v.decode
}
func BridgeOTDOACellInformationValueCodecFieldEncode(v *OTDOACellInformationValueCodec) *func(OTDOACellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellInformationValueCodecFieldPath(v *OTDOACellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOACellInformationValueCodecMethodEncodeBudget(v OTDOACellInformationValueCodec, a0 OTDOACellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellInformationValueCodecMethodEncodeChanged(v OTDOACellInformationValueCodec, a0 OTDOACellInformation, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTDDConfigurationAPERValueFieldContext(v *TDDConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTDDConfigurationAPERValueFieldReceived(v *TDDConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTDDConfigurationAPERValueFieldReplay(v *TDDConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTDDConfigurationAPERValueFieldWithoutReplay(v *TDDConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTDDConfigurationFieldExtCount(v *TDDConfiguration) *int64   { return &v.extCount }
func BridgeTDDConfigurationFieldExtData(v *TDDConfiguration) *[][]byte { return &v.extData }
func BridgeTDDConfigurationFieldExtOrigin(v *TDDConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTDDConfigurationFieldExtPresent(v *TDDConfiguration) *[]bool       { return &v.extPresent }
func BridgeTDDConfigurationFieldExtWire(v *TDDConfiguration) *[]aper.WireSpan { return &v.extWire }
func BridgeTDDConfigurationFieldIEExtensionsIndef(v *TDDConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTDDConfigurationFieldPerExtPadding(v *TDDConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTDDConfigurationFieldPerPadding(v *TDDConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTDDConfigurationFieldReceived(v *TDDConfiguration) *bool { return &v.received }
func BridgeTDDConfigurationFieldReceivedBytes(v *TDDConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTDDConfigurationFieldReplay(v *TDDConfiguration) *aper.Snapshot { return &v.replay }
func BridgeTDDConfigurationFieldStream(v *TDDConfiguration) *aper.WireSpan { return &v.stream }
func BridgeTDDConfigurationFieldWithoutReplay(v *TDDConfiguration) *bool   { return &v.withoutReplay }
func BridgeTDDConfigurationMethodMarshalAPERBudget(v *TDDConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERChanged(v *TDDConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTDDConfigurationMethodMarshalAPERChangedValue(v *TDDConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTDDConfigurationMethodMarshalAPERFreshValue(v *TDDConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERLegacy(v *TDDConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTDDConfigurationMethodMarshalAPERPlanned(v *TDDConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeTDDConfigurationMethodMarshalAPERTo(v *TDDConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTDDConfigurationMethodUnmarshalAPERFrom(v *TDDConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTDDConfigurationMethodUnmarshalAPERLegacy(v *TDDConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTDDConfigurationMethodUnmarshalAPERWithOptions(v *TDDConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTDDConfigurationValueCodecFieldCapture(v *TDDConfigurationValueCodec) *func(TDDConfiguration, aper.DecodeState) (TDDConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeTDDConfigurationValueCodecFieldCompare(v *TDDConfigurationValueCodec) *func(TDDConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeTDDConfigurationValueCodecFieldContext(v *TDDConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTDDConfigurationValueCodecFieldDecode(v *TDDConfigurationValueCodec) *func([]byte, aper.DecodeState) (TDDConfiguration, error) {
	return &v.decode
}
func BridgeTDDConfigurationValueCodecFieldEncode(v *TDDConfigurationValueCodec) *func(TDDConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTDDConfigurationValueCodecFieldPath(v *TDDConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTDDConfigurationValueCodecMethodEncodeBudget(v TDDConfigurationValueCodec, a0 TDDConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTDDConfigurationValueCodecMethodEncodeChanged(v TDDConfigurationValueCodec, a0 TDDConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
