// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s05 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s05

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/bits"
)

func BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.MeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticComparison) {
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
			s04.BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.NRCGIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.NRCGIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.OTDOACellsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.OTDOACellsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.OTDOAInformationTypeItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.OTDOAInformationTypeItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionContainer(v *s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.PosSIBSegmentsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.PosSIBSegmentsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.PosSIBsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.PosSIBsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// AssistanceInformationFailureListValueCodec is the concrete ValueCodec[AssistanceInformationFailureList].
type AssistanceInformationFailureListValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformationFailureList, aper.DecodeState,

	) (AssistanceInformationFailureList, aper.Snapshot,

	)
	compare func(AssistanceInformationFailureList, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformationFailureList,

		error)
	encode func(AssistanceInformationFailureList,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationFailureListValueCodec) New(value AssistanceInformationFailureList,

) (AssistanceInformationFailureListAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFailureListAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationFailureListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFailureListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationFailureListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationFailureListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationFailureListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFailureListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationFailureListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFailureListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFailureListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationFailureListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationFailureListValueCodec) EncodeAPER(value AssistanceInformationFailureListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationFailureListValueCodec) encodeBudget(value AssistanceInformationFailureList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFailureListValueCodec) encodeChanged(value AssistanceInformationFailureList,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec struct {
	context s00.BridgeCodecContext
	capture func(Cause, aper.DecodeState,

	) (Cause, aper.Snapshot,

	)
	compare func(Cause, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (Cause,

		error)
	encode func(Cause,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c CauseValueCodec) New(value Cause,

) (CauseAPERValue, error) {
	if c.encode == nil {
		return CauseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return CauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c CauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CauseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return CauseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CauseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return CauseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return CauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c CauseValueCodec) EncodeAPER(value CauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CauseValueCodec) encodeBudget(value Cause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CauseValueCodec) encodeChanged(value Cause,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AssistanceInformationFailureListElemValueCodec is the concrete ValueCodec[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformationFailureListElem, aper.DecodeState,

	) (AssistanceInformationFailureListElem, aper.Snapshot,

	)
	compare func(AssistanceInformationFailureListElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformationFailureListElem,

		error)
	encode func(AssistanceInformationFailureListElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationFailureListElemValueCodec) New(value AssistanceInformationFailureListElem,

) (AssistanceInformationFailureListElemAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFailureListElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationFailureListElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationFailureListElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationFailureListElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFailureListElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationFailureListElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFailureListElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationFailureListElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationFailureListElemValueCodec) EncodeAPER(value AssistanceInformationFailureListElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationFailureListElemValueCodec) encodeBudget(value AssistanceInformationFailureListElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFailureListElemValueCodec) encodeChanged(value AssistanceInformationFailureListElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AssistanceInformationMetaDataValueCodec is the concrete ValueCodec[AssistanceInformationMetaData].
type AssistanceInformationMetaDataValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformationMetaData, aper.DecodeState,

	) (AssistanceInformationMetaData, aper.Snapshot,

	)
	compare func(AssistanceInformationMetaData, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformationMetaData,

		error)
	encode func(AssistanceInformationMetaData,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationMetaDataValueCodec) New(value AssistanceInformationMetaData,

) (AssistanceInformationMetaDataAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationMetaDataAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationMetaDataAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationMetaDataAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationMetaDataAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationMetaDataValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationMetaDataAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationMetaDataAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationMetaDataAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationMetaDataAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationMetaDataAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationMetaDataAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationMetaDataValueCodec) EncodeAPER(value AssistanceInformationMetaDataAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationMetaDataValueCodec) encodeBudget(value AssistanceInformationMetaData,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationMetaDataValueCodec) encodeChanged(value AssistanceInformationMetaData,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// BitmapsforNPRSValueCodec is the concrete ValueCodec[BitmapsforNPRS].
type BitmapsforNPRSValueCodec struct {
	context s00.BridgeCodecContext
	capture func(BitmapsforNPRS, aper.DecodeState,

	) (BitmapsforNPRS, aper.Snapshot,

	)
	compare func(BitmapsforNPRS, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (BitmapsforNPRS,

		error)
	encode func(BitmapsforNPRS,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c BitmapsforNPRSValueCodec) New(value BitmapsforNPRS,

) (BitmapsforNPRSAPERValue, error) {
	if c.encode == nil {
		return BitmapsforNPRSAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BitmapsforNPRSAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BitmapsforNPRSAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return BitmapsforNPRSAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c BitmapsforNPRSValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BitmapsforNPRSAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BitmapsforNPRSAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return BitmapsforNPRSAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BitmapsforNPRSAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return BitmapsforNPRSAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return BitmapsforNPRSAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c BitmapsforNPRSValueCodec) EncodeAPER(value BitmapsforNPRSAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BitmapsforNPRSValueCodec) encodeBudget(value BitmapsforNPRS,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BitmapsforNPRSValueCodec) encodeChanged(value BitmapsforNPRS,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec struct {
	context s00.BridgeCodecContext
	capture func(CriticalityDiagnosticsIEList, aper.DecodeState,

	) (CriticalityDiagnosticsIEList, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList,

		error)
	encode func(CriticalityDiagnosticsIEList,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c CriticalityDiagnosticsIEListValueCodec) New(value CriticalityDiagnosticsIEList,

) (CriticalityDiagnosticsIEListAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c CriticalityDiagnosticsIEListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return CriticalityDiagnosticsIEListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c CriticalityDiagnosticsIEListValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListValueCodec) encodeBudget(value CriticalityDiagnosticsIEList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsIEListValueCodec) encodeChanged(value CriticalityDiagnosticsIEList,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListElemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(CriticalityDiagnosticsIEListElem, aper.DecodeState,

	) (CriticalityDiagnosticsIEListElem, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEListElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEListElem,

		error)
	encode func(CriticalityDiagnosticsIEListElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c CriticalityDiagnosticsIEListElemValueCodec) New(value CriticalityDiagnosticsIEListElem,

) (CriticalityDiagnosticsIEListElemAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsIEListElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c CriticalityDiagnosticsIEListElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return CriticalityDiagnosticsIEListElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsIEListElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c CriticalityDiagnosticsIEListElemValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListElemValueCodec) encodeBudget(value CriticalityDiagnosticsIEListElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsIEListElemValueCodec) encodeChanged(value CriticalityDiagnosticsIEListElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECGIValueCodec is the concrete ValueCodec[ECGI].
type ECGIValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECGI, aper.DecodeState,

	) (ECGI, aper.Snapshot,

	)
	compare func(ECGI, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECGI,

		error)
	encode func(ECGI,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECGIValueCodec) New(value ECGI,

) (ECGIAPERValue, error) {
	if c.encode == nil {
		return ECGIAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECGIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECGIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECGIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECGIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECGIValueCodec) EncodeAPER(value ECGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECGIValueCodec) encodeBudget(value ECGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECGIValueCodec) encodeChanged(value ECGI,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// measurementQuantitiesValueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.MeasurementQuantitiesValueExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.MeasurementQuantitiesValueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// nRCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRCGIExtIEsValue].
type NRCGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.NRCGIExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.NRCGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.NRCGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeNRCGIExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeNRCGIExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeNRCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeNRCGIExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s04.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionField(v *s04.NRCGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeNRCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s04.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}

// oTDOACellsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.OTDOACellsExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.OTDOACellsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.OTDOACellsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeOTDOACellsExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeOTDOACellsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeOTDOACellsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeOTDOACellsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeOTDOACellsExtIEsExtFieldFieldReplay(v), *s04.BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(v *s04.OTDOACellsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeOTDOACellsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeOTDOACellsExtIEsExtFieldFieldReplay(v), *s04.BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}

// oTDOAInformationTypeItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.OTDOAInformationTypeItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.OTDOAInformationTypeItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.OTDOAInformationTypeItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v), *s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionField(v *s04.OTDOAInformationTypeItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgeOTDOAInformationTypeItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v), *s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v))
}

// pRSFrequencyHoppingConfigurationItemIEsValueProtocolOpenValue is the concrete protocolOpenValue[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.PRSFrequencyHoppingConfigurationItemIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.PRSFrequencyHoppingConfigurationItemIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionField(v *s04.PRSFrequencyHoppingConfigurationItemIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v), *s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v))
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionField(v *s04.PRSFrequencyHoppingConfigurationItemIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v), *s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v))
}

// posSIBSegmentsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s02.PosSIBSegmentsExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s02.PosSIBSegmentsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.PosSIBSegmentsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgePosSIBSegmentsExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s02.BridgePosSIBSegmentsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s02.BridgePosSIBSegmentsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s02.BridgePosSIBSegmentsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v), *s04.BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionField(v *s04.PosSIBSegmentsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s02.BridgePosSIBSegmentsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v), *s04.BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v))
}

// posSIBsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PosSIBsExtIEsValue].
type PosSIBsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.PosSIBsExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.PosSIBsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.PosSIBsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgePosSIBsExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgePosSIBsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgePosSIBsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgePosSIBsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgePosSIBsExtIEsExtFieldFieldReplay(v), *s04.BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionField(v *s04.PosSIBsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgePosSIBsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgePosSIBsExtIEsExtFieldFieldReplay(v), *s04.BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v))
}

// AssistanceInformationFailureListAPERValue is the concrete APERValue[AssistanceInformationFailureList].
type AssistanceInformationFailureListAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformationFailureList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationFailureListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFailureListAPERValue) WithoutReplay() AssistanceInformationFailureListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   Cause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v CauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CauseAPERValue) WithoutReplay() CauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationFailureListElemAPERValue is the concrete APERValue[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformationFailureListElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationFailureListElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFailureListElemAPERValue) WithoutReplay() AssistanceInformationFailureListElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationMetaDataAPERValue is the concrete APERValue[AssistanceInformationMetaData].
type AssistanceInformationMetaDataAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformationMetaData

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationMetaDataAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationMetaDataAPERValue) WithoutReplay() AssistanceInformationMetaDataAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BitmapsforNPRSAPERValue is the concrete APERValue[BitmapsforNPRS].
type BitmapsforNPRSAPERValue struct {
	context s00.BridgeCodecContext
	Value   BitmapsforNPRS

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v BitmapsforNPRSAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v BitmapsforNPRSAPERValue) WithoutReplay() BitmapsforNPRSAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v CriticalityDiagnosticsIEListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsIEListAPERValue) WithoutReplay() CriticalityDiagnosticsIEListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListElemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEListElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v CriticalityDiagnosticsIEListElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsIEListElemAPERValue) WithoutReplay() CriticalityDiagnosticsIEListElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECGIAPERValue is the concrete APERValue[ECGI].
type ECGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECGIAPERValue) WithoutReplay() ECGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type AssistanceInformationFailureList = []AssistanceInformationFailureListElem

// AssistanceInformationMetaData represents the ASN.1 type AssistanceInformationMetaData (SEQUENCE).
type AssistanceInformationMetaData struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	Encrypted         *int64                                              `asn1:"tag:0,context,implicit,optional" json:"Encrypted,omitempty"`
	GNSSID            *int64                                              `asn1:"tag:1,context,implicit,optional" json:"GNSSID,omitempty"`
	SBASID            *int64                                              `asn1:"tag:2,context,implicit,optional" json:"SBASID,omitempty"`
	IEExtensions      s03.AssistanceInformationMetaDataExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                `asn1:"-" json:"-"`
	extCount          int64                                               `asn1:"-" json:"-"`
	extPresent        []bool                                              `asn1:"-" json:"-"`
	extData           [][]byte                                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// BitmapsforNPRS represents the ASN.1 CHOICE type BitmapsforNPRS.
type BitmapsforNPRS struct {
	knownOpenBytes     uint64
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Ten                *runtime.BitString    `json:"Ten,omitempty"`
	Forty              *runtime.BitString    `json:"Forty,omitempty"`
	TenTdd             *runtime.BitString    `json:"TenTdd,omitempty"`
	FortyTdd           *runtime.BitString    `json:"FortyTdd,omitempty"`
}

// Cause represents the ASN.1 CHOICE type Cause.
type Cause struct {
	knownOpenBytes     uint64
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding   `json:"-"`
	perOpenTypePadding aper.CompletePadding   `json:"-"`
	UnknownExtension   *aper.ChoiceExtension  `json:"UnknownExtension,omitempty"`
	RadioNetwork       *s00.CauseRadioNetwork `json:"RadioNetwork,omitempty"`
	Protocol           *s00.CauseProtocol     `json:"Protocol,omitempty"`
	Misc               *s00.CauseMisc         `json:"Misc,omitempty"`
}
type CriticalityDiagnosticsIEList = []CriticalityDiagnosticsIEListElem

// ECGI represents the ASN.1 type ECGI (SEQUENCE).
type ECGI struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        aper.WireSpan
	PLMNIdentity         s00.PLMNIdentity           `asn1:"tag:0,context,implicit"`
	EUTRANcellIdentifier s00.EUTRANCellIdentifier   `asn1:"tag:1,context,implicit"`
	IEExtensions         s03.ECGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                       `asn1:"-" json:"-"`
	extCount             int64                      `asn1:"-" json:"-"`
	extPresent           []bool                     `asn1:"-" json:"-"`
	extData              [][]byte                   `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding     `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// AssistanceInformationFailureListElem represents the ASN.1 type AssistanceInformationFailureList-Elem (SEQUENCE).
type AssistanceInformationFailureListElem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	PosSIBType        s00.PosSIBType                                         `asn1:"tag:0,context,implicit"`
	Outcome           s00.Outcome                                            `asn1:"tag:1,context,implicit"`
	IEExtensions      s03.AssistanceInformationFailureListExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                   `asn1:"-" json:"-"`
	extCount          int64                                                  `asn1:"-" json:"-"`
	extPresent        []bool                                                 `asn1:"-" json:"-"`
	extData           [][]byte                                               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// CriticalityDiagnosticsIEListElem represents the ASN.1 type CriticalityDiagnostics-IE-List-Elem (SEQUENCE).
type CriticalityDiagnosticsIEListElem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	IECriticality     s00.Criticality                                    `asn1:"tag:0,context,implicit"`
	IEID              s00.ProtocolIEID                                   `asn1:"tag:1,context,implicit"`
	TypeOfError       s00.TypeOfError                                    `asn1:"tag:2,context,implicit"`
	IEExtensions      s03.CriticalityDiagnosticsIEListExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes AssistanceInformationMetaData to APER format.
func (v *AssistanceInformationMetaData) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationMetaData) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeBoolean(bb, v.Encrypted != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.GNSSID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SBASID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.Encrypted != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Encrypted), 1, true); err != nil {
			return fmt.Errorf("encoding encrypted: %w", err)
		}
	}
	if v.GNSSID != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.GNSSID), 6, true); err != nil {
			return fmt.Errorf("encoding gNSSID: %w", err)
		}
	}
	if v.SBASID != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.SBASID), 4, true); err != nil {
			return fmt.Errorf("encoding sBASID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformationMetaData from APER format.
func (v *AssistanceInformationMetaData) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationMetaData with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationMetaData) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformationMetaData")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationMetaData) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaData{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_encrypted, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_gnssid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sbasid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_encrypted {
		val_encrypted, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Encrypted"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Encrypted")
		}
		if err := aper.ChargeValue(bb, val_encrypted); err != nil {
			return err
		}
		v.Encrypted = (*int64)(bb.OwnInt64(int64(val_encrypted)))
	}
	if opt_gnssid {
		val_gnssid, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 1, Path: "GNSSID"})
		if err != nil {
			return runtime.WrapDecodePath(err, "GNSSID")
		}
		if err := aper.ChargeValue(bb, val_gnssid); err != nil {
			return err
		}
		v.GNSSID = (*int64)(bb.OwnInt64(int64(val_gnssid)))
	}
	if opt_sbasid {
		val_sbasid, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SBASID"})
		if err != nil {
			return runtime.WrapDecodePath(err, "SBASID")
		}
		if err := aper.ChargeValue(bb, val_sbasid); err != nil {
			return err
		}
		v.SBASID = (*int64)(bb.OwnInt64(int64(val_sbasid)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s03.AssistanceInformationMetaDataExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.AssistanceInformationMetaDataExtIEsExtField
				if err := s03.BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes BitmapsforNPRS to APER format.
func (v *BitmapsforNPRS) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *BitmapsforNPRS) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.replay.ReplayTo(v.stream, bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "BitmapsforNPRS:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "BitmapsforNPRS:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 2 {
			return fmt.Errorf("%s extension index %d is known to this schema", "BitmapsforNPRS:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "BitmapsforNPRS:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.BitmapsforNPRSChoiceTenTdd:
			if v.TenTdd == nil {
				return fmt.Errorf("choice alternative ten-tdd is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.TenTdd.Bytes, v.TenTdd.BitLength, 8, 8, true); err != nil {
				return fmt.Errorf("encoding ten-tdd: %w", err)
			}
		case s00.BitmapsforNPRSChoiceFortyTdd:
			if v.FortyTdd == nil {
				return fmt.Errorf("choice alternative forty-tdd is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.FortyTdd.Bytes, v.FortyTdd.BitLength, 32, 32, true); err != nil {
				return fmt.Errorf("encoding forty-tdd: %w", err)
			}
		default:
			return fmt.Errorf("unknown BitmapsforNPRS extension choice %d", v.Choice)
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
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.BitmapsforNPRSChoiceTen:
		if v.Ten == nil {
			return fmt.Errorf("choice alternative ten is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Ten.Bytes, v.Ten.BitLength, 10, 10, true); err != nil {
			return fmt.Errorf("encoding ten: %w", err)
		}
	case s00.BitmapsforNPRSChoiceForty:
		if v.Forty == nil {
			return fmt.Errorf("choice alternative forty is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Forty.Bytes, v.Forty.BitLength, 40, 40, true); err != nil {
			return fmt.Errorf("encoding forty: %w", err)
		}
	default:
		return fmt.Errorf("unknown BitmapsforNPRS choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BitmapsforNPRS from APER format.
func (v *BitmapsforNPRS) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BitmapsforNPRS with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BitmapsforNPRS) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	padding, err := aper.CaptureFinalBits(bb, "BitmapsforNPRS")
	if err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *BitmapsforNPRS) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BitmapsforNPRS{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 2)
		if extIdx < 2 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 2 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(2) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.BitmapsforNPRSChoiceTenTdd:
			extensionPath = "TenTdd"
			bsBytes_tentdd, bsBitLen_tentdd, err := aper.DecodeBitStringAligned(inner, 8, 8, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "TenTdd")
			}
			tmp_tentdd := runtime.BitString{Bytes: bsBytes_tentdd, BitLength: bsBitLen_tentdd}
			if err := aper.ChargeValue(inner, tmp_tentdd); err != nil {
				return err
			}
			v.TenTdd = &tmp_tentdd
		case s00.BitmapsforNPRSChoiceFortyTdd:
			extensionPath = "FortyTdd"
			bsBytes_fortytdd, bsBitLen_fortytdd, err := aper.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "FortyTdd")
			}
			tmp_fortytdd := runtime.BitString{Bytes: bsBytes_fortytdd, BitLength: bsBitLen_fortytdd}
			if err := aper.ChargeValue(inner, tmp_fortytdd); err != nil {
				return err
			}
			v.FortyTdd = &tmp_fortytdd
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.BitmapsforNPRSChoiceTen:
		bsBytes_ten, bsBitLen_ten, err := aper.DecodeBitStringAligned(bb, 10, 10, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Ten")
		}
		tmp_ten := runtime.BitString{Bytes: bsBytes_ten, BitLength: bsBitLen_ten}
		if err := aper.ChargeValue(bb, tmp_ten); err != nil {
			return err
		}
		v.Ten = &tmp_ten
	case s00.BitmapsforNPRSChoiceForty:
		bsBytes_forty, bsBitLen_forty, err := aper.DecodeBitStringAligned(bb, 40, 40, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Forty")
		}
		tmp_forty := runtime.BitString{Bytes: bsBytes_forty, BitLength: bsBitLen_forty}
		if err := aper.ChargeValue(bb, tmp_forty); err != nil {
			return err
		}
		v.Forty = &tmp_forty
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes Cause to APER format.
func (v *Cause) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Cause) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.replay.ReplayTo(v.stream, bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "Cause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "Cause:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "Cause:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "Cause:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		if v.RadioNetwork == nil {
			return fmt.Errorf("choice alternative radioNetwork is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.RadioNetwork), 3, true); err != nil {
			return fmt.Errorf("encoding radioNetwork: %w", err)
		}
	case s00.CauseChoiceProtocol:
		if v.Protocol == nil {
			return fmt.Errorf("choice alternative protocol is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Protocol), 7, true); err != nil {
			return fmt.Errorf("encoding protocol: %w", err)
		}
	case s00.CauseChoiceMisc:
		if v.Misc == nil {
			return fmt.Errorf("choice alternative misc is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Misc), 1, true); err != nil {
			return fmt.Errorf("encoding misc: %w", err)
		}
	default:
		return fmt.Errorf("unknown Cause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Cause from APER format.
func (v *Cause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Cause with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Cause) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	padding, err := aper.CaptureFinalBits(bb, "Cause")
	if err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Cause) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cause{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		val_radionetwork, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RadioNetwork"})
		if err != nil {
			return runtime.WrapDecodePath(err, "RadioNetwork")
		}
		tmp_radionetwork := s00.CauseRadioNetwork(val_radionetwork)
		if err := aper.ChargeValue(bb, tmp_radionetwork); err != nil {
			return err
		}
		v.RadioNetwork = (*s00.CauseRadioNetwork)(bb.OwnInt64(int64(tmp_radionetwork)))
	case s00.CauseChoiceProtocol:
		val_protocol, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Protocol"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Protocol")
		}
		tmp_protocol := s00.CauseProtocol(val_protocol)
		if err := aper.ChargeValue(bb, tmp_protocol); err != nil {
			return err
		}
		v.Protocol = (*s00.CauseProtocol)(bb.OwnInt64(int64(tmp_protocol)))
	case s00.CauseChoiceMisc:
		val_misc, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Misc"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Misc")
		}
		tmp_misc := s00.CauseMisc(val_misc)
		if err := aper.ChargeValue(bb, tmp_misc); err != nil {
			return err
		}
		v.Misc = (*s00.CauseMisc)(bb.OwnInt64(int64(

			// MarshalAPER encodes CriticalityDiagnostics to APER format.
			tmp_misc)))
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes ECGI to APER format.
func (v *ECGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.EUTRANcellIdentifier.Bytes, v.EUTRANcellIdentifier.BitLength, 28, 28, true); err != nil {
		return fmt.Errorf("encoding eUTRANcellIdentifier: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeECGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECGI from APER format.
func (v *ECGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECGI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNIdentity(val_plmnidentity)
	bsBytes_eutrancellidentifier, bsBitLen_eutrancellidentifier, err := aper.DecodeBitStringAligned(bb, 28, 28, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANcellIdentifier")
	}
	v.EUTRANcellIdentifier = runtime.BitString{Bytes: bsBytes_eutrancellidentifier, BitLength: bsBitLen_eutrancellidentifier}
	if opt_ieextensions {
		tmp_ieextensions := make(s03.ECGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.ECGIExtIEsExtField
				if err := s03.BridgeECGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes AssistanceInformationFailureListElem to APER format.
func (v *AssistanceInformationFailureListElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationFailureListElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return fmt.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Outcome), 1, true); err != nil {
		return fmt.Errorf("encoding outcome: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeAssistanceInformationFailureListExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformationFailureListElem from APER format.
func (v *AssistanceInformationFailureListElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationFailureListElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationFailureListElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformationFailureListElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationFailureListElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListElem{}
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
	val_possibtype, err := aper.DecodeEnumeratedAligned(bb, 27, true, aper.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = s00.PosSIBType(val_possibtype)
	val_outcome, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Outcome"})
	if err != nil {
		return runtime.WrapDecodePath(err, "Outcome")
	}
	v.Outcome = s00.Outcome(val_outcome)
	if opt_ieextensions {
		tmp_ieextensions := make(s03.AssistanceInformationFailureListExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.AssistanceInformationFailureListExtIEsExtField
				if err := s03.BridgeAssistanceInformationFailureListExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes CriticalityDiagnosticsIEListElem to APER format.
func (v *CriticalityDiagnosticsIEListElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IECriticality), 3, false); err != nil {
		return fmt.Errorf("encoding iECriticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.IEID), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding iE-ID: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.TypeOfError), 2, true); err != nil {
		return fmt.Errorf("encoding typeOfError: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CriticalityDiagnosticsIEListElem from APER format.
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnosticsIEListElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEListElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListElem{}
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
	val_iecriticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "IECriticality"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IECriticality")
	}
	v.IECriticality = s00.Criticality(val_iecriticality)
	val_ieid, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "IEID")
	}
	v.IEID = s00.ProtocolIEID(val_ieid)
	val_typeoferror, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
	if err != nil {
		return runtime.WrapDecodePath(err, "TypeOfError")
	}
	v.TypeOfError = s00.TypeOfError(val_typeoferror)
	if opt_ieextensions {
		tmp_ieextensions := make(s03.CriticalityDiagnosticsIEListExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.CriticalityDiagnosticsIEListExtIEsExtField
				if err := s03.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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
func (v *AssistanceInformationFailureListElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFailureListElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFailureListElem) WithoutReplay() AssistanceInformationFailureListElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformationFailureListElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationMetaData) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationMetaData", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationMetaData) WithoutReplay() AssistanceInformationMetaData {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformationMetaData
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BitmapsforNPRS) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "BitmapsforNPRS", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BitmapsforNPRS) WithoutReplay() BitmapsforNPRS {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero BitmapsforNPRS
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cause) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "Cause", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cause) WithoutReplay() Cause {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero Cause
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEListElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEListElem) WithoutReplay() CriticalityDiagnosticsIEListElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero CriticalityDiagnosticsIEListElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "ECGI", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECGI) WithoutReplay() ECGI {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationFailureListElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationFailureListElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationFailureListElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationMetaData) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationMetaData) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationMetaData) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnosticsIEListElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnosticsIEListElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnosticsIEListElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ECGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AssistanceInformationFailureListElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFailureListElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformationFailureListElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFailureListElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformationFailureListElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformationFailureListElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformationFailureListElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformationFailureListElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformationFailureListElem")
}
func (v *AssistanceInformationFailureListElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFailureListElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFailureListElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationFailureListElem(v, &s)
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
func (v *AssistanceInformationFailureListElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFailureListElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationMetaData) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationMetaData")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformationMetaData")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationMetaData(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformationMetaData")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformationMetaData")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformationMetaData")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformationMetaData")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformationMetaData")
}
func (v *AssistanceInformationMetaData) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationMetaData) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationMetaData) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationMetaData(v, &s)
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
func (v *AssistanceInformationMetaData) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationMetaData) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *BitmapsforNPRS) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BitmapsforNPRS")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "BitmapsforNPRS")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaBitmapsforNPRS(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "BitmapsforNPRS")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "BitmapsforNPRS")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "BitmapsforNPRS")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "BitmapsforNPRS")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "BitmapsforNPRS")
}
func (v *BitmapsforNPRS) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *BitmapsforNPRS) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *BitmapsforNPRS) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaBitmapsforNPRS(v, &s)
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
func (v *BitmapsforNPRS) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *BitmapsforNPRS) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *Cause) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "Cause")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaCause(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "Cause")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "Cause")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "Cause")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "Cause")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *Cause) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *Cause) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaCause(v, &s)
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
func (v *Cause) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *Cause) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *CriticalityDiagnosticsIEListElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListElem(v, &s)
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
func (v *CriticalityDiagnosticsIEListElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECGI")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECGI")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECGI(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECGI")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECGI")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECGI")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECGI")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECGI")
}
func (v *ECGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECGI) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECGI(v, &s)
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
func (v *ECGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationFailureListElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFailureListElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFailureListElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFailureListElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFailureListElem{}
		return report, aper.OperationError(err, "AssistanceInformationFailureListElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformationFailureListElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AssistanceInformationMetaData) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationMetaData")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationMetaData
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationMetaData(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationMetaData{}
		return report, aper.OperationError(err, "AssistanceInformationMetaData")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformationMetaData")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *BitmapsforNPRS) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BitmapsforNPRS")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded BitmapsforNPRS
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaBitmapsforNPRS(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = BitmapsforNPRS{}
		return report, aper.OperationError(err, "BitmapsforNPRS")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BitmapsforNPRS")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *Cause) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded Cause
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCause(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = Cause{}
		return report, aper.OperationError(err, "Cause")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Cause")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *CriticalityDiagnosticsIEListElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnosticsIEListElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEListElem{}
		return report, aper.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnosticsIEListElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ECGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECGI")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECGI
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECGI{}
		return report, aper.OperationError(err, "ECGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECGI")
}
func BridgeCaptureLPPaAssistanceInformationFailureListElem(v *AssistanceInformationFailureListElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPosSIBType(&v.PosSIBType, s)
	s00.BridgeCaptureLPPaOutcome(&v.Outcome, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFailureListElem(v *AssistanceInformationFailureListElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPosSIBType(&v.PosSIBType, s)
	s02.BridgeCompareLPPaOutcome(&v.Outcome, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationMetaData(v *AssistanceInformationMetaData, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	{
		f := s.Begin()
		s.Bool(v.Encrypted == nil)
		if v.Encrypted != nil {
			s.Int(int64((*v.Encrypted)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.GNSSID == nil)
		if v.GNSSID != nil {
			s.Int(int64((*v.GNSSID)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SBASID == nil)
		if v.SBASID != nil {
			s.Int(int64((*v.SBASID)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationMetaData(v *AssistanceInformationMetaData, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.Bool(v.Encrypted == nil)
		if v.Encrypted != nil {
			s.Int(int64((*v.Encrypted)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.GNSSID == nil)
		if v.GNSSID != nil {
			s.Int(int64((*v.GNSSID)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SBASID == nil)
		if v.SBASID != nil {
			s.Int(int64((*v.SBASID)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaBitmapsforNPRS(v *BitmapsforNPRS, s *aper.SemanticCapture) {
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
	case s00.BitmapsforNPRSChoiceTen:
		{
			f := s.Begin()
			s.Bool(v.Ten == nil)
			if v.Ten != nil {
				s.BitString((*v.Ten).Bytes, (*v.Ten).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.BitmapsforNPRSChoiceForty:
		{
			f := s.Begin()
			s.Bool(v.Forty == nil)
			if v.Forty != nil {
				s.BitString((*v.Forty).Bytes, (*v.Forty).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.BitmapsforNPRSChoiceTenTdd:
		{
			f := s.Begin()
			s.Bool(v.TenTdd == nil)
			if v.TenTdd != nil {
				s.BitString((*v.TenTdd).Bytes, (*v.TenTdd).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.BitmapsforNPRSChoiceFortyTdd:
		{
			f := s.Begin()
			s.Bool(v.FortyTdd == nil)
			if v.FortyTdd != nil {
				s.BitString((*v.FortyTdd).Bytes, (*v.FortyTdd).BitLength)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaBitmapsforNPRS(v *BitmapsforNPRS, s *aper.SemanticComparison) {
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
	case s00.BitmapsforNPRSChoiceTen:
		{
			f := s.Begin()
			s.Bool(v.Ten == nil)
			if v.Ten != nil {
				s.BitString((*v.Ten).Bytes, (*v.Ten).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.BitmapsforNPRSChoiceForty:
		{
			f := s.Begin()
			s.Bool(v.Forty == nil)
			if v.Forty != nil {
				s.BitString((*v.Forty).Bytes, (*v.Forty).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.BitmapsforNPRSChoiceTenTdd:
		{
			f := s.Begin()
			s.Bool(v.TenTdd == nil)
			if v.TenTdd != nil {
				s.BitString((*v.TenTdd).Bytes, (*v.TenTdd).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.BitmapsforNPRSChoiceFortyTdd:
		{
			f := s.Begin()
			s.Bool(v.FortyTdd == nil)
			if v.FortyTdd != nil {
				s.BitString((*v.FortyTdd).Bytes, (*v.FortyTdd).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCause(v *Cause, s *aper.SemanticCapture) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s00.BridgeCaptureLPPaCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s00.BridgeCaptureLPPaCauseProtocol(v.Protocol, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s00.BridgeCaptureLPPaCauseMisc(v.Misc, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCause(v *Cause, s *aper.SemanticComparison) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s02.BridgeCompareLPPaCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s02.BridgeCompareLPPaCauseProtocol(v.Protocol, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s02.BridgeCompareLPPaCauseMisc(v.Misc, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(v *CriticalityDiagnosticsIEListElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaCriticality(&v.IECriticality, s)
	s00.BridgeCaptureLPPaProtocolIEID(&v.IEID, s)
	s00.BridgeCaptureLPPaTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListElem(v *CriticalityDiagnosticsIEListElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaCriticality(&v.IECriticality, s)
	s02.BridgeCompareLPPaProtocolIEID(&v.IEID, s)
	s03.BridgeCompareLPPaTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECGI(v *ECGI, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPLMNIdentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureLPPaEUTRANCellIdentifier(&v.EUTRANcellIdentifier, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECGI(v *ECGI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPLMNIdentity(&v.PLMNIdentity, s)
	s02.BridgeCompareLPPaEUTRANCellIdentifier(&v.EUTRANcellIdentifier, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeECGIExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

// preferredSequenceTail chooses the shortest extension bitmap containing all
// semantic additions. X.691 (02/2021) §19.8 defines its index and length.
func BridgePreferredSequenceTail(present []bool, data [][]byte) (int64, bool) {
	var last int64
	found := false
	for i, set := range present {
		if set {
			last = int64(i)
			found = true
		}
	}
	for i, contents := range data {
		if contents != nil {
			last = int64(i)
			found = true
		}
	}
	return last, found
}
func BridgeReceivedFormAt(present bool, original aper.WireSpan, path aper.Path, location aper.Location, complete interface{ Bits() (uint8, uint8) }) aper.ReceivedForm {
	location.Path = path
	var padding []aper.PaddingSpan
	if location.HasWireLocation && len(location.Spans) != 0 {
		last := location.Spans[len(location.Spans)-1]
		value, count := complete.Bits()
		width, borrow := bits.Sub64(last.End, last.Start, 0)
		if count != 0 && borrow == 0 && uint64(count) <= width {
			start, borrow := bits.Sub64(last.End, uint64(count), 0)
			if borrow == 0 {
				padding = []aper.PaddingSpan{{Span: aper.BitSpan{Start: start, End: last.End}, Value: value, Width: count}}
			}
		}
	}
	return aper.NewReceivedSpanForm(present, original, location, padding)
}

// AssistanceInformationFailureListElemCodec binds the complete source value type.
func AssistanceInformationFailureListElemCodec() AssistanceInformationFailureListElemValueCodec {
	return AssistanceInformationFailureListElemValueCodec{path: "AssistanceInformationFailureListElem", decode: func(data []byte, options aper.DecodeState) (AssistanceInformationFailureListElem, error) {
		var value AssistanceInformationFailureListElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceInformationFailureListElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceInformationFailureListElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceInformationFailureListElem, options aper.DecodeState) (AssistanceInformationFailureListElem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		BridgeCaptureLPPaAssistanceInformationFailureListElem(&v,
			&s,
		)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f,
			&root, false)
		return v, root
	}, compare: func(v AssistanceInformationFailureListElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAssistanceInformationFailureListElem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFailureListElem"
		return sealed
	}(),
	}
}

// AssistanceInformationMetaDataCodec binds the complete source value type.
func AssistanceInformationMetaDataCodec() AssistanceInformationMetaDataValueCodec {
	return AssistanceInformationMetaDataValueCodec{path: "AssistanceInformationMetaData", decode: func(data []byte, options aper.DecodeState) (AssistanceInformationMetaData, error) {
		var value AssistanceInformationMetaData
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceInformationMetaData{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceInformationMetaData, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceInformationMetaData, options aper.DecodeState) (AssistanceInformationMetaData, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaAssistanceInformationMetaData(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v AssistanceInformationMetaData, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAssistanceInformationMetaData(&v, &s)
		s.End(f, root, false)

		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationMetaData"
		return sealed
	}(),
	}
}

// BitmapsforNPRSCodec binds the complete source value type.
func BitmapsforNPRSCodec() BitmapsforNPRSValueCodec {
	return BitmapsforNPRSValueCodec{path: "BitmapsforNPRS", decode: func(data []byte, options aper.DecodeState) (BitmapsforNPRS, error) {
		var value BitmapsforNPRS
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return BitmapsforNPRS{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value BitmapsforNPRS, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v BitmapsforNPRS, options aper.DecodeState) (BitmapsforNPRS, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaBitmapsforNPRS(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v BitmapsforNPRS, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaBitmapsforNPRS(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BitmapsforNPRS"
		return sealed
	}(),
	}
}

// CriticalityDiagnosticsIEListElemCodec binds the complete source value type.
func CriticalityDiagnosticsIEListElemCodec() CriticalityDiagnosticsIEListElemValueCodec {
	return CriticalityDiagnosticsIEListElemValueCodec{path: "CriticalityDiagnosticsIEListElem", decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnosticsIEListElem, error) {
		var value CriticalityDiagnosticsIEListElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CriticalityDiagnosticsIEListElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CriticalityDiagnosticsIEListElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CriticalityDiagnosticsIEListElem, options aper.DecodeState) (CriticalityDiagnosticsIEListElem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)

		return v, root
	}, compare: func(v CriticalityDiagnosticsIEListElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaCriticalityDiagnosticsIEListElem(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEListElem"
		return sealed
	}(),
	}
}

// ECGICodec binds the complete source value type.
func ECGICodec() ECGIValueCodec {
	return ECGIValueCodec{path: "ECGI", decode: func(data []byte, options aper.DecodeState) (ECGI, error) {
		var value ECGI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ECGI{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ECGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ECGI, options aper.DecodeState) (ECGI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaECGI(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ECGI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			limits)
		f := s.Begin()
		BridgeCompareLPPaECGI(&v, &s)
		s.End(f,
			root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECGI"
		return sealed
	}(),
	}
}
func BridgeAssistanceInformationFailureListAPERValueFieldContext(v *AssistanceInformationFailureListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListAPERValueFieldReceived(v *AssistanceInformationFailureListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListAPERValueFieldReplay(v *AssistanceInformationFailureListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListAPERValueFieldWithoutReplay(v *AssistanceInformationFailureListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldContext(v *AssistanceInformationFailureListElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldReceived(v *AssistanceInformationFailureListElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldReplay(v *AssistanceInformationFailureListElemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldWithoutReplay(v *AssistanceInformationFailureListElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListElemFieldExtCount(v *AssistanceInformationFailureListElem) *int64 {
	return &v.extCount
}
func BridgeAssistanceInformationFailureListElemFieldExtData(v *AssistanceInformationFailureListElem) *[][]byte {
	return &v.extData
}
func BridgeAssistanceInformationFailureListElemFieldExtOrigin(v *AssistanceInformationFailureListElem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFailureListElemFieldExtPresent(v *AssistanceInformationFailureListElem) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFailureListElemFieldExtWire(v *AssistanceInformationFailureListElem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFailureListElemFieldIEExtensionsIndef(v *AssistanceInformationFailureListElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationFailureListElemFieldPerExtPadding(v *AssistanceInformationFailureListElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFailureListElemFieldPerPadding(v *AssistanceInformationFailureListElem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFailureListElemFieldReceived(v *AssistanceInformationFailureListElem) *bool {
	return &v.received
}
func BridgeAssistanceInformationFailureListElemFieldReceivedBytes(v *AssistanceInformationFailureListElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFailureListElemFieldReplay(v *AssistanceInformationFailureListElem) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListElemFieldStream(v *AssistanceInformationFailureListElem) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListElemFieldWithoutReplay(v *AssistanceInformationFailureListElem) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERBudget(v *AssistanceInformationFailureListElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERChanged(v *AssistanceInformationFailureListElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERChangedValue(v *AssistanceInformationFailureListElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERFreshValue(v *AssistanceInformationFailureListElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERLegacy(v *AssistanceInformationFailureListElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERPlanned(v *AssistanceInformationFailureListElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERTo(v *AssistanceInformationFailureListElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERLegacy(v *AssistanceInformationFailureListElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERWithOptions(v *AssistanceInformationFailureListElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldCapture(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, aper.DecodeState) (AssistanceInformationFailureListElem, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldCompare(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldContext(v *AssistanceInformationFailureListElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldDecode(v *AssistanceInformationFailureListElemValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformationFailureListElem, error) {
	return &v.decode
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldEncode(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldPath(v *AssistanceInformationFailureListElemValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationFailureListElemValueCodecMethodEncodeBudget(v AssistanceInformationFailureListElemValueCodec, a0 AssistanceInformationFailureListElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemValueCodecMethodEncodeChanged(v AssistanceInformationFailureListElemValueCodec, a0 AssistanceInformationFailureListElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationFailureListValueCodecFieldCapture(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, aper.DecodeState) (AssistanceInformationFailureList, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFailureListValueCodecFieldCompare(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFailureListValueCodecFieldContext(v *AssistanceInformationFailureListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListValueCodecFieldDecode(v *AssistanceInformationFailureListValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformationFailureList, error) {
	return &v.decode
}
func BridgeAssistanceInformationFailureListValueCodecFieldEncode(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFailureListValueCodecFieldPath(v *AssistanceInformationFailureListValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationFailureListValueCodecMethodEncodeBudget(v AssistanceInformationFailureListValueCodec, a0 AssistanceInformationFailureList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListValueCodecMethodEncodeChanged(v AssistanceInformationFailureListValueCodec, a0 AssistanceInformationFailureList, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationMetaDataAPERValueFieldContext(v *AssistanceInformationMetaDataAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationMetaDataAPERValueFieldReceived(v *AssistanceInformationMetaDataAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationMetaDataAPERValueFieldReplay(v *AssistanceInformationMetaDataAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataAPERValueFieldWithoutReplay(v *AssistanceInformationMetaDataAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataFieldExtCount(v *AssistanceInformationMetaData) *int64 {
	return &v.extCount
}
func BridgeAssistanceInformationMetaDataFieldExtData(v *AssistanceInformationMetaData) *[][]byte {
	return &v.extData
}
func BridgeAssistanceInformationMetaDataFieldExtOrigin(v *AssistanceInformationMetaData) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationMetaDataFieldExtPresent(v *AssistanceInformationMetaData) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationMetaDataFieldExtWire(v *AssistanceInformationMetaData) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationMetaDataFieldIEExtensionsIndef(v *AssistanceInformationMetaData) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationMetaDataFieldPerExtPadding(v *AssistanceInformationMetaData) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationMetaDataFieldPerPadding(v *AssistanceInformationMetaData) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationMetaDataFieldReceived(v *AssistanceInformationMetaData) *bool {
	return &v.received
}
func BridgeAssistanceInformationMetaDataFieldReceivedBytes(v *AssistanceInformationMetaData) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationMetaDataFieldReplay(v *AssistanceInformationMetaData) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataFieldStream(v *AssistanceInformationMetaData) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataFieldWithoutReplay(v *AssistanceInformationMetaData) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERBudget(v *AssistanceInformationMetaData, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERChanged(v *AssistanceInformationMetaData, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERChangedValue(v *AssistanceInformationMetaData, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERFreshValue(v *AssistanceInformationMetaData, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERLegacy(v *AssistanceInformationMetaData) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERPlanned(v *AssistanceInformationMetaData, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERTo(v *AssistanceInformationMetaData, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERFrom(v *AssistanceInformationMetaData, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERLegacy(v *AssistanceInformationMetaData, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERWithOptions(v *AssistanceInformationMetaData, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationMetaDataValueCodecFieldCapture(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, aper.DecodeState) (AssistanceInformationMetaData, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationMetaDataValueCodecFieldCompare(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationMetaDataValueCodecFieldContext(v *AssistanceInformationMetaDataValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationMetaDataValueCodecFieldDecode(v *AssistanceInformationMetaDataValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformationMetaData, error) {
	return &v.decode
}
func BridgeAssistanceInformationMetaDataValueCodecFieldEncode(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationMetaDataValueCodecFieldPath(v *AssistanceInformationMetaDataValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationMetaDataValueCodecMethodEncodeBudget(v AssistanceInformationMetaDataValueCodec, a0 AssistanceInformationMetaData, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataValueCodecMethodEncodeChanged(v AssistanceInformationMetaDataValueCodec, a0 AssistanceInformationMetaData, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBitmapsforNPRSAPERValueFieldContext(v *BitmapsforNPRSAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBitmapsforNPRSAPERValueFieldReceived(v *BitmapsforNPRSAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBitmapsforNPRSAPERValueFieldReplay(v *BitmapsforNPRSAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBitmapsforNPRSAPERValueFieldWithoutReplay(v *BitmapsforNPRSAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBitmapsforNPRSFieldKnownOpenBytes(v *BitmapsforNPRS) *uint64 { return &v.knownOpenBytes }
func BridgeBitmapsforNPRSFieldPerOpenTypePadding(v *BitmapsforNPRS) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeBitmapsforNPRSFieldPerPadding(v *BitmapsforNPRS) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBitmapsforNPRSFieldReceived(v *BitmapsforNPRS) *bool { return &v.received }
func BridgeBitmapsforNPRSFieldReceivedBytes(v *BitmapsforNPRS) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBitmapsforNPRSFieldReplay(v *BitmapsforNPRS) *aper.Snapshot { return &v.replay }
func BridgeBitmapsforNPRSFieldStream(v *BitmapsforNPRS) *aper.WireSpan { return &v.stream }
func BridgeBitmapsforNPRSFieldWithoutReplay(v *BitmapsforNPRS) *bool   { return &v.withoutReplay }
func BridgeBitmapsforNPRSMethodMarshalAPERBudget(v *BitmapsforNPRS, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERChanged(v *BitmapsforNPRS, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBitmapsforNPRSMethodMarshalAPERChangedValue(v *BitmapsforNPRS, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBitmapsforNPRSMethodMarshalAPERFreshValue(v *BitmapsforNPRS, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERLegacy(v *BitmapsforNPRS) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBitmapsforNPRSMethodMarshalAPERPlanned(v *BitmapsforNPRS, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERTo(v *BitmapsforNPRS, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERFrom(v *BitmapsforNPRS, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERLegacy(v *BitmapsforNPRS, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERWithOptions(v *BitmapsforNPRS, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBitmapsforNPRSValueCodecFieldCapture(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, aper.DecodeState) (BitmapsforNPRS, aper.Snapshot) {
	return &v.capture
}
func BridgeBitmapsforNPRSValueCodecFieldCompare(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeBitmapsforNPRSValueCodecFieldContext(v *BitmapsforNPRSValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBitmapsforNPRSValueCodecFieldDecode(v *BitmapsforNPRSValueCodec) *func([]byte, aper.DecodeState) (BitmapsforNPRS, error) {
	return &v.decode
}
func BridgeBitmapsforNPRSValueCodecFieldEncode(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBitmapsforNPRSValueCodecFieldPath(v *BitmapsforNPRSValueCodec) *aper.Path { return &v.path }
func BridgeBitmapsforNPRSValueCodecMethodEncodeBudget(v BitmapsforNPRSValueCodec, a0 BitmapsforNPRS, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBitmapsforNPRSValueCodecMethodEncodeChanged(v BitmapsforNPRSValueCodec, a0 BitmapsforNPRS, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseAPERValueFieldContext(v *CauseAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeCauseAPERValueFieldReceived(v *CauseAPERValue) *aper.WireSpan         { return &v.received }
func BridgeCauseAPERValueFieldReplay(v *CauseAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeCauseAPERValueFieldWithoutReplay(v *CauseAPERValue) *bool             { return &v.withoutReplay }
func BridgeCauseFieldKnownOpenBytes(v *Cause) *uint64                            { return &v.knownOpenBytes }
func BridgeCauseFieldPerOpenTypePadding(v *Cause) *aper.CompletePadding          { return &v.perOpenTypePadding }
func BridgeCauseFieldPerPadding(v *Cause) *aper.CompletePadding                  { return &v.perPadding }
func BridgeCauseFieldReceived(v *Cause) *bool                                    { return &v.received }
func BridgeCauseFieldReceivedBytes(v *Cause) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeCauseFieldReplay(v *Cause) *aper.Snapshot                             { return &v.replay }
func BridgeCauseFieldStream(v *Cause) *aper.WireSpan                             { return &v.stream }
func BridgeCauseFieldWithoutReplay(v *Cause) *bool                               { return &v.withoutReplay }
func BridgeCauseMethodMarshalAPERBudget(v *Cause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCauseMethodMarshalAPERChanged(v *Cause, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERChangedValue(v *Cause, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERFreshValue(v *Cause, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCauseMethodMarshalAPERLegacy(v *Cause) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeCauseMethodMarshalAPERPlanned(v *Cause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCauseMethodMarshalAPERTo(v *Cause, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCauseMethodUnmarshalAPERFrom(v *Cause, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCauseMethodUnmarshalAPERLegacy(v *Cause, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCauseMethodUnmarshalAPERWithOptions(v *Cause, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCauseValueCodecFieldCapture(v *CauseValueCodec) *func(Cause, aper.DecodeState) (Cause, aper.Snapshot) {
	return &v.capture
}
func BridgeCauseValueCodecFieldCompare(v *CauseValueCodec) *func(Cause, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeCauseValueCodecFieldContext(v *CauseValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeCauseValueCodecFieldDecode(v *CauseValueCodec) *func([]byte, aper.DecodeState) (Cause, error) {
	return &v.decode
}
func BridgeCauseValueCodecFieldEncode(v *CauseValueCodec) *func(Cause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseValueCodecFieldPath(v *CauseValueCodec) *aper.Path { return &v.path }
func BridgeCauseValueCodecMethodEncodeBudget(v CauseValueCodec, a0 Cause, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCauseValueCodecMethodEncodeChanged(v CauseValueCodec, a0 Cause, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldContext(v *CriticalityDiagnosticsIEListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReceived(v *CriticalityDiagnosticsIEListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReplay(v *CriticalityDiagnosticsIEListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldContext(v *CriticalityDiagnosticsIEListElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldReceived(v *CriticalityDiagnosticsIEListElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldReplay(v *CriticalityDiagnosticsIEListElemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtCount(v *CriticalityDiagnosticsIEListElem) *int64 {
	return &v.extCount
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtData(v *CriticalityDiagnosticsIEListElem) *[][]byte {
	return &v.extData
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtOrigin(v *CriticalityDiagnosticsIEListElem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtPresent(v *CriticalityDiagnosticsIEListElem) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtWire(v *CriticalityDiagnosticsIEListElem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeCriticalityDiagnosticsIEListElemFieldIEExtensionsIndef(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCriticalityDiagnosticsIEListElemFieldPerExtPadding(v *CriticalityDiagnosticsIEListElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeCriticalityDiagnosticsIEListElemFieldPerPadding(v *CriticalityDiagnosticsIEListElem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsIEListElemFieldReceived(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListElemFieldReceivedBytes(v *CriticalityDiagnosticsIEListElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsIEListElemFieldReplay(v *CriticalityDiagnosticsIEListElem) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListElemFieldStream(v *CriticalityDiagnosticsIEListElem) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListElemFieldWithoutReplay(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERBudget(v *CriticalityDiagnosticsIEListElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERChanged(v *CriticalityDiagnosticsIEListElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERChangedValue(v *CriticalityDiagnosticsIEListElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERFreshValue(v *CriticalityDiagnosticsIEListElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERLegacy(v *CriticalityDiagnosticsIEListElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERPlanned(v *CriticalityDiagnosticsIEListElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERLegacy(v *CriticalityDiagnosticsIEListElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERWithOptions(v *CriticalityDiagnosticsIEListElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldCapture(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, aper.DecodeState) (CriticalityDiagnosticsIEListElem, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldCompare(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldContext(v *CriticalityDiagnosticsIEListElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldDecode(v *CriticalityDiagnosticsIEListElemValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEListElem, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldEncode(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldPath(v *CriticalityDiagnosticsIEListElemValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecMethodEncodeBudget(v CriticalityDiagnosticsIEListElemValueCodec, a0 CriticalityDiagnosticsIEListElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEListElemValueCodec, a0 CriticalityDiagnosticsIEListElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.DecodeState) (CriticalityDiagnosticsIEList, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(v *CriticalityDiagnosticsIEListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(v *CriticalityDiagnosticsIEListValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(v *CriticalityDiagnosticsIEListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeBudget(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECGIAPERValueFieldContext(v *ECGIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeECGIAPERValueFieldReceived(v *ECGIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeECGIAPERValueFieldReplay(v *ECGIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeECGIAPERValueFieldWithoutReplay(v *ECGIAPERValue) *bool             { return &v.withoutReplay }
func BridgeECGIFieldExtCount(v *ECGI) *int64                                   { return &v.extCount }
func BridgeECGIFieldExtData(v *ECGI) *[][]byte                                 { return &v.extData }
func BridgeECGIFieldExtOrigin(v *ECGI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeECGIFieldExtPresent(v *ECGI) *[]bool                                { return &v.extPresent }
func BridgeECGIFieldExtWire(v *ECGI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeECGIFieldIEExtensionsIndef(v *ECGI) *bool                           { return &v.iEExtensionsIndef }
func BridgeECGIFieldPerExtPadding(v *ECGI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeECGIFieldPerPadding(v *ECGI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeECGIFieldReceived(v *ECGI) *bool                                    { return &v.received }
func BridgeECGIFieldReceivedBytes(v *ECGI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeECGIFieldReplay(v *ECGI) *aper.Snapshot                             { return &v.replay }
func BridgeECGIFieldStream(v *ECGI) *aper.WireSpan                             { return &v.stream }
func BridgeECGIFieldWithoutReplay(v *ECGI) *bool                               { return &v.withoutReplay }
func BridgeECGIMethodMarshalAPERBudget(v *ECGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECGIMethodMarshalAPERChanged(v *ECGI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECGIMethodMarshalAPERChangedValue(v *ECGI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECGIMethodMarshalAPERFreshValue(v *ECGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECGIMethodMarshalAPERLegacy(v *ECGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeECGIMethodMarshalAPERPlanned(v *ECGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECGIMethodMarshalAPERTo(v *ECGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIMethodUnmarshalAPERFrom(v *ECGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIMethodUnmarshalAPERLegacy(v *ECGI, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeECGIMethodUnmarshalAPERWithOptions(v *ECGI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECGIValueCodecFieldCapture(v *ECGIValueCodec) *func(ECGI, aper.DecodeState) (ECGI, aper.Snapshot) {
	return &v.capture
}
func BridgeECGIValueCodecFieldCompare(v *ECGIValueCodec) *func(ECGI, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECGIValueCodecFieldContext(v *ECGIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeECGIValueCodecFieldDecode(v *ECGIValueCodec) *func([]byte, aper.DecodeState) (ECGI, error) {
	return &v.decode
}
func BridgeECGIValueCodecFieldEncode(v *ECGIValueCodec) *func(ECGI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECGIValueCodecFieldPath(v *ECGIValueCodec) *aper.Path { return &v.path }
func BridgeECGIValueCodecMethodEncodeBudget(v ECGIValueCodec, a0 ECGI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECGIValueCodecMethodEncodeChanged(v ECGIValueCodec, a0 ECGI, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
