// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s05 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s05

import (
	q7 "fmt"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q11 "math/bits"
)

func BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.MeasurementQuantitiesValueExtIEsExtContainer, s *q5.SemanticComparison) {
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
			q4.BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.NRCGIExtIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.NRCGIExtIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.OTDOACellsExtIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.OTDOACellsExtIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.OTDOAInformationTypeItemExtIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.OTDOAInformationTypeItemExtIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.PRSFrequencyHoppingConfigurationItemIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionContainer(v *q4.PRSFrequencyHoppingConfigurationItemIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.PosSIBSegmentsExtIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.PosSIBSegmentsExtIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q4.PosSIBsExtIEsExtContainer, s *q5.SemanticCapture) {
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
func BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionContainer(v *q4.PosSIBsExtIEsExtContainer, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}

// AssistanceInformationFailureListValueCodec is the concrete ValueCodec[AssistanceInformationFailureList].
type AssistanceInformationFailureListValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AssistanceInformationFailureList, q5.DecodeState,

	) (AssistanceInformationFailureList, q5.Snapshot,

	)
	compare func(AssistanceInformationFailureList, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AssistanceInformationFailureList,

		error)
	encode func(AssistanceInformationFailureList,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationFailureListValueCodec) New(value AssistanceInformationFailureList,

) (AssistanceInformationFailureListAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFailureListAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AssistanceInformationFailureListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFailureListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AssistanceInformationFailureListAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AssistanceInformationFailureListValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AssistanceInformationFailureListAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFailureListAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AssistanceInformationFailureListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFailureListAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFailureListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AssistanceInformationFailureListAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationFailureListValueCodec) EncodeAPER(value AssistanceInformationFailureListAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationFailureListValueCodec) encodeBudget(value AssistanceInformationFailureList,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFailureListValueCodec) encodeChanged(value AssistanceInformationFailureList,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec struct {
	context q6.BridgeCodecContext
	capture func(Cause, q5.DecodeState,

	) (Cause, q5.Snapshot,

	)
	compare func(Cause, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (Cause,

		error)
	encode func(Cause,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CauseValueCodec) New(value Cause,

) (CauseAPERValue, error) {
	if c.encode == nil {
		return CauseAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CauseAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CauseAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CauseValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CauseAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CauseAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CauseAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CauseAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CauseAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CauseAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CauseValueCodec) EncodeAPER(value CauseAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c CauseValueCodec) encodeBudget(value Cause,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CauseValueCodec) encodeChanged(value Cause,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// AssistanceInformationFailureListElemValueCodec is the concrete ValueCodec[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AssistanceInformationFailureListElem, q5.DecodeState,

	) (AssistanceInformationFailureListElem, q5.Snapshot,

	)
	compare func(AssistanceInformationFailureListElem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AssistanceInformationFailureListElem,

		error)
	encode func(AssistanceInformationFailureListElem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationFailureListElemValueCodec) New(value AssistanceInformationFailureListElem,

) (AssistanceInformationFailureListElemAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFailureListElemAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AssistanceInformationFailureListElemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AssistanceInformationFailureListElemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AssistanceInformationFailureListElemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFailureListElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AssistanceInformationFailureListElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFailureListElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFailureListElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AssistanceInformationFailureListElemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationFailureListElemValueCodec) EncodeAPER(value AssistanceInformationFailureListElemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationFailureListElemValueCodec) encodeBudget(value AssistanceInformationFailureListElem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFailureListElemValueCodec) encodeChanged(value AssistanceInformationFailureListElem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// AssistanceInformationMetaDataValueCodec is the concrete ValueCodec[AssistanceInformationMetaData].
type AssistanceInformationMetaDataValueCodec struct {
	context q6.BridgeCodecContext
	capture func(AssistanceInformationMetaData, q5.DecodeState,

	) (AssistanceInformationMetaData, q5.Snapshot,

	)
	compare func(AssistanceInformationMetaData, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (AssistanceInformationMetaData,

		error)
	encode func(AssistanceInformationMetaData,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationMetaDataValueCodec) New(value AssistanceInformationMetaData,

) (AssistanceInformationMetaDataAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationMetaDataAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return AssistanceInformationMetaDataAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationMetaDataAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return AssistanceInformationMetaDataAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c AssistanceInformationMetaDataValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (AssistanceInformationMetaDataAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationMetaDataAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return AssistanceInformationMetaDataAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationMetaDataAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationMetaDataAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return AssistanceInformationMetaDataAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationMetaDataValueCodec) EncodeAPER(value AssistanceInformationMetaDataAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationMetaDataValueCodec) encodeBudget(value AssistanceInformationMetaData,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationMetaDataValueCodec) encodeChanged(value AssistanceInformationMetaData,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// BitmapsforNPRSValueCodec is the concrete ValueCodec[BitmapsforNPRS].
type BitmapsforNPRSValueCodec struct {
	context q6.BridgeCodecContext
	capture func(BitmapsforNPRS, q5.DecodeState,

	) (BitmapsforNPRS, q5.Snapshot,

	)
	compare func(BitmapsforNPRS, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (BitmapsforNPRS,

		error)
	encode func(BitmapsforNPRS,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c BitmapsforNPRSValueCodec) New(value BitmapsforNPRS,

) (BitmapsforNPRSAPERValue, error) {
	if c.encode == nil {
		return BitmapsforNPRSAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return BitmapsforNPRSAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BitmapsforNPRSAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return BitmapsforNPRSAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c BitmapsforNPRSValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (BitmapsforNPRSAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BitmapsforNPRSAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return BitmapsforNPRSAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BitmapsforNPRSAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return BitmapsforNPRSAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return BitmapsforNPRSAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c BitmapsforNPRSValueCodec) EncodeAPER(value BitmapsforNPRSAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c BitmapsforNPRSValueCodec) encodeBudget(value BitmapsforNPRS,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BitmapsforNPRSValueCodec) encodeChanged(value BitmapsforNPRS,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec struct {
	context q6.BridgeCodecContext
	capture func(CriticalityDiagnosticsIEList, q5.DecodeState,

	) (CriticalityDiagnosticsIEList, q5.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEList, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CriticalityDiagnosticsIEList,

		error)
	encode func(CriticalityDiagnosticsIEList,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CriticalityDiagnosticsIEListValueCodec) New(value CriticalityDiagnosticsIEList,

) (CriticalityDiagnosticsIEListAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CriticalityDiagnosticsIEListValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CriticalityDiagnosticsIEListAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CriticalityDiagnosticsIEListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CriticalityDiagnosticsIEListValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListValueCodec) encodeBudget(value CriticalityDiagnosticsIEList,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsIEListValueCodec) encodeChanged(value CriticalityDiagnosticsIEList,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListElemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemValueCodec struct {
	context q6.BridgeCodecContext
	capture func(CriticalityDiagnosticsIEListElem, q5.DecodeState,

	) (CriticalityDiagnosticsIEListElem, q5.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEListElem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CriticalityDiagnosticsIEListElem,

		error)
	encode func(CriticalityDiagnosticsIEListElem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CriticalityDiagnosticsIEListElemValueCodec) New(value CriticalityDiagnosticsIEListElem,

) (CriticalityDiagnosticsIEListElemAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsIEListElemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CriticalityDiagnosticsIEListElemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CriticalityDiagnosticsIEListElemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CriticalityDiagnosticsIEListElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsIEListElemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsIEListElemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CriticalityDiagnosticsIEListElemValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListElemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListElemValueCodec) encodeBudget(value CriticalityDiagnosticsIEListElem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsIEListElemValueCodec) encodeChanged(value CriticalityDiagnosticsIEListElem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ECGIValueCodec is the concrete ValueCodec[ECGI].
type ECGIValueCodec struct {
	context q6.BridgeCodecContext
	capture func(ECGI, q5.DecodeState,

	) (ECGI, q5.Snapshot,

	)
	compare func(ECGI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ECGI,

		error)
	encode func(ECGI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ECGIValueCodec) New(value ECGI,

) (ECGIAPERValue, error) {
	if c.encode == nil {
		return ECGIAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECGIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECGIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ECGIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ECGIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ECGIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECGIAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ECGIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECGIAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ECGIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ECGIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECGIValueCodec) EncodeAPER(value ECGIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ECGIValueCodec) encodeBudget(value ECGI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECGIValueCodec) encodeChanged(value ECGI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// measurementQuantitiesValueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementQuantitiesValueExtIEsValue].
type MeasurementQuantitiesValueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.MeasurementQuantitiesValueExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.MeasurementQuantitiesValueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

// nRCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRCGIExtIEsValue].
type NRCGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.NRCGIExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.NRCGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.NRCGIExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgeNRCGIExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeNRCGIExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeNRCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeNRCGIExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *q4.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionField(v *q4.NRCGIExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeNRCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *q4.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}

// oTDOACellsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[OTDOACellsExtIEsValue].
type OTDOACellsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.OTDOACellsExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.OTDOACellsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.OTDOACellsExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgeOTDOACellsExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeOTDOACellsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeOTDOACellsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeOTDOACellsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgeOTDOACellsExtIEsExtFieldFieldReplay(v), *q4.BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionField(v *q4.OTDOACellsExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeOTDOACellsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgeOTDOACellsExtIEsExtFieldFieldReplay(v), *q4.BridgeOTDOACellsExtIEsExtFieldFieldWithoutReplay(v))
}

// oTDOAInformationTypeItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationTypeItemExtIEsValue].
type OTDOAInformationTypeItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.OTDOAInformationTypeItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.OTDOAInformationTypeItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.OTDOAInformationTypeItemExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v), *q4.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionField(v *q4.OTDOAInformationTypeItemExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeOTDOAInformationTypeItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldReplay(v), *q4.BridgeOTDOAInformationTypeItemExtIEsExtFieldFieldWithoutReplay(v))
}

// pRSFrequencyHoppingConfigurationItemIEsValueProtocolOpenValue is the concrete protocolOpenValue[PRSFrequencyHoppingConfigurationItemIEsValue].
type PRSFrequencyHoppingConfigurationItemIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.PRSFrequencyHoppingConfigurationItemIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.PRSFrequencyHoppingConfigurationItemIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionField(v *q4.PRSFrequencyHoppingConfigurationItemIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v), *q4.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v))
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionField(v *q4.PRSFrequencyHoppingConfigurationItemIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldReplay(v), *q4.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldFieldWithoutReplay(v))
}

// posSIBSegmentsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PosSIBSegmentsExtIEsValue].
type PosSIBSegmentsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q8.PosSIBSegmentsExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q8.PosSIBSegmentsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.PosSIBSegmentsExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgePosSIBSegmentsExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgePosSIBSegmentsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgePosSIBSegmentsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgePosSIBSegmentsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v), *q4.BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionField(v *q4.PosSIBSegmentsExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgePosSIBSegmentsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgePosSIBSegmentsExtIEsExtFieldFieldReplay(v), *q4.BridgePosSIBSegmentsExtIEsExtFieldFieldWithoutReplay(v))
}

// posSIBsExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PosSIBsExtIEsValue].
type PosSIBsExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q9.PosSIBsExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q6.ProtocolIEID, q5.OpaqueOpenType) (q9.PosSIBsExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q6.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q6.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgePosSIBsExtIEsValueCaptureLPPaProtocolExtensionField(v *q4.PosSIBsExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q4.BridgePosSIBsExtIEsExtFieldFieldStream(v))
	q6.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q6.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q9.BridgePosSIBsExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q9.BridgePosSIBsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q9.BridgePosSIBsExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q4.BridgePosSIBsExtIEsExtFieldFieldReplay(v), *q4.BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePosSIBsExtIEsValueCompareLPPaProtocolExtensionField(v *q4.PosSIBsExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q9.BridgePosSIBsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q4.BridgePosSIBsExtIEsExtFieldFieldReplay(v), *q4.BridgePosSIBsExtIEsExtFieldFieldWithoutReplay(v))
}

// AssistanceInformationFailureListAPERValue is the concrete APERValue[AssistanceInformationFailureList].
type AssistanceInformationFailureListAPERValue struct {
	context q6.BridgeCodecContext
	Value   AssistanceInformationFailureList

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationFailureListAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AssistanceInformationFailureListAPERValue) WithoutReplay() AssistanceInformationFailureListAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue struct {
	context q6.BridgeCodecContext
	Value   Cause

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CauseAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CauseAPERValue) WithoutReplay() CauseAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationFailureListElemAPERValue is the concrete APERValue[AssistanceInformationFailureListElem].
type AssistanceInformationFailureListElemAPERValue struct {
	context q6.BridgeCodecContext
	Value   AssistanceInformationFailureListElem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationFailureListElemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AssistanceInformationFailureListElemAPERValue) WithoutReplay() AssistanceInformationFailureListElemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationMetaDataAPERValue is the concrete APERValue[AssistanceInformationMetaData].
type AssistanceInformationMetaDataAPERValue struct {
	context q6.BridgeCodecContext
	Value   AssistanceInformationMetaData

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationMetaDataAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v AssistanceInformationMetaDataAPERValue) WithoutReplay() AssistanceInformationMetaDataAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// BitmapsforNPRSAPERValue is the concrete APERValue[BitmapsforNPRS].
type BitmapsforNPRSAPERValue struct {
	context q6.BridgeCodecContext
	Value   BitmapsforNPRS

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v BitmapsforNPRSAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v BitmapsforNPRSAPERValue) WithoutReplay() BitmapsforNPRSAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue struct {
	context q6.BridgeCodecContext
	Value   CriticalityDiagnosticsIEList

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CriticalityDiagnosticsIEListAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CriticalityDiagnosticsIEListAPERValue) WithoutReplay() CriticalityDiagnosticsIEListAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListElemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEListElem].
type CriticalityDiagnosticsIEListElemAPERValue struct {
	context q6.BridgeCodecContext
	Value   CriticalityDiagnosticsIEListElem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CriticalityDiagnosticsIEListElemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CriticalityDiagnosticsIEListElemAPERValue) WithoutReplay() CriticalityDiagnosticsIEListElemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECGIAPERValue is the concrete APERValue[ECGI].
type ECGIAPERValue struct {
	context q6.BridgeCodecContext
	Value   ECGI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ECGIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ECGIAPERValue) WithoutReplay() ECGIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

type AssistanceInformationFailureList = []AssistanceInformationFailureListElem

// AssistanceInformationMetaData represents the ASN.1 type AssistanceInformationMetaData (SEQUENCE).
type AssistanceInformationMetaData struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	Encrypted         *int64                                             `asn1:"tag:0,context,implicit,optional" json:"Encrypted,omitempty"`
	GNSSID            *int64                                             `asn1:"tag:1,context,implicit,optional" json:"GNSSID,omitempty"`
	SBASID            *int64                                             `asn1:"tag:2,context,implicit,optional" json:"SBASID,omitempty"`
	IEExtensions      q9.AssistanceInformationMetaDataExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// BitmapsforNPRS represents the ASN.1 CHOICE type BitmapsforNPRS.
type BitmapsforNPRS struct {
	knownOpenBytes     uint64
	replay             q5.Snapshot
	stream             q5.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q5.WireSpan
	Choice             int
	perPadding         q5.CompletePadding  `json:"-"`
	perOpenTypePadding q5.CompletePadding  `json:"-"`
	UnknownExtension   *q5.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Ten                *q10.BitString      `json:"Ten,omitempty"`
	Forty              *q10.BitString      `json:"Forty,omitempty"`
	TenTdd             *q10.BitString      `json:"TenTdd,omitempty"`
	FortyTdd           *q10.BitString      `json:"FortyTdd,omitempty"`
}

// Cause represents the ASN.1 CHOICE type Cause.
type Cause struct {
	knownOpenBytes     uint64
	replay             q5.Snapshot
	stream             q5.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q5.WireSpan
	Choice             int
	perPadding         q5.CompletePadding    `json:"-"`
	perOpenTypePadding q5.CompletePadding    `json:"-"`
	UnknownExtension   *q5.ChoiceExtension   `json:"UnknownExtension,omitempty"`
	RadioNetwork       *q6.CauseRadioNetwork `json:"RadioNetwork,omitempty"`
	Protocol           *q6.CauseProtocol     `json:"Protocol,omitempty"`
	Misc               *q6.CauseMisc         `json:"Misc,omitempty"`
}
type CriticalityDiagnosticsIEList = []CriticalityDiagnosticsIEListElem

// ECGI represents the ASN.1 type ECGI (SEQUENCE).
type ECGI struct {
	replay               q5.Snapshot
	stream               q5.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        q5.WireSpan
	PLMNIdentity         q6.PLMNIdentity           `asn1:"tag:0,context,implicit"`
	EUTRANcellIdentifier q6.EUTRANCellIdentifier   `asn1:"tag:1,context,implicit"`
	IEExtensions         q9.ECGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                      `asn1:"-" json:"-"`
	extCount             int64                     `asn1:"-" json:"-"`
	extPresent           []bool                    `asn1:"-" json:"-"`
	extData              [][]byte                  `asn1:"-" json:"-"`
	perPadding           q5.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding        []q5.CompletePadding      `asn1:"-" json:"-"`
	extOrigin            []q5.OpaqueOrigin
	extWire              []q5.WireSpan
}

// AssistanceInformationFailureListElem represents the ASN.1 type AssistanceInformationFailureList-Elem (SEQUENCE).
type AssistanceInformationFailureListElem struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	PosSIBType        q6.PosSIBType                                         `asn1:"tag:0,context,implicit"`
	Outcome           q6.Outcome                                            `asn1:"tag:1,context,implicit"`
	IEExtensions      q9.AssistanceInformationFailureListExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                  `asn1:"-" json:"-"`
	extCount          int64                                                 `asn1:"-" json:"-"`
	extPresent        []bool                                                `asn1:"-" json:"-"`
	extData           [][]byte                                              `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding                                       `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding                                  `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// CriticalityDiagnosticsIEListElem represents the ASN.1 type CriticalityDiagnostics-IE-List-Elem (SEQUENCE).
type CriticalityDiagnosticsIEListElem struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	IECriticality     q6.Criticality                                    `asn1:"tag:0,context,implicit"`
	IEID              q6.ProtocolIEID                                   `asn1:"tag:1,context,implicit"`
	TypeOfError       q6.TypeOfError                                    `asn1:"tag:2,context,implicit"`
	IEExtensions      q9.CriticalityDiagnosticsIEListExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                              `asn1:"-" json:"-"`
	extCount          int64                                             `asn1:"-" json:"-"`
	extPresent        []bool                                            `asn1:"-" json:"-"`
	extData           [][]byte                                          `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// MarshalAPER encodes AssistanceInformationMetaData to APER format.
func (v *AssistanceInformationMetaData) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationMetaData) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.Encrypted != nil); err != nil {
		return err
	}
	if err := q5.EncodeBoolean(bb, v.GNSSID != nil); err != nil {
		return err
	}
	if err := q5.EncodeBoolean(bb, v.SBASID != nil); err != nil {
		return err
	}
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.Encrypted != nil {
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.Encrypted), 1, true); err != nil {
			return q7.Errorf("encoding encrypted: %w", err)
		}
	}
	if v.GNSSID != nil {
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.GNSSID), 6, true); err != nil {
			return q7.Errorf("encoding gNSSID: %w", err)
		}
	}
	if v.SBASID != nil {
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.SBASID), 4, true); err != nil {
			return q7.Errorf("encoding sBASID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformationMetaData from APER format.
func (v *AssistanceInformationMetaData) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationMetaData with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationMetaData) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	padding, err := q5.CaptureFinalBits(bb, "AssistanceInformationMetaData")
	if err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationMetaData")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationMetaData) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationMetaData{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_encrypted, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_gnssid, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sbasid, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_encrypted {
		val_encrypted, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Encrypted"})
		if err != nil {
			return q10.WrapDecodePath(err, "Encrypted")
		}
		if err := q5.ChargeValue(bb, val_encrypted); err != nil {
			return err
		}
		v.Encrypted = (*int64)(bb.OwnInt64(int64(val_encrypted)))
	}
	if opt_gnssid {
		val_gnssid, err := q5.DecodeEnumeratedAligned(bb, 6, true, q5.EnumerationSource{KnownExtensions: 1, Path: "GNSSID"})
		if err != nil {
			return q10.WrapDecodePath(err, "GNSSID")
		}
		if err := q5.ChargeValue(bb, val_gnssid); err != nil {
			return err
		}
		v.GNSSID = (*int64)(bb.OwnInt64(int64(val_gnssid)))
	}
	if opt_sbasid {
		val_sbasid, err := q5.DecodeEnumeratedAligned(bb, 4, true, q5.EnumerationSource{KnownExtensions: 0, Path: "SBASID"})
		if err != nil {
			return q10.WrapDecodePath(err, "SBASID")
		}
		if err := q5.ChargeValue(bb, val_sbasid); err != nil {
			return err
		}
		v.SBASID = (*int64)(bb.OwnInt64(int64(val_sbasid)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q9.AssistanceInformationMetaDataExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.AssistanceInformationMetaDataExtIEsExtField
				if err := q9.BridgeAssistanceInformationMetaDataExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q10.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q10.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "ExtData_")
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
					return q10.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes BitmapsforNPRS to APER format.
func (v *BitmapsforNPRS) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *BitmapsforNPRS) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
			return q7.Errorf("%s known choice %d and unknown extension are both selected", "BitmapsforNPRS:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q7.Errorf("%s extension index %d must be non-negative", "BitmapsforNPRS:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 2 {
			return q7.Errorf("%s extension index %d is known to this schema", "BitmapsforNPRS:", v.UnknownExtension.Index())
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
		return q7.Errorf("%s choice %d must be positive", "BitmapsforNPRS:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := q5.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return q7.Errorf("extension choice index outside root")
		}
		if err := q5.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := q5.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case q6.BitmapsforNPRSChoiceTenTdd:
			if v.TenTdd == nil {
				return q7.Errorf("choice alternative ten-tdd is nil")
			}
			if err := q5.EncodeBitStringAligned(inner, v.TenTdd.Bytes, v.TenTdd.BitLength, 8, 8, true); err != nil {
				return q7.Errorf("encoding ten-tdd: %w", err)
			}
		case q6.BitmapsforNPRSChoiceFortyTdd:
			if v.FortyTdd == nil {
				return q7.Errorf("choice alternative forty-tdd is nil")
			}
			if err := q5.EncodeBitStringAligned(inner, v.FortyTdd.Bytes, v.FortyTdd.BitLength, 32, 32, true); err != nil {
				return q7.Errorf("encoding forty-tdd: %w", err)
			}
		default:
			return q7.Errorf("unknown BitmapsforNPRS extension choice %d", v.Choice)
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
	if err := q5.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case q6.BitmapsforNPRSChoiceTen:
		if v.Ten == nil {
			return q7.Errorf("choice alternative ten is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Ten.Bytes, v.Ten.BitLength, 10, 10, true); err != nil {
			return q7.Errorf("encoding ten: %w", err)
		}
	case q6.BitmapsforNPRSChoiceForty:
		if v.Forty == nil {
			return q7.Errorf("choice alternative forty is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Forty.Bytes, v.Forty.BitLength, 40, 40, true); err != nil {
			return q7.Errorf("encoding forty: %w", err)
		}
	default:
		return q7.Errorf("unknown BitmapsforNPRS choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes BitmapsforNPRS from APER format.
func (v *BitmapsforNPRS) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BitmapsforNPRS with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BitmapsforNPRS) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "BitmapsforNPRS")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "BitmapsforNPRS")
	}
	padding, err := q5.CaptureFinalBits(bb, "BitmapsforNPRS")
	if err != nil {
		return q10.WrapDecodePath(err, "BitmapsforNPRS")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *BitmapsforNPRS) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BitmapsforNPRS{}
	isExtension, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q5.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q5.DecodeChoiceExtensionAligned(bb, extIdx, 2)
		if extIdx < 2 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q10.WrapDecodePath(err, "UnknownExtension")
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
			return q7.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case q6.BitmapsforNPRSChoiceTenTdd:
			extensionPath = "TenTdd"
			bsBytes_tentdd, bsBitLen_tentdd, err := q5.DecodeBitStringAligned(inner, 8, 8, true)
			if err != nil {
				return q10.WrapDecodePath(err, "TenTdd")
			}
			tmp_tentdd := q10.BitString{Bytes: bsBytes_tentdd, BitLength: bsBitLen_tentdd}
			if err := q5.ChargeValue(inner, tmp_tentdd); err != nil {
				return err
			}
			v.TenTdd = &tmp_tentdd
		case q6.BitmapsforNPRSChoiceFortyTdd:
			extensionPath = "FortyTdd"
			bsBytes_fortytdd, bsBitLen_fortytdd, err := q5.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return q10.WrapDecodePath(err, "FortyTdd")
			}
			tmp_fortytdd := q10.BitString{Bytes: bsBytes_fortytdd, BitLength: bsBitLen_fortytdd}
			if err := q5.ChargeValue(inner, tmp_fortytdd); err != nil {
				return err
			}
			v.FortyTdd = &tmp_fortytdd
		}
		padding, err := q5.CaptureOpenTypePadding(inner)
		if err != nil {
			return q10.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q5.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q7.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q6.BitmapsforNPRSChoiceTen:
		bsBytes_ten, bsBitLen_ten, err := q5.DecodeBitStringAligned(bb, 10, 10, true)
		if err != nil {
			return q10.WrapDecodePath(err, "Ten")
		}
		tmp_ten := q10.BitString{Bytes: bsBytes_ten, BitLength: bsBitLen_ten}
		if err := q5.ChargeValue(bb, tmp_ten); err != nil {
			return err
		}
		v.Ten = &tmp_ten
	case q6.BitmapsforNPRSChoiceForty:
		bsBytes_forty, bsBitLen_forty, err := q5.DecodeBitStringAligned(bb, 40, 40, true)
		if err != nil {
			return q10.WrapDecodePath(err, "Forty")
		}
		tmp_forty := q10.BitString{Bytes: bsBytes_forty, BitLength: bsBitLen_forty}
		if err := q5.ChargeValue(bb, tmp_forty); err != nil {
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
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Cause) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
			return q7.Errorf("%s known choice %d and unknown extension are both selected", "Cause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q7.Errorf("%s extension index %d must be non-negative", "Cause:", v.UnknownExtension.Index())
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
		return q7.Errorf("%s choice %d must be positive", "Cause:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := q5.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return q7.Errorf("%s extension choice %d not supported", "Cause:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q7.Errorf("choice index outside root")
	}
	if err := q5.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case q6.CauseChoiceRadioNetwork:
		if v.RadioNetwork == nil {
			return q7.Errorf("choice alternative radioNetwork is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.RadioNetwork), 3, true); err != nil {
			return q7.Errorf("encoding radioNetwork: %w", err)
		}
	case q6.CauseChoiceProtocol:
		if v.Protocol == nil {
			return q7.Errorf("choice alternative protocol is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.Protocol), 7, true); err != nil {
			return q7.Errorf("encoding protocol: %w", err)
		}
	case q6.CauseChoiceMisc:
		if v.Misc == nil {
			return q7.Errorf("choice alternative misc is nil")
		}
		if err := q5.EncodeEnumeratedAligned(bb, int64(*v.Misc), 1, true); err != nil {
			return q7.Errorf("encoding misc: %w", err)
		}
	default:
		return q7.Errorf("unknown Cause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Cause from APER format.
func (v *Cause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Cause with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Cause) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "Cause")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "Cause")
	}
	padding, err := q5.CaptureFinalBits(bb, "Cause")
	if err != nil {
		return q10.WrapDecodePath(err, "Cause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Cause) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cause{}
	isExtension, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q5.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q5.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q10.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q5.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q7.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q6.CauseChoiceRadioNetwork:
		val_radionetwork, err := q5.DecodeEnumeratedAligned(bb, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "RadioNetwork"})
		if err != nil {
			return q10.WrapDecodePath(err, "RadioNetwork")
		}
		tmp_radionetwork := q6.CauseRadioNetwork(val_radionetwork)
		if err := q5.ChargeValue(bb, tmp_radionetwork); err != nil {
			return err
		}
		v.RadioNetwork = (*q6.CauseRadioNetwork)(bb.OwnInt64(int64(tmp_radionetwork)))
	case q6.CauseChoiceProtocol:
		val_protocol, err := q5.DecodeEnumeratedAligned(bb, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Protocol"})
		if err != nil {
			return q10.WrapDecodePath(err, "Protocol")
		}
		tmp_protocol := q6.CauseProtocol(val_protocol)
		if err := q5.ChargeValue(bb, tmp_protocol); err != nil {
			return err
		}
		v.Protocol = (*q6.CauseProtocol)(bb.OwnInt64(int64(tmp_protocol)))
	case q6.CauseChoiceMisc:
		val_misc, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Misc"})
		if err != nil {
			return q10.WrapDecodePath(err, "Misc")
		}
		tmp_misc := q6.CauseMisc(val_misc)
		if err := q5.ChargeValue(bb, tmp_misc); err != nil {
			return err
		}
		v.Misc = (*q6.CauseMisc)(bb.OwnInt64(int64(

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
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECGI) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return q7.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := q5.EncodeBitStringAligned(bb, v.EUTRANcellIdentifier.Bytes, v.EUTRANcellIdentifier.BitLength, 28, 28, true); err != nil {
		return q7.Errorf("encoding eUTRANcellIdentifier: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeECGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECGI from APER format.
func (v *ECGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECGI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECGI) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "ECGI")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "ECGI")
	}
	padding, err := q5.CaptureFinalBits(bb, "ECGI")
	if err != nil {
		return q10.WrapDecodePath(err, "ECGI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECGI) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECGI{}
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
	val_plmnidentity, err := q5.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return q10.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = q6.PLMNIdentity(val_plmnidentity)
	bsBytes_eutrancellidentifier, bsBitLen_eutrancellidentifier, err := q5.DecodeBitStringAligned(bb, 28, 28, true)
	if err != nil {
		return q10.WrapDecodePath(err, "EUTRANcellIdentifier")
	}
	v.EUTRANcellIdentifier = q10.BitString{Bytes: bsBytes_eutrancellidentifier, BitLength: bsBitLen_eutrancellidentifier}
	if opt_ieextensions {
		tmp_ieextensions := make(q9.ECGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.ECGIExtIEsExtField
				if err := q9.BridgeECGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q10.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q10.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "ExtData_")
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
					return q10.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes AssistanceInformationFailureListElem to APER format.
func (v *AssistanceInformationFailureListElem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationFailureListElem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.PosSIBType), 27, true); err != nil {
		return q7.Errorf("encoding posSIB-Type: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Outcome), 1, true); err != nil {
		return q7.Errorf("encoding outcome: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeAssistanceInformationFailureListExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformationFailureListElem from APER format.
func (v *AssistanceInformationFailureListElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationFailureListElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationFailureListElem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	padding, err := q5.CaptureFinalBits(bb, "AssistanceInformationFailureListElem")
	if err != nil {
		return q10.WrapDecodePath(err, "AssistanceInformationFailureListElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationFailureListElem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFailureListElem{}
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
	val_possibtype, err := q5.DecodeEnumeratedAligned(bb, 27, true, q5.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
	if err != nil {
		return q10.WrapDecodePath(err, "PosSIBType")
	}
	v.PosSIBType = q6.PosSIBType(val_possibtype)
	val_outcome, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Outcome"})
	if err != nil {
		return q10.WrapDecodePath(err, "Outcome")
	}
	v.Outcome = q6.Outcome(val_outcome)
	if opt_ieextensions {
		tmp_ieextensions := make(q9.AssistanceInformationFailureListExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.AssistanceInformationFailureListExtIEsExtField
				if err := q9.BridgeAssistanceInformationFailureListExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q10.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q10.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "ExtData_")
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
					return q10.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes CriticalityDiagnosticsIEListElem to APER format.
func (v *CriticalityDiagnosticsIEListElem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.IECriticality), 3, false); err != nil {
		return q7.Errorf("encoding iECriticality: %w", err)
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.IEID), q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false); err != nil {
		return q7.Errorf("encoding iE-ID: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.TypeOfError), 2, true); err != nil {
		return q7.Errorf("encoding typeOfError: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q7.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CriticalityDiagnosticsIEListElem from APER format.
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnosticsIEListElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	padding, err := q5.CaptureFinalBits(bb, "CriticalityDiagnosticsIEListElem")
	if err != nil {
		return q10.WrapDecodePath(err, "CriticalityDiagnosticsIEListElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CriticalityDiagnosticsIEListElem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEListElem{}
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
	val_iecriticality, err := q5.DecodeEnumeratedAligned(bb, 3, false, q5.EnumerationSource{KnownExtensions: 0, Path: "IECriticality"})
	if err != nil {
		return q10.WrapDecodePath(err, "IECriticality")
	}
	v.IECriticality = q6.Criticality(val_iecriticality)
	val_ieid, err := q5.DecodeIntegerAligned(bb, q9.BridgeInt64Ptr(0), q9.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q10.WrapDecodePath(err, "IEID")
	}
	v.IEID = q6.ProtocolIEID(val_ieid)
	val_typeoferror, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
	if err != nil {
		return q10.WrapDecodePath(err, "TypeOfError")
	}
	v.TypeOfError = q6.TypeOfError(val_typeoferror)
	if opt_ieextensions {
		tmp_ieextensions := make(q9.CriticalityDiagnosticsIEListExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q7.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.CriticalityDiagnosticsIEListExtIEsExtField
				if err := q9.BridgeCriticalityDiagnosticsIEListExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q10.WrapDecodePath(err, q7.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q10.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "ExtData_")
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
					return q10.WrapDecodePath(err, q7.Sprintf("ExtData_[%d]", i))
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
func (v *AssistanceInformationFailureListElem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFailureListElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFailureListElem) WithoutReplay() AssistanceInformationFailureListElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero AssistanceInformationFailureListElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationMetaData) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationMetaData", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationMetaData) WithoutReplay() AssistanceInformationMetaData {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero AssistanceInformationMetaData
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BitmapsforNPRS) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "BitmapsforNPRS", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BitmapsforNPRS) WithoutReplay() BitmapsforNPRS {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero BitmapsforNPRS
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cause) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "Cause", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cause) WithoutReplay() Cause {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero Cause
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEListElem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEListElem) WithoutReplay() CriticalityDiagnosticsIEListElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero CriticalityDiagnosticsIEListElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECGI) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return BridgeReceivedFormAt(v.received, v.receivedBytes, "ECGI", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECGI) WithoutReplay() ECGI {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero ECGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationFailureListElem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationFailureListElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationFailureListElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("AssistanceInformationFailureListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationMetaData) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationMetaData) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationMetaData) RemoveExtension(index uint64) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("AssistanceInformationMetaData.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnosticsIEListElem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnosticsIEListElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnosticsIEListElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("CriticalityDiagnosticsIEListElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ECGI) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("ECGI.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("ECGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECGI) RemoveExtension(index uint64) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q7.Sprintf("ECGI.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q10.WrapDecodePath(err, q7.Sprintf("ECGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *AssistanceInformationFailureListElem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationFailureListElem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "AssistanceInformationFailureListElem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFailureListElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "AssistanceInformationFailureListElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "AssistanceInformationFailureListElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "AssistanceInformationFailureListElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "AssistanceInformationFailureListElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "AssistanceInformationFailureListElem")
}
func (v *AssistanceInformationFailureListElem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFailureListElem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFailureListElem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *AssistanceInformationFailureListElem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFailureListElem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationMetaData) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationMetaData")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "AssistanceInformationMetaData")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationMetaData(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "AssistanceInformationMetaData")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "AssistanceInformationMetaData")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "AssistanceInformationMetaData")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "AssistanceInformationMetaData")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "AssistanceInformationMetaData")
}
func (v *AssistanceInformationMetaData) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationMetaData) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationMetaData) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *AssistanceInformationMetaData) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationMetaData) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *BitmapsforNPRS) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "BitmapsforNPRS")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "BitmapsforNPRS")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaBitmapsforNPRS(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "BitmapsforNPRS")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "BitmapsforNPRS")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "BitmapsforNPRS")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "BitmapsforNPRS")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "BitmapsforNPRS")
}
func (v *BitmapsforNPRS) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *BitmapsforNPRS) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *BitmapsforNPRS) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *BitmapsforNPRS) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *BitmapsforNPRS) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *Cause) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "Cause")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "Cause")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaCause(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "Cause")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "Cause")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "Cause")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "Cause")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *Cause) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *Cause) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *Cause) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *Cause) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *CriticalityDiagnosticsIEListElem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "CriticalityDiagnosticsIEListElem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *CriticalityDiagnosticsIEListElem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnosticsIEListElem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECGI) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "ECGI")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "ECGI")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaECGI(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "ECGI")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "ECGI")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "ECGI")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "ECGI")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "ECGI")
}
func (v *ECGI) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECGI) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECGI) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *ECGI) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECGI) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationFailureListElem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationFailureListElem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFailureListElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFailureListElem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFailureListElem{}
		return report, q5.OperationError(err, "AssistanceInformationFailureListElem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "AssistanceInformationFailureListElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AssistanceInformationMetaData) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "AssistanceInformationMetaData")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationMetaData
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationMetaData(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationMetaData{}
		return report, q5.OperationError(err, "AssistanceInformationMetaData")
	}
	*v = decoded
	return report, q5.OperationError(nil, "AssistanceInformationMetaData")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *BitmapsforNPRS) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "BitmapsforNPRS")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded BitmapsforNPRS
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaBitmapsforNPRS(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = BitmapsforNPRS{}
		return report, q5.OperationError(err, "BitmapsforNPRS")
	}
	*v = decoded
	return report, q5.OperationError(nil, "BitmapsforNPRS")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *Cause) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "Cause")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded Cause
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCause(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = Cause{}
		return report, q5.OperationError(err, "Cause")
	}
	*v = decoded
	return report, q5.OperationError(nil, "Cause")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *CriticalityDiagnosticsIEListElem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "CriticalityDiagnosticsIEListElem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnosticsIEListElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEListElem{}
		return report, q5.OperationError(err, "CriticalityDiagnosticsIEListElem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "CriticalityDiagnosticsIEListElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ECGI) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "ECGI")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded ECGI
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECGI(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = ECGI{}
		return report, q5.OperationError(err, "ECGI")
	}
	*v = decoded
	return report, q5.OperationError(nil, "ECGI")
}
func BridgeCaptureLPPaAssistanceInformationFailureListElem(v *AssistanceInformationFailureListElem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q6.BridgeCaptureLPPaPosSIBType(&v.PosSIBType, s)
	q6.BridgeCaptureLPPaOutcome(&v.Outcome, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeAssistanceInformationFailureListExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFailureListElem(v *AssistanceInformationFailureListElem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaPosSIBType(&v.PosSIBType, s)
	q8.BridgeCompareLPPaOutcome(&v.Outcome, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeAssistanceInformationFailureListExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationMetaData(v *AssistanceInformationMetaData, s *q5.SemanticCapture) {
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
	q4.BridgeAssistanceInformationMetaDataExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationMetaData(v *AssistanceInformationMetaData, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.GNSSID == nil)
		if v.GNSSID != nil {
			s.Int(int64((*v.GNSSID)))
		}
		s.End(f, q5.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SBASID == nil)
		if v.SBASID != nil {
			s.Int(int64((*v.SBASID)))
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	q4.BridgeAssistanceInformationMetaDataExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaBitmapsforNPRS(v *BitmapsforNPRS, s *q5.SemanticCapture) {
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
	case q6.BitmapsforNPRSChoiceTen:
		{
			f := s.Begin()
			s.Bool(v.Ten == nil)
			if v.Ten != nil {
				s.BitString((*v.Ten).Bytes, (*v.Ten).BitLength)
			}
			s.End(f, nil, false)
		}
	case q6.BitmapsforNPRSChoiceForty:
		{
			f := s.Begin()
			s.Bool(v.Forty == nil)
			if v.Forty != nil {
				s.BitString((*v.Forty).Bytes, (*v.Forty).BitLength)
			}
			s.End(f, nil, false)
		}
	case q6.BitmapsforNPRSChoiceTenTdd:
		{
			f := s.Begin()
			s.Bool(v.TenTdd == nil)
			if v.TenTdd != nil {
				s.BitString((*v.TenTdd).Bytes, (*v.TenTdd).BitLength)
			}
			s.End(f, nil, false)
		}
	case q6.BitmapsforNPRSChoiceFortyTdd:
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
func BridgeCompareLPPaBitmapsforNPRS(v *BitmapsforNPRS, s *q5.SemanticComparison) {
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
	case q6.BitmapsforNPRSChoiceTen:
		{
			f := s.Begin()
			s.Bool(v.Ten == nil)
			if v.Ten != nil {
				s.BitString((*v.Ten).Bytes, (*v.Ten).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.BitmapsforNPRSChoiceForty:
		{
			f := s.Begin()
			s.Bool(v.Forty == nil)
			if v.Forty != nil {
				s.BitString((*v.Forty).Bytes, (*v.Forty).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.BitmapsforNPRSChoiceTenTdd:
		{
			f := s.Begin()
			s.Bool(v.TenTdd == nil)
			if v.TenTdd != nil {
				s.BitString((*v.TenTdd).Bytes, (*v.TenTdd).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.BitmapsforNPRSChoiceFortyTdd:
		{
			f := s.Begin()
			s.Bool(v.FortyTdd == nil)
			if v.FortyTdd != nil {
				s.BitString((*v.FortyTdd).Bytes, (*v.FortyTdd).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCause(v *Cause, s *q5.SemanticCapture) {
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
	case q6.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				q6.BridgeCaptureLPPaCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, nil, false)
		}
	case q6.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				q6.BridgeCaptureLPPaCauseProtocol(v.Protocol, s)
			}
			s.End(f, nil, false)
		}
	case q6.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				q6.BridgeCaptureLPPaCauseMisc(v.Misc, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCause(v *Cause, s *q5.SemanticComparison) {
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
	case q6.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				q8.BridgeCompareLPPaCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				q8.BridgeCompareLPPaCauseProtocol(v.Protocol, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q6.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				q8.BridgeCompareLPPaCauseMisc(v.Misc, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(v *CriticalityDiagnosticsIEListElem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q6.BridgeCaptureLPPaCriticality(&v.IECriticality, s)
	q6.BridgeCaptureLPPaProtocolIEID(&v.IEID, s)
	q6.BridgeCaptureLPPaTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeCriticalityDiagnosticsIEListExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListElem(v *CriticalityDiagnosticsIEListElem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaCriticality(&v.IECriticality, s)
	q8.BridgeCompareLPPaProtocolIEID(&v.IEID, s)
	q9.BridgeCompareLPPaTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeCriticalityDiagnosticsIEListExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECGI(v *ECGI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q6.BridgeCaptureLPPaPLMNIdentity(&v.PLMNIdentity, s)
	q6.BridgeCaptureLPPaEUTRANCellIdentifier(&v.EUTRANcellIdentifier, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeECGIExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECGI(v *ECGI, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaPLMNIdentity(&v.PLMNIdentity, s)
	q8.BridgeCompareLPPaEUTRANCellIdentifier(&v.EUTRANcellIdentifier, s)
	s.Bool(v.IEExtensions == nil)
	q4.BridgeECGIExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
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
func BridgeReceivedFormAt(present bool, original q5.WireSpan, path q5.Path, location q5.Location, complete interface{ Bits() (uint8, uint8) }) q5.ReceivedForm {
	location.Path = path
	var padding []q5.PaddingSpan
	if location.HasWireLocation && len(location.Spans) != 0 {
		last := location.Spans[len(location.Spans)-1]
		value, count := complete.Bits()
		width, borrow := q11.Sub64(last.End, last.Start, 0)
		if count != 0 && borrow == 0 && uint64(count) <= width {
			start, borrow := q11.Sub64(last.End, uint64(count), 0)
			if borrow == 0 {
				padding = []q5.PaddingSpan{{Span: q5.BitSpan{Start: start, End: last.End}, Value: value, Width: count}}
			}
		}
	}
	return q5.NewReceivedSpanForm(present, original, location, padding)
}

// AssistanceInformationFailureListElemCodec binds the complete source value type.
func AssistanceInformationFailureListElemCodec() AssistanceInformationFailureListElemValueCodec {
	return AssistanceInformationFailureListElemValueCodec{path: "AssistanceInformationFailureListElem", decode: func(data []byte, options q5.DecodeState) (AssistanceInformationFailureListElem, error) {
		var value AssistanceInformationFailureListElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceInformationFailureListElem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceInformationFailureListElem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceInformationFailureListElem, options q5.DecodeState) (AssistanceInformationFailureListElem, q5.Snapshot,
	) {
		s := q5.SemanticCaptureFor(options)
		f := s.
			Begin()
		BridgeCaptureLPPaAssistanceInformationFailureListElem(&v,
			&s,
		)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f,
			&root, false)
		return v, root
	}, compare: func(v AssistanceInformationFailureListElem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAssistanceInformationFailureListElem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFailureListElem"
		return sealed
	}(),
	}
}

// AssistanceInformationMetaDataCodec binds the complete source value type.
func AssistanceInformationMetaDataCodec() AssistanceInformationMetaDataValueCodec {
	return AssistanceInformationMetaDataValueCodec{path: "AssistanceInformationMetaData", decode: func(data []byte, options q5.DecodeState) (AssistanceInformationMetaData, error) {
		var value AssistanceInformationMetaData
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceInformationMetaData{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceInformationMetaData, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceInformationMetaData, options q5.DecodeState) (AssistanceInformationMetaData, q5.Snapshot,

	) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaAssistanceInformationMetaData(&v, &s)
		var root q5.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v AssistanceInformationMetaData, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaAssistanceInformationMetaData(&v, &s)
		s.End(f, root, false)

		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationMetaData"
		return sealed
	}(),
	}
}

// BitmapsforNPRSCodec binds the complete source value type.
func BitmapsforNPRSCodec() BitmapsforNPRSValueCodec {
	return BitmapsforNPRSValueCodec{path: "BitmapsforNPRS", decode: func(data []byte, options q5.DecodeState) (BitmapsforNPRS, error) {
		var value BitmapsforNPRS
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return BitmapsforNPRS{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value BitmapsforNPRS, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v BitmapsforNPRS, options q5.DecodeState) (BitmapsforNPRS, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaBitmapsforNPRS(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v BitmapsforNPRS, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaBitmapsforNPRS(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:BitmapsforNPRS"
		return sealed
	}(),
	}
}

// CriticalityDiagnosticsIEListElemCodec binds the complete source value type.
func CriticalityDiagnosticsIEListElemCodec() CriticalityDiagnosticsIEListElemValueCodec {
	return CriticalityDiagnosticsIEListElemValueCodec{path: "CriticalityDiagnosticsIEListElem", decode: func(data []byte, options q5.DecodeState) (CriticalityDiagnosticsIEListElem, error) {
		var value CriticalityDiagnosticsIEListElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CriticalityDiagnosticsIEListElem{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value CriticalityDiagnosticsIEListElem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CriticalityDiagnosticsIEListElem, options q5.DecodeState) (CriticalityDiagnosticsIEListElem, q5.Snapshot,
	) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&v, &s)
		var root q5.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)

		return v, root
	}, compare: func(v CriticalityDiagnosticsIEListElem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaCriticalityDiagnosticsIEListElem(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEListElem"
		return sealed
	}(),
	}
}

// ECGICodec binds the complete source value type.
func ECGICodec() ECGIValueCodec {
	return ECGIValueCodec{path: "ECGI", decode: func(data []byte, options q5.DecodeState) (ECGI, error) {
		var value ECGI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ECGI{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value ECGI, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ECGI, options q5.DecodeState) (ECGI, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaECGI(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ECGI, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root,
			limits)
		f := s.Begin()
		BridgeCompareLPPaECGI(&v, &s)
		s.End(f,
			root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:ECGI"
		return sealed
	}(),
	}
}
func BridgeAssistanceInformationFailureListAPERValueFieldContext(v *AssistanceInformationFailureListAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListAPERValueFieldReceived(v *AssistanceInformationFailureListAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListAPERValueFieldReplay(v *AssistanceInformationFailureListAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListAPERValueFieldWithoutReplay(v *AssistanceInformationFailureListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldContext(v *AssistanceInformationFailureListElemAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldReceived(v *AssistanceInformationFailureListElemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListElemAPERValueFieldReplay(v *AssistanceInformationFailureListElemAPERValue) *q5.Snapshot {
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
func BridgeAssistanceInformationFailureListElemFieldExtOrigin(v *AssistanceInformationFailureListElem) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFailureListElemFieldExtPresent(v *AssistanceInformationFailureListElem) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFailureListElemFieldExtWire(v *AssistanceInformationFailureListElem) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFailureListElemFieldIEExtensionsIndef(v *AssistanceInformationFailureListElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationFailureListElemFieldPerExtPadding(v *AssistanceInformationFailureListElem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFailureListElemFieldPerPadding(v *AssistanceInformationFailureListElem) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFailureListElemFieldReceived(v *AssistanceInformationFailureListElem) *bool {
	return &v.received
}
func BridgeAssistanceInformationFailureListElemFieldReceivedBytes(v *AssistanceInformationFailureListElem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFailureListElemFieldReplay(v *AssistanceInformationFailureListElem) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListElemFieldStream(v *AssistanceInformationFailureListElem) *q5.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListElemFieldWithoutReplay(v *AssistanceInformationFailureListElem) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERBudget(v *AssistanceInformationFailureListElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERChanged(v *AssistanceInformationFailureListElem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERChangedValue(v *AssistanceInformationFailureListElem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERFreshValue(v *AssistanceInformationFailureListElem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERLegacy(v *AssistanceInformationFailureListElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERPlanned(v *AssistanceInformationFailureListElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFailureListElemMethodMarshalAPERTo(v *AssistanceInformationFailureListElem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERFrom(v *AssistanceInformationFailureListElem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERLegacy(v *AssistanceInformationFailureListElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERWithOptions(v *AssistanceInformationFailureListElem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldCapture(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, q5.DecodeState) (AssistanceInformationFailureListElem, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldCompare(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldContext(v *AssistanceInformationFailureListElemValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldDecode(v *AssistanceInformationFailureListElemValueCodec) *func([]byte, q5.DecodeState) (AssistanceInformationFailureListElem, error) {
	return &v.decode
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldEncode(v *AssistanceInformationFailureListElemValueCodec) *func(AssistanceInformationFailureListElem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFailureListElemValueCodecFieldPath(v *AssistanceInformationFailureListElemValueCodec) *q5.Path {
	return &v.path
}
func BridgeAssistanceInformationFailureListElemValueCodecMethodEncodeBudget(v AssistanceInformationFailureListElemValueCodec, a0 AssistanceInformationFailureListElem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListElemValueCodecMethodEncodeChanged(v AssistanceInformationFailureListElemValueCodec, a0 AssistanceInformationFailureListElem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationFailureListValueCodecFieldCapture(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, q5.DecodeState) (AssistanceInformationFailureList, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFailureListValueCodecFieldCompare(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFailureListValueCodecFieldContext(v *AssistanceInformationFailureListValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFailureListValueCodecFieldDecode(v *AssistanceInformationFailureListValueCodec) *func([]byte, q5.DecodeState) (AssistanceInformationFailureList, error) {
	return &v.decode
}
func BridgeAssistanceInformationFailureListValueCodecFieldEncode(v *AssistanceInformationFailureListValueCodec) *func(AssistanceInformationFailureList, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFailureListValueCodecFieldPath(v *AssistanceInformationFailureListValueCodec) *q5.Path {
	return &v.path
}
func BridgeAssistanceInformationFailureListValueCodecMethodEncodeBudget(v AssistanceInformationFailureListValueCodec, a0 AssistanceInformationFailureList, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListValueCodecMethodEncodeChanged(v AssistanceInformationFailureListValueCodec, a0 AssistanceInformationFailureList, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeAssistanceInformationMetaDataAPERValueFieldContext(v *AssistanceInformationMetaDataAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationMetaDataAPERValueFieldReceived(v *AssistanceInformationMetaDataAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationMetaDataAPERValueFieldReplay(v *AssistanceInformationMetaDataAPERValue) *q5.Snapshot {
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
func BridgeAssistanceInformationMetaDataFieldExtOrigin(v *AssistanceInformationMetaData) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationMetaDataFieldExtPresent(v *AssistanceInformationMetaData) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationMetaDataFieldExtWire(v *AssistanceInformationMetaData) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationMetaDataFieldIEExtensionsIndef(v *AssistanceInformationMetaData) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationMetaDataFieldPerExtPadding(v *AssistanceInformationMetaData) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationMetaDataFieldPerPadding(v *AssistanceInformationMetaData) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationMetaDataFieldReceived(v *AssistanceInformationMetaData) *bool {
	return &v.received
}
func BridgeAssistanceInformationMetaDataFieldReceivedBytes(v *AssistanceInformationMetaData) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationMetaDataFieldReplay(v *AssistanceInformationMetaData) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataFieldStream(v *AssistanceInformationMetaData) *q5.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationMetaDataFieldWithoutReplay(v *AssistanceInformationMetaData) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERBudget(v *AssistanceInformationMetaData, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERChanged(v *AssistanceInformationMetaData, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERChangedValue(v *AssistanceInformationMetaData, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERFreshValue(v *AssistanceInformationMetaData, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERLegacy(v *AssistanceInformationMetaData) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERPlanned(v *AssistanceInformationMetaData, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationMetaDataMethodMarshalAPERTo(v *AssistanceInformationMetaData, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERFrom(v *AssistanceInformationMetaData, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERLegacy(v *AssistanceInformationMetaData, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationMetaDataMethodUnmarshalAPERWithOptions(v *AssistanceInformationMetaData, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationMetaDataValueCodecFieldCapture(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, q5.DecodeState) (AssistanceInformationMetaData, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationMetaDataValueCodecFieldCompare(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationMetaDataValueCodecFieldContext(v *AssistanceInformationMetaDataValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationMetaDataValueCodecFieldDecode(v *AssistanceInformationMetaDataValueCodec) *func([]byte, q5.DecodeState) (AssistanceInformationMetaData, error) {
	return &v.decode
}
func BridgeAssistanceInformationMetaDataValueCodecFieldEncode(v *AssistanceInformationMetaDataValueCodec) *func(AssistanceInformationMetaData, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationMetaDataValueCodecFieldPath(v *AssistanceInformationMetaDataValueCodec) *q5.Path {
	return &v.path
}
func BridgeAssistanceInformationMetaDataValueCodecMethodEncodeBudget(v AssistanceInformationMetaDataValueCodec, a0 AssistanceInformationMetaData, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationMetaDataValueCodecMethodEncodeChanged(v AssistanceInformationMetaDataValueCodec, a0 AssistanceInformationMetaData, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBitmapsforNPRSAPERValueFieldContext(v *BitmapsforNPRSAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeBitmapsforNPRSAPERValueFieldReceived(v *BitmapsforNPRSAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeBitmapsforNPRSAPERValueFieldReplay(v *BitmapsforNPRSAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeBitmapsforNPRSAPERValueFieldWithoutReplay(v *BitmapsforNPRSAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBitmapsforNPRSFieldKnownOpenBytes(v *BitmapsforNPRS) *uint64 { return &v.knownOpenBytes }
func BridgeBitmapsforNPRSFieldPerOpenTypePadding(v *BitmapsforNPRS) *q5.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeBitmapsforNPRSFieldPerPadding(v *BitmapsforNPRS) *q5.CompletePadding { return &v.perPadding }
func BridgeBitmapsforNPRSFieldReceived(v *BitmapsforNPRS) *bool                 { return &v.received }
func BridgeBitmapsforNPRSFieldReceivedBytes(v *BitmapsforNPRS) *q5.WireSpan     { return &v.receivedBytes }
func BridgeBitmapsforNPRSFieldReplay(v *BitmapsforNPRS) *q5.Snapshot            { return &v.replay }
func BridgeBitmapsforNPRSFieldStream(v *BitmapsforNPRS) *q5.WireSpan            { return &v.stream }
func BridgeBitmapsforNPRSFieldWithoutReplay(v *BitmapsforNPRS) *bool            { return &v.withoutReplay }
func BridgeBitmapsforNPRSMethodMarshalAPERBudget(v *BitmapsforNPRS, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERChanged(v *BitmapsforNPRS, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBitmapsforNPRSMethodMarshalAPERChangedValue(v *BitmapsforNPRS, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBitmapsforNPRSMethodMarshalAPERFreshValue(v *BitmapsforNPRS, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERLegacy(v *BitmapsforNPRS) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBitmapsforNPRSMethodMarshalAPERPlanned(v *BitmapsforNPRS, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeBitmapsforNPRSMethodMarshalAPERTo(v *BitmapsforNPRS, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERFrom(v *BitmapsforNPRS, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERLegacy(v *BitmapsforNPRS, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBitmapsforNPRSMethodUnmarshalAPERWithOptions(v *BitmapsforNPRS, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBitmapsforNPRSValueCodecFieldCapture(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, q5.DecodeState) (BitmapsforNPRS, q5.Snapshot) {
	return &v.capture
}
func BridgeBitmapsforNPRSValueCodecFieldCompare(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeBitmapsforNPRSValueCodecFieldContext(v *BitmapsforNPRSValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeBitmapsforNPRSValueCodecFieldDecode(v *BitmapsforNPRSValueCodec) *func([]byte, q5.DecodeState) (BitmapsforNPRS, error) {
	return &v.decode
}
func BridgeBitmapsforNPRSValueCodecFieldEncode(v *BitmapsforNPRSValueCodec) *func(BitmapsforNPRS, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBitmapsforNPRSValueCodecFieldPath(v *BitmapsforNPRSValueCodec) *q5.Path { return &v.path }
func BridgeBitmapsforNPRSValueCodecMethodEncodeBudget(v BitmapsforNPRSValueCodec, a0 BitmapsforNPRS, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBitmapsforNPRSValueCodecMethodEncodeChanged(v BitmapsforNPRSValueCodec, a0 BitmapsforNPRS, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseAPERValueFieldContext(v *CauseAPERValue) *q6.BridgeCodecContext { return &v.context }
func BridgeCauseAPERValueFieldReceived(v *CauseAPERValue) *q5.WireSpan          { return &v.received }
func BridgeCauseAPERValueFieldReplay(v *CauseAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeCauseAPERValueFieldWithoutReplay(v *CauseAPERValue) *bool            { return &v.withoutReplay }
func BridgeCauseFieldKnownOpenBytes(v *Cause) *uint64                           { return &v.knownOpenBytes }
func BridgeCauseFieldPerOpenTypePadding(v *Cause) *q5.CompletePadding           { return &v.perOpenTypePadding }
func BridgeCauseFieldPerPadding(v *Cause) *q5.CompletePadding                   { return &v.perPadding }
func BridgeCauseFieldReceived(v *Cause) *bool                                   { return &v.received }
func BridgeCauseFieldReceivedBytes(v *Cause) *q5.WireSpan                       { return &v.receivedBytes }
func BridgeCauseFieldReplay(v *Cause) *q5.Snapshot                              { return &v.replay }
func BridgeCauseFieldStream(v *Cause) *q5.WireSpan                              { return &v.stream }
func BridgeCauseFieldWithoutReplay(v *Cause) *bool                              { return &v.withoutReplay }
func BridgeCauseMethodMarshalAPERBudget(v *Cause, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCauseMethodMarshalAPERChanged(v *Cause, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERChangedValue(v *Cause, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCauseMethodMarshalAPERFreshValue(v *Cause, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCauseMethodMarshalAPERLegacy(v *Cause) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeCauseMethodMarshalAPERPlanned(v *Cause, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCauseMethodMarshalAPERTo(v *Cause, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCauseMethodUnmarshalAPERFrom(v *Cause, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCauseMethodUnmarshalAPERLegacy(v *Cause, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCauseMethodUnmarshalAPERWithOptions(v *Cause, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCauseValueCodecFieldCapture(v *CauseValueCodec) *func(Cause, q5.DecodeState) (Cause, q5.Snapshot) {
	return &v.capture
}
func BridgeCauseValueCodecFieldCompare(v *CauseValueCodec) *func(Cause, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCauseValueCodecFieldContext(v *CauseValueCodec) *q6.BridgeCodecContext { return &v.context }
func BridgeCauseValueCodecFieldDecode(v *CauseValueCodec) *func([]byte, q5.DecodeState) (Cause, error) {
	return &v.decode
}
func BridgeCauseValueCodecFieldEncode(v *CauseValueCodec) *func(Cause, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseValueCodecFieldPath(v *CauseValueCodec) *q5.Path { return &v.path }
func BridgeCauseValueCodecMethodEncodeBudget(v CauseValueCodec, a0 Cause, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCauseValueCodecMethodEncodeChanged(v CauseValueCodec, a0 Cause, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldContext(v *CriticalityDiagnosticsIEListAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReceived(v *CriticalityDiagnosticsIEListAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldReplay(v *CriticalityDiagnosticsIEListAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldContext(v *CriticalityDiagnosticsIEListElemAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldReceived(v *CriticalityDiagnosticsIEListElemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListElemAPERValueFieldReplay(v *CriticalityDiagnosticsIEListElemAPERValue) *q5.Snapshot {
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
func BridgeCriticalityDiagnosticsIEListElemFieldExtOrigin(v *CriticalityDiagnosticsIEListElem) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtPresent(v *CriticalityDiagnosticsIEListElem) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsIEListElemFieldExtWire(v *CriticalityDiagnosticsIEListElem) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeCriticalityDiagnosticsIEListElemFieldIEExtensionsIndef(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCriticalityDiagnosticsIEListElemFieldPerExtPadding(v *CriticalityDiagnosticsIEListElem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeCriticalityDiagnosticsIEListElemFieldPerPadding(v *CriticalityDiagnosticsIEListElem) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsIEListElemFieldReceived(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListElemFieldReceivedBytes(v *CriticalityDiagnosticsIEListElem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsIEListElemFieldReplay(v *CriticalityDiagnosticsIEListElem) *q5.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListElemFieldStream(v *CriticalityDiagnosticsIEListElem) *q5.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListElemFieldWithoutReplay(v *CriticalityDiagnosticsIEListElem) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERBudget(v *CriticalityDiagnosticsIEListElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERChanged(v *CriticalityDiagnosticsIEListElem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERChangedValue(v *CriticalityDiagnosticsIEListElem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERFreshValue(v *CriticalityDiagnosticsIEListElem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERLegacy(v *CriticalityDiagnosticsIEListElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERPlanned(v *CriticalityDiagnosticsIEListElem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(v *CriticalityDiagnosticsIEListElem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEListElem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERLegacy(v *CriticalityDiagnosticsIEListElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERWithOptions(v *CriticalityDiagnosticsIEListElem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldCapture(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, q5.DecodeState) (CriticalityDiagnosticsIEListElem, q5.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldCompare(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldContext(v *CriticalityDiagnosticsIEListElemValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldDecode(v *CriticalityDiagnosticsIEListElemValueCodec) *func([]byte, q5.DecodeState) (CriticalityDiagnosticsIEListElem, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldEncode(v *CriticalityDiagnosticsIEListElemValueCodec) *func(CriticalityDiagnosticsIEListElem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecFieldPath(v *CriticalityDiagnosticsIEListElemValueCodec) *q5.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecMethodEncodeBudget(v CriticalityDiagnosticsIEListElemValueCodec, a0 CriticalityDiagnosticsIEListElem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListElemValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEListElemValueCodec, a0 CriticalityDiagnosticsIEListElem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, q5.DecodeState) (CriticalityDiagnosticsIEList, q5.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(v *CriticalityDiagnosticsIEListValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(v *CriticalityDiagnosticsIEListValueCodec) *func([]byte, q5.DecodeState) (CriticalityDiagnosticsIEList, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(v *CriticalityDiagnosticsIEListValueCodec) *q5.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeBudget(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListValueCodecMethodEncodeChanged(v CriticalityDiagnosticsIEListValueCodec, a0 CriticalityDiagnosticsIEList, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECGIAPERValueFieldContext(v *ECGIAPERValue) *q6.BridgeCodecContext { return &v.context }
func BridgeECGIAPERValueFieldReceived(v *ECGIAPERValue) *q5.WireSpan          { return &v.received }
func BridgeECGIAPERValueFieldReplay(v *ECGIAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeECGIAPERValueFieldWithoutReplay(v *ECGIAPERValue) *bool            { return &v.withoutReplay }
func BridgeECGIFieldExtCount(v *ECGI) *int64                                  { return &v.extCount }
func BridgeECGIFieldExtData(v *ECGI) *[][]byte                                { return &v.extData }
func BridgeECGIFieldExtOrigin(v *ECGI) *[]q5.OpaqueOrigin                     { return &v.extOrigin }
func BridgeECGIFieldExtPresent(v *ECGI) *[]bool                               { return &v.extPresent }
func BridgeECGIFieldExtWire(v *ECGI) *[]q5.WireSpan                           { return &v.extWire }
func BridgeECGIFieldIEExtensionsIndef(v *ECGI) *bool                          { return &v.iEExtensionsIndef }
func BridgeECGIFieldPerExtPadding(v *ECGI) *[]q5.CompletePadding              { return &v.perExtPadding }
func BridgeECGIFieldPerPadding(v *ECGI) *q5.FinalPadding                      { return &v.perPadding }
func BridgeECGIFieldReceived(v *ECGI) *bool                                   { return &v.received }
func BridgeECGIFieldReceivedBytes(v *ECGI) *q5.WireSpan                       { return &v.receivedBytes }
func BridgeECGIFieldReplay(v *ECGI) *q5.Snapshot                              { return &v.replay }
func BridgeECGIFieldStream(v *ECGI) *q5.WireSpan                              { return &v.stream }
func BridgeECGIFieldWithoutReplay(v *ECGI) *bool                              { return &v.withoutReplay }
func BridgeECGIMethodMarshalAPERBudget(v *ECGI, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECGIMethodMarshalAPERChanged(v *ECGI, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECGIMethodMarshalAPERChangedValue(v *ECGI, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECGIMethodMarshalAPERFreshValue(v *ECGI, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECGIMethodMarshalAPERLegacy(v *ECGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeECGIMethodMarshalAPERPlanned(v *ECGI, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECGIMethodMarshalAPERTo(v *ECGI, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECGIMethodUnmarshalAPERFrom(v *ECGI, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECGIMethodUnmarshalAPERLegacy(v *ECGI, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeECGIMethodUnmarshalAPERWithOptions(v *ECGI, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECGIValueCodecFieldCapture(v *ECGIValueCodec) *func(ECGI, q5.DecodeState) (ECGI, q5.Snapshot) {
	return &v.capture
}
func BridgeECGIValueCodecFieldCompare(v *ECGIValueCodec) *func(ECGI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECGIValueCodecFieldContext(v *ECGIValueCodec) *q6.BridgeCodecContext { return &v.context }
func BridgeECGIValueCodecFieldDecode(v *ECGIValueCodec) *func([]byte, q5.DecodeState) (ECGI, error) {
	return &v.decode
}
func BridgeECGIValueCodecFieldEncode(v *ECGIValueCodec) *func(ECGI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECGIValueCodecFieldPath(v *ECGIValueCodec) *q5.Path { return &v.path }
func BridgeECGIValueCodecMethodEncodeBudget(v ECGIValueCodec, a0 ECGI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECGIValueCodecMethodEncodeChanged(v ECGIValueCodec, a0 ECGI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
