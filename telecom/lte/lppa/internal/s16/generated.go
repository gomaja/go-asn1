// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s16 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s16

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
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
)

// ECIDMeasurementInitiationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s11.ECIDMeasurementInitiationFailure, aper.DecodeState,

	) (s11.ECIDMeasurementInitiationFailure, aper.Snapshot,

	)
	compare func(s11.ECIDMeasurementInitiationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s11.ECIDMeasurementInitiationFailure,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s11.ECIDMeasurementInitiationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s11.ECIDMeasurementInitiationFailure,

		error)
	inject func(s11.ECIDMeasurementInitiationFailure,

	) UnsuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Codec() s11.ECIDMeasurementInitiationFailureValueCodec {
	return func() s11.ECIDMeasurementInitiationFailureValueCodec {
		sealed := s11.ECIDMeasurementInitiationFailureValueCodec{}
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldDecode(&sealed) = b.decode
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldEncode(&sealed) = func(value s11.ECIDMeasurementInitiationFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldCapture(&sealed) = b.capture
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldCompare(&sealed) = b.compare
		*s11.BridgeECIDMeasurementInitiationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Build(body s11.ECIDMeasurementInitiationFailure,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// OTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[OTDOAInformationFailure].
type OTDOAInformationFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s12.OTDOAInformationFailure, aper.DecodeState,

	) (s12.OTDOAInformationFailure, aper.Snapshot,

	)
	compare func(s12.OTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s12.OTDOAInformationFailure,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s12.OTDOAInformationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s12.OTDOAInformationFailure,

		error)
	inject func(s12.OTDOAInformationFailure,

	) UnsuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationFailureUnsuccessfulBinding) Codec() s12.OTDOAInformationFailureValueCodec {
	return func() s12.OTDOAInformationFailureValueCodec {
		sealed := s12.OTDOAInformationFailureValueCodec{}
		*s12.BridgeOTDOAInformationFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s12.BridgeOTDOAInformationFailureValueCodecFieldDecode(&sealed) = b.decode
		*s12.BridgeOTDOAInformationFailureValueCodecFieldEncode(&sealed) = func(value s12.OTDOAInformationFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s12.BridgeOTDOAInformationFailureValueCodecFieldCapture(&sealed) = b.capture
		*s12.BridgeOTDOAInformationFailureValueCodecFieldCompare(&sealed) = b.compare
		*s12.BridgeOTDOAInformationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b OTDOAInformationFailureUnsuccessfulBinding) Build(body s12.OTDOAInformationFailure,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UTDOAInformationFailure].
type UTDOAInformationFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(UTDOAInformationFailure, aper.DecodeState,

	) (UTDOAInformationFailure, aper.Snapshot,

	)
	compare func(UTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*UTDOAInformationFailure,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*UTDOAInformationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (UTDOAInformationFailure,

		error)
	inject func(UTDOAInformationFailure,

	) UnsuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationFailureUnsuccessfulBinding) Codec() UTDOAInformationFailureValueCodec {
	return UTDOAInformationFailureValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value UTDOAInformationFailure,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b UTDOAInformationFailureUnsuccessfulBinding) Build(body UTDOAInformationFailure,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(v *s10.UTDOAInformationFailureIEContainer, s *aper.SemanticCapture) {
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
			BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(v *s10.UTDOAInformationFailureIEContainer, s *aper.SemanticComparison) {
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
			BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(v *s09.UTDOAInformationRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(v *s09.UTDOAInformationRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(v *s10.UTDOAInformationResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(v *s10.UTDOAInformationResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// OTDOACellsValueCodec is the concrete ValueCodec[OTDOACells].
type OTDOACellsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOACells, aper.DecodeState,

	) (OTDOACells, aper.Snapshot,

	)
	compare func(OTDOACells, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOACells,

		error)
	encode func(OTDOACells,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOACellsValueCodec) New(value OTDOACells,

) (OTDOACellsAPERValue, error) {
	if c.encode == nil {
		return OTDOACellsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOACellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOACellsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOACellsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOACellsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOACellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOACellsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOACellsValueCodec) EncodeAPER(value OTDOACellsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOACellsValueCodec) encodeBudget(value OTDOACells,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellsValueCodec) encodeChanged(value OTDOACells,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOACellsElemValueCodec is the concrete ValueCodec[OTDOACellsElem].
type OTDOACellsElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOACellsElem, aper.DecodeState,

	) (OTDOACellsElem, aper.Snapshot,

	)
	compare func(OTDOACellsElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOACellsElem,

		error)
	encode func(OTDOACellsElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOACellsElemValueCodec) New(value OTDOACellsElem,

) (OTDOACellsElemAPERValue, error) {
	if c.encode == nil {
		return OTDOACellsElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOACellsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOACellsElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOACellsElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOACellsElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOACellsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOACellsElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOACellsElemValueCodec) EncodeAPER(value OTDOACellsElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOACellsElemValueCodec) encodeBudget(value OTDOACellsElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellsElemValueCodec) encodeChanged(value OTDOACellsElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTDOAInformationFailureValueCodec is the concrete ValueCodec[UTDOAInformationFailure].
type UTDOAInformationFailureValueCodec struct {
	context s00.BridgeCodecContext
	capture func(UTDOAInformationFailure, aper.DecodeState,

	) (UTDOAInformationFailure, aper.Snapshot,

	)
	compare func(UTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (UTDOAInformationFailure,

		error)
	encode func(UTDOAInformationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTDOAInformationFailureValueCodec) New(value UTDOAInformationFailure,

) (UTDOAInformationFailureAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationFailureAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTDOAInformationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTDOAInformationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTDOAInformationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTDOAInformationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTDOAInformationFailureValueCodec) EncodeAPER(value UTDOAInformationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTDOAInformationFailureValueCodec) encodeBudget(value UTDOAInformationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationFailureValueCodec) encodeChanged(value UTDOAInformationFailure,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTDOAInformationRequestValueCodec is the concrete ValueCodec[UTDOAInformationRequest].
type UTDOAInformationRequestValueCodec struct {
	context s00.BridgeCodecContext
	capture func(UTDOAInformationRequest, aper.DecodeState,

	) (UTDOAInformationRequest, aper.Snapshot,

	)
	compare func(UTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (UTDOAInformationRequest,

		error)
	encode func(UTDOAInformationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTDOAInformationRequestValueCodec) New(value UTDOAInformationRequest,

) (UTDOAInformationRequestAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationRequestAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTDOAInformationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTDOAInformationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTDOAInformationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTDOAInformationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTDOAInformationRequestValueCodec) EncodeAPER(value UTDOAInformationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTDOAInformationRequestValueCodec) encodeBudget(value UTDOAInformationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationRequestValueCodec) encodeChanged(value UTDOAInformationRequest,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UnsuccessfulOutcomeValueCodec is the concrete ValueCodec[UnsuccessfulOutcome].
type UnsuccessfulOutcomeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(UnsuccessfulOutcome, aper.DecodeState,

	) (UnsuccessfulOutcome, aper.Snapshot,

	)
	compare func(UnsuccessfulOutcome, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (UnsuccessfulOutcome,

		error)
	encode func(UnsuccessfulOutcome,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UnsuccessfulOutcomeValueCodec) New(value UnsuccessfulOutcome,

) (UnsuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UnsuccessfulOutcomeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UnsuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UnsuccessfulOutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UnsuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UnsuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UnsuccessfulOutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UnsuccessfulOutcomeValueCodec) EncodeAPER(value UnsuccessfulOutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UnsuccessfulOutcomeValueCodec) encodeBudget(value UnsuccessfulOutcome,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UnsuccessfulOutcomeValueCodec) encodeChanged(value UnsuccessfulOutcome,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(fields s09.UTDOAInformationRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s09.BridgeUTDOAInformationRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s09.BridgeUTDOAInformationRequestIEValueMethodRule(field.Value)
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
func BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(fields s10.UTDOAInformationFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s10.BridgeUTDOAInformationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s10.BridgeUTDOAInformationFailureIEValueMethodRule(field.Value)
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
func BridgeTDDConfigurationExtIEsValueValidateLPPaExtensionContainer(fields s04.TDDConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.TDDConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.TDDConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTDDConfigurationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// tDDConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.TDDConfigurationExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.TDDConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uTDOAInformationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.UTDOAInformationFailureIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.UTDOAInformationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(v *s10.UTDOAInformationFailureIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s10.BridgeUTDOAInformationFailureIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s10.BridgeUTDOAInformationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = s10.BridgeUTDOAInformationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s10.BridgeUTDOAInformationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s10.BridgeUTDOAInformationFailureIEFieldFieldReplay(v), *s10.BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEField(v *s10.UTDOAInformationFailureIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s10.BridgeUTDOAInformationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeUTDOAInformationFailureIEFieldFieldReplay(v), *s10.BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}

// uTDOAInformationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.UTDOAInformationRequestIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.UTDOAInformationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(v *s09.UTDOAInformationRequestIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s09.BridgeUTDOAInformationRequestIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s09.BridgeUTDOAInformationRequestIEValueMethodCaptureFraming(v.Value))
	v.Value = s09.BridgeUTDOAInformationRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s09.BridgeUTDOAInformationRequestIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s09.BridgeUTDOAInformationRequestIEFieldFieldReplay(v), *s09.BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEField(v *s09.UTDOAInformationRequestIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s09.BridgeUTDOAInformationRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeUTDOAInformationRequestIEFieldFieldReplay(v), *s09.BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(v *s10.UTDOAInformationResponseIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s10.BridgeUTDOAInformationResponseIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s10.BridgeUTDOAInformationResponseIEValueMethodCaptureFraming(v.Value))
	v.Value = s10.BridgeUTDOAInformationResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s10.BridgeUTDOAInformationResponseIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s10.BridgeUTDOAInformationResponseIEFieldFieldReplay(v), *s10.BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEField(v *s10.UTDOAInformationResponseIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s10.BridgeUTDOAInformationResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeUTDOAInformationResponseIEFieldFieldReplay(v), *s10.BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v))
}

// OTDOACellsAPERValue is the concrete APERValue[OTDOACells].
type OTDOACellsAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOACells

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOACellsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellsAPERValue) WithoutReplay() OTDOACellsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellsElemAPERValue is the concrete APERValue[OTDOACellsElem].
type OTDOACellsElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOACellsElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOACellsElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellsElemAPERValue) WithoutReplay() OTDOACellsElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationFailureAPERValue is the concrete APERValue[UTDOAInformationFailure].
type UTDOAInformationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   UTDOAInformationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTDOAInformationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationFailureAPERValue) WithoutReplay() UTDOAInformationFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationRequestAPERValue is the concrete APERValue[UTDOAInformationRequest].
type UTDOAInformationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UTDOAInformationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTDOAInformationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationRequestAPERValue) WithoutReplay() UTDOAInformationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UnsuccessfulOutcomeAPERValue is the concrete APERValue[UnsuccessfulOutcome].
type UnsuccessfulOutcomeAPERValue struct {
	context s00.BridgeCodecContext
	Value   UnsuccessfulOutcome

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UnsuccessfulOutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UnsuccessfulOutcomeAPERValue) WithoutReplay() UnsuccessfulOutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeTDDConfigurationExtIEsValueValidateLPPaIEContainer(fields s04.TDDConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s03.BridgeTDDConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeTDDConfigurationExtIEsValueMethodRule(field.Value)
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

type OTDOACells = []OTDOACellsElem

// NewOTDOACellInformationItemPCI creates a OTDOACellInformationItem with the pCI alternative.
func BridgeNewOTDOACellInformationItemPCILegacy(v s00.PCI) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoicePCI,
		PCI:    v,
	}
}

// NewOTDOACellInformationItemCellId creates a OTDOACellInformationItem with the cellId alternative.
func BridgeNewOTDOACellInformationItemCellIdLegacy(v s05.ECGI) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceCellId,
		CellId: &v,
	}
}

// NewOTDOACellInformationItemTAC creates a OTDOACellInformationItem with the tAC alternative.
func BridgeNewOTDOACellInformationItemTACLegacy(v s00.TAC) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceTAC,
		TAC:    &v,
	}
}

// NewOTDOACellInformationItemEARFCN creates a OTDOACellInformationItem with the eARFCN alternative.
func BridgeNewOTDOACellInformationItemEARFCNLegacy(v s00.EARFCN) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceEARFCN,
		EARFCN: v,
	}
}

// NewOTDOACellInformationItemPRSBandwidth creates a OTDOACellInformationItem with the pRS-Bandwidth alternative.
func BridgeNewOTDOACellInformationItemPRSBandwidthLegacy(v s00.PRSBandwidth) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:       s00.OTDOACellInformationItemChoicePRSBandwidth,
		PRSBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSConfigurationIndex creates a OTDOACellInformationItem with the pRS-ConfigurationIndex alternative.
func BridgeNewOTDOACellInformationItemPRSConfigurationIndexLegacy(v s00.PRSConfigurationIndex) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                s00.OTDOACellInformationItemChoicePRSConfigurationIndex,
		PRSConfigurationIndex: v,
	}
}

// NewOTDOACellInformationItemCPLength creates a OTDOACellInformationItem with the cPLength alternative.
func BridgeNewOTDOACellInformationItemCPLengthLegacy(v s00.CPLength) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:   s00.OTDOACellInformationItemChoiceCPLength,
		CPLength: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFrames creates a OTDOACellInformationItem with the numberOfDlFrames alternative.
func BridgeNewOTDOACellInformationItemNumberOfDlFramesLegacy(v s00.NumberOfDlFrames) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:           s00.OTDOACellInformationItemChoiceNumberOfDlFrames,
		NumberOfDlFrames: &v,
	}
}

// NewOTDOACellInformationItemNumberOfAntennaPorts creates a OTDOACellInformationItem with the numberOfAntennaPorts alternative.
func BridgeNewOTDOACellInformationItemNumberOfAntennaPortsLegacy(v s00.NumberOfAntennaPorts) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:               s00.OTDOACellInformationItemChoiceNumberOfAntennaPorts,
		NumberOfAntennaPorts: &v,
	}
}

// NewOTDOACellInformationItemSFNInitialisationTime creates a OTDOACellInformationItem with the sFNInitialisationTime alternative.
func BridgeNewOTDOACellInformationItemSFNInitialisationTimeLegacy(v s00.SFNInitialisationTime) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                s00.OTDOACellInformationItemChoiceSFNInitialisationTime,
		SFNInitialisationTime: &v,
	}
}

// NewOTDOACellInformationItemEUTRANAccessPointPosition creates a OTDOACellInformationItem with the e-UTRANAccessPointPosition alternative.
func BridgeNewOTDOACellInformationItemEUTRANAccessPointPositionLegacy(v s06.EUTRANAccessPointPosition) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                    s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition,
		EUTRANAccessPointPosition: &v,
	}
}

// NewOTDOACellInformationItemPRSMutingConfiguration creates a OTDOACellInformationItem with the pRSMutingConfiguration alternative.
func BridgeNewOTDOACellInformationItemPRSMutingConfigurationLegacy(v s08.PRSMutingConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                 s00.OTDOACellInformationItemChoicePRSMutingConfiguration,
		PRSMutingConfiguration: &v,
	}
}

// NewOTDOACellInformationItemPrsid creates a OTDOACellInformationItem with the prsid alternative.
func BridgeNewOTDOACellInformationItemPrsidLegacy(v s00.PRSID) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoicePrsid,
		Prsid:  v,
	}
}

// NewOTDOACellInformationItemTpid creates a OTDOACellInformationItem with the tpid alternative.
func BridgeNewOTDOACellInformationItemTpidLegacy(v s00.TPID) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceTpid,
		Tpid:   v,
	}
}

// NewOTDOACellInformationItemTpType creates a OTDOACellInformationItem with the tpType alternative.
func BridgeNewOTDOACellInformationItemTpTypeLegacy(v s00.TPType) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceTpType,
		TpType: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFramesExtended creates a OTDOACellInformationItem with the numberOfDlFrames-Extended alternative.
func BridgeNewOTDOACellInformationItemNumberOfDlFramesExtendedLegacy(v s00.NumberOfDlFramesExtended) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                   s00.OTDOACellInformationItemChoiceNumberOfDlFramesExtended,
		NumberOfDlFramesExtended: v,
	}
}

// NewOTDOACellInformationItemCrsCPlength creates a OTDOACellInformationItem with the crsCPlength alternative.
func BridgeNewOTDOACellInformationItemCrsCPlengthLegacy(v s00.CPLength) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:      s00.OTDOACellInformationItemChoiceCrsCPlength,
		CrsCPlength: &v,
	}
}

// NewOTDOACellInformationItemMBSFNsubframeConfiguration creates a OTDOACellInformationItem with the mBSFNsubframeConfiguration alternative.
func BridgeNewOTDOACellInformationItemMBSFNsubframeConfigurationLegacy(v s09.MBSFNsubframeConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                     s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration,
		MBSFNsubframeConfiguration: v,
	}
}

// NewOTDOACellInformationItemNPRSConfiguration creates a OTDOACellInformationItem with the nPRSConfiguration alternative.
func BridgeNewOTDOACellInformationItemNPRSConfigurationLegacy(v s07.NPRSConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:            s00.OTDOACellInformationItemChoiceNPRSConfiguration,
		NPRSConfiguration: &v,
	}
}

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN creates a OTDOACellInformationItem with the offsetNBChanneltoEARFCN alternative.
func BridgeNewOTDOACellInformationItemOffsetNBChanneltoEARFCNLegacy(v s00.OffsetNBChanneltoEARFCN) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                  s00.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN,
		OffsetNBChanneltoEARFCN: &v,
	}
}

// NewOTDOACellInformationItemOperationModeInfo creates a OTDOACellInformationItem with the operationModeInfo alternative.
func BridgeNewOTDOACellInformationItemOperationModeInfoLegacy(v s00.OperationModeInfo) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:            s00.OTDOACellInformationItemChoiceOperationModeInfo,
		OperationModeInfo: &v,
	}
}

// NewOTDOACellInformationItemNPRSID creates a OTDOACellInformationItem with the nPRS-ID alternative.
func BridgeNewOTDOACellInformationItemNPRSIDLegacy(v *big.Int) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice: s00.OTDOACellInformationItemChoiceNPRSID,
		NPRSID: v,
	}
}

// NewOTDOACellInformationItemDLBandwidth creates a OTDOACellInformationItem with the dL-Bandwidth alternative.
func BridgeNewOTDOACellInformationItemDLBandwidthLegacy(v s00.DLBandwidth) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:      s00.OTDOACellInformationItemChoiceDLBandwidth,
		DLBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSOccasionGroup creates a OTDOACellInformationItem with the pRSOccasionGroup alternative.
func BridgeNewOTDOACellInformationItemPRSOccasionGroupLegacy(v s00.PRSOccasionGroup) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:           s00.OTDOACellInformationItemChoicePRSOccasionGroup,
		PRSOccasionGroup: &v,
	}
}

// NewOTDOACellInformationItemPRSFreqHoppingConfig creates a OTDOACellInformationItem with the pRSFreqHoppingConfig alternative.
func BridgeNewOTDOACellInformationItemPRSFreqHoppingConfigLegacy(v s08.PRSFrequencyHoppingConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:               s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig,
		PRSFreqHoppingConfig: &v,
	}
}

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB creates a OTDOACellInformationItem with the repetitionNumberofSIB1-NB alternative.
func BridgeNewOTDOACellInformationItemRepetitionNumberofSIB1NBLegacy(v s00.RepetitionNumberofSIB1NB) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:                   s00.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB,
		RepetitionNumberofSIB1NB: &v,
	}
}

// NewOTDOACellInformationItemNPRSSequenceInfo creates a OTDOACellInformationItem with the nPRSSequenceInfo alternative.
func BridgeNewOTDOACellInformationItemNPRSSequenceInfoLegacy(v s00.NPRSSequenceInfo) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:           s00.OTDOACellInformationItemChoiceNPRSSequenceInfo,
		NPRSSequenceInfo: v,
	}
}

// NewOTDOACellInformationItemNPRSType2 creates a OTDOACellInformationItem with the nPRSType2 alternative.
func BridgeNewOTDOACellInformationItemNPRSType2Legacy(v s07.NPRSConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:    s00.OTDOACellInformationItemChoiceNPRSType2,
		NPRSType2: &v,
	}
}

// NewOTDOACellInformationItemTddConfiguration creates a OTDOACellInformationItem with the tddConfiguration alternative.
func BridgeNewOTDOACellInformationItemTddConfigurationLegacy(v s15.TDDConfiguration) s15.OTDOACellInformationItem {
	return s15.OTDOACellInformationItem{
		Choice:           s00.OTDOACellInformationItemChoiceTddConfiguration,
		TddConfiguration: &v,
	}
}

// OTDOACellsElem represents the ASN.1 type OTDOACells-Elem (SEQUENCE).
type OTDOACellsElem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	OTDOACellInfo      s15.OTDOACellInformation         `asn1:"tag:0,context,implicit"`
	oTDOACellInfoIndef bool                             `asn1:"-" json:"-"`
	IEExtensions       s04.OTDOACellsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                             `asn1:"-" json:"-"`
	extCount           int64                            `asn1:"-" json:"-"`
	extPresent         []bool                           `asn1:"-" json:"-"`
	extData            [][]byte                         `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// MarshalAPERAddOTDOACellsTo appends a AddOTDOACells list to bb.
func BridgeMarshalAPERAddOTDOACellsTo(list s15.AddOTDOACells, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s15.BridgeAsn1cAPERAddOTDOACellsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeAddOTDOACellsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERAddOTDOACellInformationTo appends a AddOTDOACellInformation list to bb.
func BridgeMarshalAPERAddOTDOACellInformationTo(list s15.AddOTDOACellInformation, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s15.BridgeAsn1cAPERAddOTDOACellInformationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

type BridgeAsn1cAPEROTDOACellsListValue struct{ Value OTDOACells }

// MarshalAPEROTDOACellsTo appends a OTDOACells list to bb.
func BridgeMarshalAPEROTDOACellsTo(list OTDOACells, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPEROTDOACellsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPEROTDOACellInformationTo appends a OTDOACellInformation list to bb.
func BridgeMarshalAPEROTDOACellInformationTo(list s15.OTDOACellInformation, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s15.BridgeAsn1cAPEROTDOACellInformationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes OTDOACellsElem to APER format.
func (v *OTDOACellsElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOACellsElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.OTDOACellInfo)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_otdoacellinfo < 0 || fragmentOffset_otdoacellinfo > int64(len(v.OTDOACellInfo)) || fragmentLength_otdoacellinfo < 0 || fragmentLength_otdoacellinfo > int64(len(v.OTDOACellInfo[fragmentOffset_otdoacellinfo:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.OTDOACellInfo[fragmentOffset_otdoacellinfo : fragmentOffset_otdoacellinfo+fragmentLength_otdoacellinfo] {
			if err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding oTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding oTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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
	return nil
}

// UnmarshalAPER decodes OTDOACellsElem from APER format.
func (v *OTDOACellsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *OTDOACellsElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellsElem")
	}
	bb.EnterComponent("OTDOACellsElem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellsElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOACellsElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellsElem")
	}
	v.perPadding = padding
	return nil
}
func (v *OTDOACellsElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsElem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_otdoacellinfo := bb.EnterComponent("OTDOACellInfo")
	v.OTDOACellInfo = make(s15.OTDOACellInformation, 0)
	_, errCollection_otdoacellinfo := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_otdoacellinfo < 0 || fragmentLength_otdoacellinfo < 0 || fragmentLength_otdoacellinfo > int64(^uint(0)>>1) || fragmentOffset_otdoacellinfo > int64(^uint(0)>>1)-fragmentLength_otdoacellinfo {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_otdoacellinfo; i++ {
			var elem s15.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_otdoacellinfo + i)
			if err := s15.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOACellInfo[%d]", fragmentOffset_otdoacellinfo+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.OTDOACellInfo, elem); err != nil {
				return err
			} else {
				v.OTDOACellInfo = next
			}
		}
		return nil
	})
	if errCollection_otdoacellinfo != nil {
		return runtime.WrapDecodePath(errCollection_otdoacellinfo, "OTDOACellInfo")
	}
	bb.LeaveComponent(toleranceMark_otdoacellinfo)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.OTDOACellsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.OTDOACellsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellsElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellsElem) WithoutReplay() OTDOACellsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOACellsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOACellsElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOACellsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOACellsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOACellsElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOACellsElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOACellsElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOACellsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOACellsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOACellsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOACellsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOACellsElem")
}
func (v *OTDOACellsElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellsElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellsElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOACellsElem(v, &s)
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
func (v *OTDOACellsElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellsElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *OTDOACellsElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOACellsElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellsElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellsElem{}
		return report, aper.OperationError(err, "OTDOACellsElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOACellsElem")
}

// NewOTDOACellInformationItemPCI constructs a checked complete value.
func NewOTDOACellInformationItemPCI(v s00.PCI, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPCI")
	}
	value := BridgeNewOTDOACellInformationItemPCILegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPCI")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPCI")
}

// NewOTDOACellInformationItemCellId constructs a checked complete value.
func NewOTDOACellInformationItemCellId(v s05.ECGI, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCellId")
	}
	value := BridgeNewOTDOACellInformationItemCellIdLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCellId")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemCellId")
}

// NewOTDOACellInformationItemTAC constructs a checked complete value.
func NewOTDOACellInformationItemTAC(v s00.TAC, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTAC")
	}
	value := BridgeNewOTDOACellInformationItemTACLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTAC")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemTAC")
}

// NewOTDOACellInformationItemEARFCN constructs a checked complete value.
func NewOTDOACellInformationItemEARFCN(v s00.EARFCN, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemEARFCN")
	}
	value := BridgeNewOTDOACellInformationItemEARFCNLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemEARFCN")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemEARFCN")
}

// NewOTDOACellInformationItemPRSBandwidth constructs a checked complete value.
func NewOTDOACellInformationItemPRSBandwidth(v s00.PRSBandwidth, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSBandwidth")
	}
	value := BridgeNewOTDOACellInformationItemPRSBandwidthLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSBandwidth")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPRSBandwidth")
}

// NewOTDOACellInformationItemPRSConfigurationIndex constructs a checked complete value.
func NewOTDOACellInformationItemPRSConfigurationIndex(v s00.PRSConfigurationIndex, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSConfigurationIndex")
	}
	value := BridgeNewOTDOACellInformationItemPRSConfigurationIndexLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSConfigurationIndex")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPRSConfigurationIndex")
}

// NewOTDOACellInformationItemCPLength constructs a checked complete value.
func NewOTDOACellInformationItemCPLength(v s00.CPLength, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCPLength")
	}
	value := BridgeNewOTDOACellInformationItemCPLengthLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCPLength")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemCPLength")
}

// NewOTDOACellInformationItemNumberOfDlFrames constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfDlFrames(v s00.NumberOfDlFrames, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfDlFrames")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfDlFramesLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfDlFrames")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNumberOfDlFrames")
}

// NewOTDOACellInformationItemNumberOfAntennaPorts constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfAntennaPorts(v s00.NumberOfAntennaPorts, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfAntennaPorts")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfAntennaPortsLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfAntennaPorts")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNumberOfAntennaPorts")
}

// NewOTDOACellInformationItemSFNInitialisationTime constructs a checked complete value.
func NewOTDOACellInformationItemSFNInitialisationTime(v s00.SFNInitialisationTime, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemSFNInitialisationTime")
	}
	value := BridgeNewOTDOACellInformationItemSFNInitialisationTimeLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemSFNInitialisationTime")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemSFNInitialisationTime")
}

// NewOTDOACellInformationItemEUTRANAccessPointPosition constructs a checked complete value.
func NewOTDOACellInformationItemEUTRANAccessPointPosition(v s06.EUTRANAccessPointPosition, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemEUTRANAccessPointPosition")
	}
	value := BridgeNewOTDOACellInformationItemEUTRANAccessPointPositionLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemEUTRANAccessPointPosition")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemEUTRANAccessPointPosition")
}

// NewOTDOACellInformationItemPRSMutingConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemPRSMutingConfiguration(v s08.PRSMutingConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSMutingConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemPRSMutingConfigurationLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSMutingConfiguration")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPRSMutingConfiguration")
}

// NewOTDOACellInformationItemPrsid constructs a checked complete value.
func NewOTDOACellInformationItemPrsid(v s00.PRSID, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPrsid")
	}
	value := BridgeNewOTDOACellInformationItemPrsidLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPrsid")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPrsid")
}

// NewOTDOACellInformationItemTpid constructs a checked complete value.
func NewOTDOACellInformationItemTpid(v s00.TPID, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTpid")
	}
	value := BridgeNewOTDOACellInformationItemTpidLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTpid")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemTpid")
}

// NewOTDOACellInformationItemTpType constructs a checked complete value.
func NewOTDOACellInformationItemTpType(v s00.TPType, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTpType")
	}
	value := BridgeNewOTDOACellInformationItemTpTypeLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTpType")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemTpType")
}

// NewOTDOACellInformationItemNumberOfDlFramesExtended constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfDlFramesExtended(v s00.NumberOfDlFramesExtended, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfDlFramesExtended")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfDlFramesExtendedLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNumberOfDlFramesExtended")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNumberOfDlFramesExtended")
}

// NewOTDOACellInformationItemCrsCPlength constructs a checked complete value.
func NewOTDOACellInformationItemCrsCPlength(v s00.CPLength, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCrsCPlength")
	}
	value := BridgeNewOTDOACellInformationItemCrsCPlengthLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemCrsCPlength")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemCrsCPlength")
}

// NewOTDOACellInformationItemMBSFNsubframeConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemMBSFNsubframeConfiguration(v s09.MBSFNsubframeConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemMBSFNsubframeConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemMBSFNsubframeConfigurationLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemMBSFNsubframeConfiguration")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemMBSFNsubframeConfiguration")
}

// NewOTDOACellInformationItemNPRSConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemNPRSConfiguration(v s07.NPRSConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemNPRSConfigurationLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSConfiguration")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNPRSConfiguration")
}

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN constructs a checked complete value.
func NewOTDOACellInformationItemOffsetNBChanneltoEARFCN(v s00.OffsetNBChanneltoEARFCN, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
	}
	value := BridgeNewOTDOACellInformationItemOffsetNBChanneltoEARFCNLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
}

// NewOTDOACellInformationItemOperationModeInfo constructs a checked complete value.
func NewOTDOACellInformationItemOperationModeInfo(v s00.OperationModeInfo, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemOperationModeInfo")
	}
	value := BridgeNewOTDOACellInformationItemOperationModeInfoLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemOperationModeInfo")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemOperationModeInfo")
}

// NewOTDOACellInformationItemNPRSID constructs a checked complete value.
func NewOTDOACellInformationItemNPRSID(v *big.Int, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSID")
	}
	value := BridgeNewOTDOACellInformationItemNPRSIDLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSID")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNPRSID")
}

// NewOTDOACellInformationItemDLBandwidth constructs a checked complete value.
func NewOTDOACellInformationItemDLBandwidth(v s00.DLBandwidth, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemDLBandwidth")
	}
	value := BridgeNewOTDOACellInformationItemDLBandwidthLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemDLBandwidth")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemDLBandwidth")
}

// NewOTDOACellInformationItemPRSOccasionGroup constructs a checked complete value.
func NewOTDOACellInformationItemPRSOccasionGroup(v s00.PRSOccasionGroup, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSOccasionGroup")
	}
	value := BridgeNewOTDOACellInformationItemPRSOccasionGroupLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSOccasionGroup")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPRSOccasionGroup")
}

// NewOTDOACellInformationItemPRSFreqHoppingConfig constructs a checked complete value.
func NewOTDOACellInformationItemPRSFreqHoppingConfig(v s08.PRSFrequencyHoppingConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSFreqHoppingConfig")
	}
	value := BridgeNewOTDOACellInformationItemPRSFreqHoppingConfigLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemPRSFreqHoppingConfig")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemPRSFreqHoppingConfig")
}

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB constructs a checked complete value.
func NewOTDOACellInformationItemRepetitionNumberofSIB1NB(v s00.RepetitionNumberofSIB1NB, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
	}
	value := BridgeNewOTDOACellInformationItemRepetitionNumberofSIB1NBLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
}

// NewOTDOACellInformationItemNPRSSequenceInfo constructs a checked complete value.
func NewOTDOACellInformationItemNPRSSequenceInfo(v s00.NPRSSequenceInfo, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSSequenceInfo")
	}
	value := BridgeNewOTDOACellInformationItemNPRSSequenceInfoLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSSequenceInfo")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNPRSSequenceInfo")
}

// NewOTDOACellInformationItemNPRSType2 constructs a checked complete value.
func NewOTDOACellInformationItemNPRSType2(v s07.NPRSConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSType2")
	}
	value := BridgeNewOTDOACellInformationItemNPRSType2Legacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemNPRSType2")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemNPRSType2")
}

// NewOTDOACellInformationItemTddConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemTddConfiguration(v s15.TDDConfiguration, options ...aper.BuildOption) (s15.OTDOACellInformationItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTddConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemTddConfigurationLegacy(v)
	if _, err := s15.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s15.OTDOACellInformationItem{}, aper.OperationError(err, "OTDOACellInformationItemTddConfiguration")
	}
	return value, aper.OperationError(nil, "OTDOACellInformationItemTddConfiguration")
}

// UTDOAInformationRequest represents the ASN.1 type UTDOAInformationRequest (SEQUENCE).
type UTDOAInformationRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s09.UTDOAInformationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UTDOAInformationFailure represents the ASN.1 type UTDOAInformationFailure (SEQUENCE).
type UTDOAInformationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s10.UTDOAInformationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UTDOAInformationRequest to APER format.
func (v *UTDOAInformationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s09.BridgeUTDOAInformationRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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
	return nil
}

// UnmarshalAPER decodes UTDOAInformationRequest from APER format.
func (v *UTDOAInformationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UTDOAInformationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	bb.EnterComponent("UTDOAInformationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UTDOAInformationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *UTDOAInformationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s09.UTDOAInformationRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s09.UTDOAInformationRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s09.BridgeUTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// MarshalAPER encodes UTDOAInformationFailure to APER format.
func (v *UTDOAInformationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s10.BridgeUTDOAInformationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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
	return nil
}

// UnmarshalAPER decodes UTDOAInformationFailure from APER format.
func (v *UTDOAInformationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UTDOAInformationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	bb.EnterComponent("UTDOAInformationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "UTDOAInformationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	v.perPadding = padding
	return nil
}
func (v *UTDOAInformationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s10.UTDOAInformationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.UTDOAInformationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s10.BridgeUTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationFailure) WithoutReplay() UTDOAInformationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero UTDOAInformationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationRequest) WithoutReplay() UTDOAInformationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero UTDOAInformationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *UTDOAInformationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationFailure")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "UTDOAInformationFailure")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "UTDOAInformationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "UTDOAInformationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "UTDOAInformationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "UTDOAInformationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "UTDOAInformationFailure")
}
func (v *UTDOAInformationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationFailure) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationFailure(v, &s)
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
func (v *UTDOAInformationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *UTDOAInformationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationRequest")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "UTDOAInformationRequest")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "UTDOAInformationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "UTDOAInformationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "UTDOAInformationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "UTDOAInformationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "UTDOAInformationRequest")
}
func (v *UTDOAInformationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationRequest) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationRequest(v, &s)
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
func (v *UTDOAInformationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *UTDOAInformationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationFailure")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationFailure{}
		return report, aper.OperationError(err, "UTDOAInformationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UTDOAInformationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationRequest")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationRequest{}
		return report, aper.OperationError(err, "UTDOAInformationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UTDOAInformationRequest")
}

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	ProcedureCode     s00.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       s00.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID s00.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             UnsuccessfulValue     `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        aper.CompletePadding  `asn1:"-" json:"-"`
}

// MarshalAPER encodes UnsuccessfulOutcome to APER format.
func (v *UnsuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UnsuccessfulOutcome) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(
			previous,
		)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Value.code != v.ProcedureCode {
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "UnsuccessfulOutcome.ProcedureCode")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.LppatransactionID), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes UnsuccessfulOutcome from APER format.
func (v *UnsuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UnsuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	bb.EnterComponent("UnsuccessfulOutcome")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	padding, err := aper.CaptureFinalBits(bb, "UnsuccessfulOutcome")
	if err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UnsuccessfulOutcome) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UnsuccessfulOutcome{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = s00.ProcedureCode(val_procedurecode)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	val_lppatransactionid, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = s00.LPPATransactionID(val_lppatransactionid)
	toleranceMark_value := bb.EnterComponent("Value")
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.UnsuccessfulReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Unsuccessful"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("UnsuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeUnsuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UnsuccessfulOutcome) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "UnsuccessfulOutcome", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UnsuccessfulOutcome) WithoutReplay() UnsuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero UnsuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *UnsuccessfulOutcome) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "UnsuccessfulOutcome")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaUnsuccessfulOutcome(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "UnsuccessfulOutcome")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "UnsuccessfulOutcome")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "UnsuccessfulOutcome")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "UnsuccessfulOutcome")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "UnsuccessfulOutcome")
}
func (v *UnsuccessfulOutcome) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UnsuccessfulOutcome) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UnsuccessfulOutcome) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaUnsuccessfulOutcome(v, &s)
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
func (v *UnsuccessfulOutcome) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UnsuccessfulOutcome) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UnsuccessfulOutcome) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded UnsuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUnsuccessfulOutcome(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UnsuccessfulOutcome{}
		return report, aper.OperationError(err, "UnsuccessfulOutcome")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UnsuccessfulOutcome")
}

type UnsuccessfulValue struct {
	code                                 s00.ProcedureCode
	withoutReplay                        bool
	received                             aper.WireSpan
	replay                               aper.Snapshot
	opaque                               *aper.OpaqueOpenType
	isOpaque                             bool
	bodyECIDMeasurementInitiationFailure *s11.ECIDMeasurementInitiationFailure
	bodyOTDOAInformationFailure          *s12.OTDOAInformationFailure
	bodyUTDOAInformationFailure          *UTDOAInformationFailure
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *UnsuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}

// AsECIDMeasurementInitiationFailure returns the selected ECIDMeasurementInitiationFailure value and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsECIDMeasurementInitiationFailure() (*s11.ECIDMeasurementInitiationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(2) || v.bodyECIDMeasurementInitiationFailure == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationFailure, true
}

// AsOTDOAInformationFailure returns the selected OTDOAInformationFailure value and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsOTDOAInformationFailure() (*s12.OTDOAInformationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyOTDOAInformationFailure == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationFailure, true
}

// AsUTDOAInformationFailure returns the selected UTDOAInformationFailure value and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsUTDOAInformationFailure() (*UTDOAInformationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyUTDOAInformationFailure == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationFailure, true
}
func BridgeDecodeUnsuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (UnsuccessfulValue, error) {
	v := UnsuccessfulValue{code: code}
	var scope *aper.BitBuffer
	switch code {
	case 2, 6, 7:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case s00.ProcedureCode(2):
		var body s11.ECIDMeasurementInitiationFailure
		child := scope
		replayUsage := child.Usage()
		if err := s11.BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.ECIDMeasurementInitiationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementInitiationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s11.BridgeECIDMeasurementInitiationFailureFieldPerPadding(&body) = padding
		*s11.BridgeECIDMeasurementInitiationFailureFieldReceived(&body) = true
		raw.RetainContents(s11.BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(6):
		var body s12.OTDOAInformationFailure
		child := scope
		replayUsage := child.Usage()
		if err := s12.BridgeOTDOAInformationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.OTDOAInformationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OTDOAInformationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s12.BridgeOTDOAInformationFailureFieldPerPadding(&body) = padding
		*s12.BridgeOTDOAInformationFailureFieldReceived(&body) = true
		raw.RetainContents(s12.BridgeOTDOAInformationFailureFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(7):
		var body UTDOAInformationFailure
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.UTDOAInformationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UTDOAInformationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(aper.UnknownProcedure); err != nil {
			return v, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return v, err
		}
		v.opaque = retained
		v.isOpaque = true
	}
	return v, nil
}
func (v UnsuccessfulValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UnsuccessfulValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.code {
	case s00.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationFailure == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementInitiationFailure", "Unsuccessful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s11.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v.bodyECIDMeasurementInitiationFailure, budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyOTDOAInformationFailure == nil {
			return nil, fmt.Errorf("%s value: missing OTDOAInformationFailure", "Unsuccessful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s12.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v.bodyOTDOAInformationFailure, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyUTDOAInformationFailure == nil {
			return nil, fmt.Errorf("%s value: missing UTDOAInformationFailure", "Unsuccessful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyUTDOAInformationFailure.marshalAPERBudget(budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Unsuccessful", v.code)
	}
}
func NewOpaqueUnsuccessfulOutcome(code s00.ProcedureCode, criticality s00.Criticality, transactionID s00.LPPATransactionID, data []byte) (UnsuccessfulOutcome, error) {
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	switch code {
	case s00.ProcedureCode(2):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(6):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(7):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	message := UnsuccessfulOutcome{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: UnsuccessfulValue{code: code, opaque: retained, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	return message, aper.OperationError(nil, "OpaqueUnsuccessfulOutcome")
}
func BridgeCaptureLPPaOTDOACells(v *OTDOACells, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaOTDOACellsElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaOTDOACells(v *OTDOACells, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaOTDOACellsElem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOACellsElem(v *OTDOACellsElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s15.BridgeCaptureLPPaOTDOACellInformation(&v.OTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellsElem(v *OTDOACellsElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s15.BridgeCompareLPPaOTDOACellInformation(&v.OTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationFailure(v *UTDOAInformationFailure, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationFailure(v *UTDOAInformationFailure, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationRequest(v *UTDOAInformationRequest, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationRequest(v *UTDOAInformationRequest, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s00.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaUnsuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)
	s02.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaUnsuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUnsuccessfulValue(v *UnsuccessfulValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationFailure == nil)
				if v.bodyECIDMeasurementInitiationFailure != nil {
					s11.BridgeCaptureLPPaECIDMeasurementInitiationFailure(v.bodyECIDMeasurementInitiationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationFailure == nil)
				if v.bodyOTDOAInformationFailure != nil {
					s12.BridgeCaptureLPPaOTDOAInformationFailure(v.bodyOTDOAInformationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationFailure == nil)
				if v.bodyUTDOAInformationFailure != nil {
					BridgeCaptureLPPaUTDOAInformationFailure(v.bodyUTDOAInformationFailure, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UnsuccessfulValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v UnsuccessfulValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UnsuccessfulValue) captureSemantics(s aper.SemanticCapture) UnsuccessfulValue {
	BridgeCaptureLPPaUnsuccessfulValue(&v, &s)
	return v
}
func BridgeCompareLPPaUnsuccessfulValue(v *UnsuccessfulValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationFailure == nil)
				if v.bodyECIDMeasurementInitiationFailure != nil {
					s11.BridgeCompareLPPaECIDMeasurementInitiationFailure(v.bodyECIDMeasurementInitiationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationFailure == nil)
				if v.bodyOTDOAInformationFailure != nil {
					s12.BridgeCompareLPPaOTDOAInformationFailure(v.bodyOTDOAInformationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationFailure == nil)
				if v.bodyUTDOAInformationFailure != nil {
					BridgeCompareLPPaUTDOAInformationFailure(v.bodyUTDOAInformationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UnsuccessfulValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaUnsuccessfulValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UnsuccessfulValue) WithoutReplay() UnsuccessfulValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

// OTDOACellsElemCodec binds the complete source value type.
func OTDOACellsElemCodec() OTDOACellsElemValueCodec {
	return OTDOACellsElemValueCodec{path: "OTDOACellsElem", decode: func(data []byte, options aper.DecodeState) (OTDOACellsElem, error) {
		var value OTDOACellsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return OTDOACellsElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value OTDOACellsElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v OTDOACellsElem, options aper.DecodeState) (OTDOACellsElem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaOTDOACellsElem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OTDOACellsElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaOTDOACellsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellsElem"
		return sealed
	}(),
	}
}

// UnsuccessfulOutcomeCodec binds the complete source value type.
func UnsuccessfulOutcomeCodec() UnsuccessfulOutcomeValueCodec {
	return UnsuccessfulOutcomeValueCodec{path: "UnsuccessfulOutcome", decode: func(data []byte, options aper.DecodeState) (UnsuccessfulOutcome, error) {
		var value UnsuccessfulOutcome
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return UnsuccessfulOutcome{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value UnsuccessfulOutcome, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v UnsuccessfulOutcome, options aper.DecodeState) (UnsuccessfulOutcome, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaUnsuccessfulOutcome(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v UnsuccessfulOutcome, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaUnsuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UnsuccessfulOutcome"
		return sealed
	}(),
	}
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UnsuccessfulValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case 2:
		if v.bodyECIDMeasurementInitiationFailure != nil {
			return v.bodyECIDMeasurementInitiationFailure, true
		}
	case 6:
		if v.bodyOTDOAInformationFailure != nil {
			return v.bodyOTDOAInformationFailure, true
		}
	case 7:
		if v.bodyUTDOAInformationFailure != nil {
			return v.bodyUTDOAInformationFailure, true
		}
	}
	return nil, false
}

func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCapture(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(s11.ECIDMeasurementInitiationFailure, aper.DecodeState) (s11.ECIDMeasurementInitiationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCompare(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(s11.ECIDMeasurementInitiationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldContext(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldDecode(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s11.ECIDMeasurementInitiationFailure, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldEncode(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(*s11.ECIDMeasurementInitiationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInfo(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInject(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(s11.ECIDMeasurementInitiationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldValidate(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(*s11.ECIDMeasurementInitiationFailure, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeOTDOACellsAPERValueFieldContext(v *OTDOACellsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsAPERValueFieldReceived(v *OTDOACellsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOACellsAPERValueFieldReplay(v *OTDOACellsAPERValue) *aper.Snapshot { return &v.replay }
func BridgeOTDOACellsAPERValueFieldWithoutReplay(v *OTDOACellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsElemAPERValueFieldContext(v *OTDOACellsElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsElemAPERValueFieldReceived(v *OTDOACellsElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOACellsElemAPERValueFieldReplay(v *OTDOACellsElemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsElemAPERValueFieldWithoutReplay(v *OTDOACellsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsElemFieldExtCount(v *OTDOACellsElem) *int64                { return &v.extCount }
func BridgeOTDOACellsElemFieldExtData(v *OTDOACellsElem) *[][]byte              { return &v.extData }
func BridgeOTDOACellsElemFieldExtOrigin(v *OTDOACellsElem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeOTDOACellsElemFieldExtPresent(v *OTDOACellsElem) *[]bool             { return &v.extPresent }
func BridgeOTDOACellsElemFieldExtWire(v *OTDOACellsElem) *[]aper.WireSpan       { return &v.extWire }
func BridgeOTDOACellsElemFieldIEExtensionsIndef(v *OTDOACellsElem) *bool        { return &v.iEExtensionsIndef }
func BridgeOTDOACellsElemFieldOTDOACellInfoIndef(v *OTDOACellsElem) *bool {
	return &v.oTDOACellInfoIndef
}
func BridgeOTDOACellsElemFieldPerExtPadding(v *OTDOACellsElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOACellsElemFieldPerPadding(v *OTDOACellsElem) *aper.FinalPadding { return &v.perPadding }
func BridgeOTDOACellsElemFieldReceived(v *OTDOACellsElem) *bool                { return &v.received }
func BridgeOTDOACellsElemFieldReceivedBytes(v *OTDOACellsElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellsElemFieldReplay(v *OTDOACellsElem) *aper.Snapshot { return &v.replay }
func BridgeOTDOACellsElemFieldStream(v *OTDOACellsElem) *aper.WireSpan { return &v.stream }
func BridgeOTDOACellsElemFieldWithoutReplay(v *OTDOACellsElem) *bool   { return &v.withoutReplay }
func BridgeOTDOACellsElemMethodMarshalAPERBudget(v *OTDOACellsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERChanged(v *OTDOACellsElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellsElemMethodMarshalAPERChangedValue(v *OTDOACellsElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellsElemMethodMarshalAPERFreshValue(v *OTDOACellsElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERLegacy(v *OTDOACellsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellsElemMethodMarshalAPERPlanned(v *OTDOACellsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERTo(v *OTDOACellsElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERFrom(v *OTDOACellsElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERLegacy(v *OTDOACellsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERWithOptions(v *OTDOACellsElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellsElemValueCodecFieldCapture(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, aper.DecodeState) (OTDOACellsElem, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellsElemValueCodecFieldCompare(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellsElemValueCodecFieldContext(v *OTDOACellsElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsElemValueCodecFieldDecode(v *OTDOACellsElemValueCodec) *func([]byte, aper.DecodeState) (OTDOACellsElem, error) {
	return &v.decode
}
func BridgeOTDOACellsElemValueCodecFieldEncode(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellsElemValueCodecFieldPath(v *OTDOACellsElemValueCodec) *aper.Path { return &v.path }
func BridgeOTDOACellsElemValueCodecMethodEncodeBudget(v OTDOACellsElemValueCodec, a0 OTDOACellsElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellsElemValueCodecMethodEncodeChanged(v OTDOACellsElemValueCodec, a0 OTDOACellsElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellsValueCodecFieldCapture(v *OTDOACellsValueCodec) *func(OTDOACells, aper.DecodeState) (OTDOACells, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellsValueCodecFieldCompare(v *OTDOACellsValueCodec) *func(OTDOACells, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellsValueCodecFieldContext(v *OTDOACellsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsValueCodecFieldDecode(v *OTDOACellsValueCodec) *func([]byte, aper.DecodeState) (OTDOACells, error) {
	return &v.decode
}
func BridgeOTDOACellsValueCodecFieldEncode(v *OTDOACellsValueCodec) *func(OTDOACells, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellsValueCodecFieldPath(v *OTDOACellsValueCodec) *aper.Path { return &v.path }
func BridgeOTDOACellsValueCodecMethodEncodeBudget(v OTDOACellsValueCodec, a0 OTDOACells, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellsValueCodecMethodEncodeChanged(v OTDOACellsValueCodec, a0 OTDOACells, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCapture(v *OTDOAInformationFailureUnsuccessfulBinding) *func(s12.OTDOAInformationFailure, aper.DecodeState) (s12.OTDOAInformationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCompare(v *OTDOAInformationFailureUnsuccessfulBinding) *func(s12.OTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldContext(v *OTDOAInformationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldDecode(v *OTDOAInformationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s12.OTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldEncode(v *OTDOAInformationFailureUnsuccessfulBinding) *func(*s12.OTDOAInformationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInfo(v *OTDOAInformationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInject(v *OTDOAInformationFailureUnsuccessfulBinding) *func(s12.OTDOAInformationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldValidate(v *OTDOAInformationFailureUnsuccessfulBinding) *func(*s12.OTDOAInformationFailure, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationFailureAPERValueFieldContext(v *UTDOAInformationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureAPERValueFieldReceived(v *UTDOAInformationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationFailureAPERValueFieldReplay(v *UTDOAInformationFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureAPERValueFieldWithoutReplay(v *UTDOAInformationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureFieldExtCount(v *UTDOAInformationFailure) *int64 {
	return &v.extCount
}
func BridgeUTDOAInformationFailureFieldExtData(v *UTDOAInformationFailure) *[][]byte {
	return &v.extData
}
func BridgeUTDOAInformationFailureFieldExtOrigin(v *UTDOAInformationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationFailureFieldExtPresent(v *UTDOAInformationFailure) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationFailureFieldExtWire(v *UTDOAInformationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationFailureFieldPerExtPadding(v *UTDOAInformationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationFailureFieldPerPadding(v *UTDOAInformationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationFailureFieldProtocolIEsIndef(v *UTDOAInformationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationFailureFieldReceived(v *UTDOAInformationFailure) *bool { return &v.received }
func BridgeUTDOAInformationFailureFieldReceivedBytes(v *UTDOAInformationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationFailureFieldReplay(v *UTDOAInformationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureFieldStream(v *UTDOAInformationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationFailureFieldWithoutReplay(v *UTDOAInformationFailure) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v *UTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERChanged(v *UTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERChangedValue(v *UTDOAInformationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERFreshValue(v *UTDOAInformationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERLegacy(v *UTDOAInformationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationFailureMethodMarshalAPERPlanned(v *UTDOAInformationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERTo(v *UTDOAInformationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERFrom(v *UTDOAInformationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERLegacy(v *UTDOAInformationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERWithOptions(v *UTDOAInformationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCapture(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure, aper.DecodeState) (UTDOAInformationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCompare(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldContext(v *UTDOAInformationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldDecode(v *UTDOAInformationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (UTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldEncode(v *UTDOAInformationFailureUnsuccessfulBinding) *func(*UTDOAInformationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInfo(v *UTDOAInformationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInject(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldValidate(v *UTDOAInformationFailureUnsuccessfulBinding) *func(*UTDOAInformationFailure, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationFailureValueCodecFieldCapture(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, aper.DecodeState) (UTDOAInformationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationFailureValueCodecFieldCompare(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationFailureValueCodecFieldContext(v *UTDOAInformationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureValueCodecFieldDecode(v *UTDOAInformationFailureValueCodec) *func([]byte, aper.DecodeState) (UTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeUTDOAInformationFailureValueCodecFieldEncode(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationFailureValueCodecFieldPath(v *UTDOAInformationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeUTDOAInformationFailureValueCodecMethodEncodeBudget(v UTDOAInformationFailureValueCodec, a0 UTDOAInformationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationFailureValueCodecMethodEncodeChanged(v UTDOAInformationFailureValueCodec, a0 UTDOAInformationFailure, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationRequestAPERValueFieldContext(v *UTDOAInformationRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestAPERValueFieldReceived(v *UTDOAInformationRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationRequestAPERValueFieldReplay(v *UTDOAInformationRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestAPERValueFieldWithoutReplay(v *UTDOAInformationRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestFieldExtCount(v *UTDOAInformationRequest) *int64 {
	return &v.extCount
}
func BridgeUTDOAInformationRequestFieldExtData(v *UTDOAInformationRequest) *[][]byte {
	return &v.extData
}
func BridgeUTDOAInformationRequestFieldExtOrigin(v *UTDOAInformationRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationRequestFieldExtPresent(v *UTDOAInformationRequest) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationRequestFieldExtWire(v *UTDOAInformationRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationRequestFieldPerExtPadding(v *UTDOAInformationRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationRequestFieldPerPadding(v *UTDOAInformationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationRequestFieldProtocolIEsIndef(v *UTDOAInformationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationRequestFieldReceived(v *UTDOAInformationRequest) *bool { return &v.received }
func BridgeUTDOAInformationRequestFieldReceivedBytes(v *UTDOAInformationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationRequestFieldReplay(v *UTDOAInformationRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestFieldStream(v *UTDOAInformationRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationRequestFieldWithoutReplay(v *UTDOAInformationRequest) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v *UTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERChanged(v *UTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERChangedValue(v *UTDOAInformationRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERFreshValue(v *UTDOAInformationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERLegacy(v *UTDOAInformationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationRequestMethodMarshalAPERPlanned(v *UTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERTo(v *UTDOAInformationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERFrom(v *UTDOAInformationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERLegacy(v *UTDOAInformationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERWithOptions(v *UTDOAInformationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationRequestValueCodecFieldCapture(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, aper.DecodeState) (UTDOAInformationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationRequestValueCodecFieldCompare(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationRequestValueCodecFieldContext(v *UTDOAInformationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestValueCodecFieldDecode(v *UTDOAInformationRequestValueCodec) *func([]byte, aper.DecodeState) (UTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeUTDOAInformationRequestValueCodecFieldEncode(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationRequestValueCodecFieldPath(v *UTDOAInformationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUTDOAInformationRequestValueCodecMethodEncodeBudget(v UTDOAInformationRequestValueCodec, a0 UTDOAInformationRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationRequestValueCodecMethodEncodeChanged(v UTDOAInformationRequestValueCodec, a0 UTDOAInformationRequest, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnsuccessfulOutcomeAPERValueFieldContext(v *UnsuccessfulOutcomeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReceived(v *UnsuccessfulOutcomeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReplay(v *UnsuccessfulOutcomeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUnsuccessfulOutcomeAPERValueFieldWithoutReplay(v *UnsuccessfulOutcomeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeFieldPerPadding(v *UnsuccessfulOutcome) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeUnsuccessfulOutcomeFieldReceived(v *UnsuccessfulOutcome) *bool { return &v.received }
func BridgeUnsuccessfulOutcomeFieldReceivedBytes(v *UnsuccessfulOutcome) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUnsuccessfulOutcomeFieldReplay(v *UnsuccessfulOutcome) *aper.Snapshot { return &v.replay }
func BridgeUnsuccessfulOutcomeFieldStream(v *UnsuccessfulOutcome) *aper.WireSpan { return &v.stream }
func BridgeUnsuccessfulOutcomeFieldWithoutReplay(v *UnsuccessfulOutcome) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERBudget(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChanged(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChangedValue(v *UnsuccessfulOutcome, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERFreshValue(v *UnsuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERLegacy(v *UnsuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERPlanned(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v *UnsuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(v *UnsuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERLegacy(v *UnsuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *UnsuccessfulOutcome, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCapture(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, aper.DecodeState) (UnsuccessfulOutcome, aper.Snapshot) {
	return &v.capture
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCompare(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUnsuccessfulOutcomeValueCodecFieldContext(v *UnsuccessfulOutcomeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeValueCodecFieldDecode(v *UnsuccessfulOutcomeValueCodec) *func([]byte, aper.DecodeState) (UnsuccessfulOutcome, error) {
	return &v.decode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldEncode(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldPath(v *UnsuccessfulOutcomeValueCodec) *aper.Path {
	return &v.path
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeBudget(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeChanged(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnsuccessfulValueFieldBodyECIDMeasurementInitiationFailure(v *UnsuccessfulValue) **s11.ECIDMeasurementInitiationFailure {
	return &v.bodyECIDMeasurementInitiationFailure
}
func BridgeUnsuccessfulValueFieldBodyOTDOAInformationFailure(v *UnsuccessfulValue) **s12.OTDOAInformationFailure {
	return &v.bodyOTDOAInformationFailure
}
func BridgeUnsuccessfulValueFieldBodyUTDOAInformationFailure(v *UnsuccessfulValue) **UTDOAInformationFailure {
	return &v.bodyUTDOAInformationFailure
}
func BridgeUnsuccessfulValueFieldCode(v *UnsuccessfulValue) *s00.ProcedureCode      { return &v.code }
func BridgeUnsuccessfulValueFieldIsOpaque(v *UnsuccessfulValue) *bool               { return &v.isOpaque }
func BridgeUnsuccessfulValueFieldOpaque(v *UnsuccessfulValue) **aper.OpaqueOpenType { return &v.opaque }
func BridgeUnsuccessfulValueFieldReceived(v *UnsuccessfulValue) *aper.WireSpan      { return &v.received }
func BridgeUnsuccessfulValueFieldReplay(v *UnsuccessfulValue) *aper.Snapshot        { return &v.replay }
func BridgeUnsuccessfulValueFieldWithoutReplay(v *UnsuccessfulValue) *bool          { return &v.withoutReplay }
func BridgeUnsuccessfulValueMethodCaptureFraming(v UnsuccessfulValue) uint64 {
	return v.captureFraming()
}
func BridgeUnsuccessfulValueMethodCaptureSemantics(v UnsuccessfulValue, a0 aper.SemanticCapture) UnsuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeUnsuccessfulValueMethodCaptureSnapshot(v UnsuccessfulValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeUnsuccessfulValueMethodCompareSemantics(v UnsuccessfulValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUnsuccessfulValueMethodEncode(v UnsuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeUnsuccessfulValueMethodEncodeFresh(v UnsuccessfulValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
