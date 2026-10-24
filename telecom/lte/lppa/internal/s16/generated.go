// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s16 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s16

import (
	q8 "fmt"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q19 "math/big"
)

// ECIDMeasurementInitiationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureUnsuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(q5.ECIDMeasurementInitiationFailure, q6.DecodeState,

	) (q5.ECIDMeasurementInitiationFailure, q6.Snapshot,

	)
	compare func(q5.ECIDMeasurementInitiationFailure, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*q5.ECIDMeasurementInitiationFailure,

		*q6.DecodeBudget) (q7.ValidationReport, error)
	encode func(*q5.ECIDMeasurementInitiationFailure,

		bool, *q6.DecodeBudget) ([]byte, error)
	decode func([]byte, q6.DecodeState) (q5.ECIDMeasurementInitiationFailure,

		error)
	inject func(q5.ECIDMeasurementInitiationFailure,

	) UnsuccessfulValue
}

func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Codec() q5.ECIDMeasurementInitiationFailureValueCodec {
	return func() q5.ECIDMeasurementInitiationFailureValueCodec {
		sealed := q5.ECIDMeasurementInitiationFailureValueCodec{}
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldPath(&sealed) = q6.Path(b.info.Rule.Assignment.Assignment)
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldDecode(&sealed) = b.decode
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldEncode(&sealed) = func(value q5.ECIDMeasurementInitiationFailure,

			fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldCapture(&sealed) = b.capture
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldCompare(&sealed) = b.compare
		*q5.BridgeECIDMeasurementInitiationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ECIDMeasurementInitiationFailureUnsuccessfulBinding) Build(body q5.ECIDMeasurementInitiationFailure,

	transactionID q4.LPPATransactionID, options ...q6.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("%w: unbound procedure binding", q6.ErrInvalidValue), "Build")
	}
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, q6.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := q6.ChargeValue(q6.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q6.OperationError(nil, "Build")
}

// OTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[OTDOAInformationFailure].
type OTDOAInformationFailureUnsuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(q9.OTDOAInformationFailure, q6.DecodeState,

	) (q9.OTDOAInformationFailure, q6.Snapshot,

	)
	compare func(q9.OTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*q9.OTDOAInformationFailure,

		*q6.DecodeBudget) (q7.ValidationReport, error)
	encode func(*q9.OTDOAInformationFailure,

		bool, *q6.DecodeBudget) ([]byte, error)
	decode func([]byte, q6.DecodeState) (q9.OTDOAInformationFailure,

		error)
	inject func(q9.OTDOAInformationFailure,

	) UnsuccessfulValue
}

func (b OTDOAInformationFailureUnsuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b OTDOAInformationFailureUnsuccessfulBinding) Codec() q9.OTDOAInformationFailureValueCodec {
	return func() q9.OTDOAInformationFailureValueCodec {
		sealed := q9.OTDOAInformationFailureValueCodec{}
		*q9.BridgeOTDOAInformationFailureValueCodecFieldPath(&sealed) = q6.Path(b.info.Rule.Assignment.Assignment)
		*q9.BridgeOTDOAInformationFailureValueCodecFieldDecode(&sealed) = b.decode
		*q9.BridgeOTDOAInformationFailureValueCodecFieldEncode(&sealed) = func(value q9.OTDOAInformationFailure,

			fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q9.BridgeOTDOAInformationFailureValueCodecFieldCapture(&sealed) = b.capture
		*q9.BridgeOTDOAInformationFailureValueCodecFieldCompare(&sealed) = b.compare
		*q9.BridgeOTDOAInformationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b OTDOAInformationFailureUnsuccessfulBinding) Build(body q9.OTDOAInformationFailure,

	transactionID q4.LPPATransactionID, options ...q6.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("%w: unbound procedure binding", q6.ErrInvalidValue), "Build")
	}
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, q6.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := q6.ChargeValue(q6.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q6.OperationError(nil, "Build")
}

// UTDOAInformationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UTDOAInformationFailure].
type UTDOAInformationFailureUnsuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(UTDOAInformationFailure, q6.DecodeState,

	) (UTDOAInformationFailure, q6.Snapshot,

	)
	compare func(UTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*UTDOAInformationFailure,

		*q6.DecodeBudget) (q7.ValidationReport, error)
	encode func(*UTDOAInformationFailure,

		bool, *q6.DecodeBudget) ([]byte, error)
	decode func([]byte, q6.DecodeState) (UTDOAInformationFailure,

		error)
	inject func(UTDOAInformationFailure,

	) UnsuccessfulValue
}

func (b UTDOAInformationFailureUnsuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b UTDOAInformationFailureUnsuccessfulBinding) Codec() UTDOAInformationFailureValueCodec {
	return UTDOAInformationFailureValueCodec{path: q6.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value UTDOAInformationFailure,

		fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}
func (b UTDOAInformationFailureUnsuccessfulBinding) Build(body UTDOAInformationFailure,

	transactionID q4.LPPATransactionID, options ...q6.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("%w: unbound procedure binding", q6.ErrInvalidValue), "Build")
	}
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, q6.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := q6.ChargeValue(q6.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q6.OperationError(nil, "Build")
}
func BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEContainer(v *q10.UTDOAInformationFailureIEContainer, s *q6.SemanticCapture) {
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
func BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(v *q10.UTDOAInformationFailureIEContainer, s *q6.SemanticComparison) {
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
		s.End(f, q6.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(v *q7.UTDOAInformationRequestIEContainer, s *q6.SemanticCapture) {
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
func BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(v *q7.UTDOAInformationRequestIEContainer, s *q6.SemanticComparison) {
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
		s.End(f, q6.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(v *q10.UTDOAInformationResponseIEContainer, s *q6.SemanticCapture) {
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
func BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(v *q10.UTDOAInformationResponseIEContainer, s *q6.SemanticComparison) {
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
		s.End(f, q6.Snapshot{}, false)
	}
}

// OTDOACellsValueCodec is the concrete ValueCodec[OTDOACells].
type OTDOACellsValueCodec struct {
	context q4.BridgeCodecContext
	capture func(OTDOACells, q6.DecodeState,

	) (OTDOACells, q6.Snapshot,

	)
	compare func(OTDOACells, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	path   q6.Path
	decode func([]byte, q6.DecodeState) (OTDOACells,

		error)
	encode func(OTDOACells,

		bool, *q6.DecodeBudget) ([]byte, error)
}

func (c OTDOACellsValueCodec) New(value OTDOACells,

) (OTDOACellsAPERValue, error) {
	if c.encode == nil {
		return OTDOACellsAPERValue{}, q6.OperationError(q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue), "Value.New")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return OTDOACellsAPERValue{}, q6.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellsAPERValue{}, q6.OperationError(err, "Value.New")
	}
	return OTDOACellsAPERValue{Value: value}, q6.OperationError(nil, "Value.New")
}
func (c OTDOACellsValueCodec) DecodeAPER(data []byte, options ...q6.DecodeOption) (OTDOACellsAPERValue, q6.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellsAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q6.FinishDecode(settings, err)
		return OTDOACellsAPERValue{}, report, q6.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellsAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q6.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q6.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellsAPERValue{}, report, q6.OperationError(err, c.path)
	}
	return OTDOACellsAPERValue{Value: value, received: q6.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOACellsValueCodec) EncodeAPER(value OTDOACellsAPERValue, options ...q6.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q6.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q6.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q6.OperationError(err, c.path)
}
func (c OTDOACellsValueCodec) encodeBudget(value OTDOACells,

	fresh bool, budget q6.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellsValueCodec) encodeChanged(value OTDOACells,

	fresh bool, plan q6.ReplayPlan, budget q6.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q6.OperationError(err, c.path)
}

// OTDOACellsElemValueCodec is the concrete ValueCodec[OTDOACellsElem].
type OTDOACellsElemValueCodec struct {
	context q4.BridgeCodecContext
	capture func(OTDOACellsElem, q6.DecodeState,

	) (OTDOACellsElem, q6.Snapshot,

	)
	compare func(OTDOACellsElem, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	path   q6.Path
	decode func([]byte, q6.DecodeState) (OTDOACellsElem,

		error)
	encode func(OTDOACellsElem,

		bool, *q6.DecodeBudget) ([]byte, error)
}

func (c OTDOACellsElemValueCodec) New(value OTDOACellsElem,

) (OTDOACellsElemAPERValue, error) {
	if c.encode == nil {
		return OTDOACellsElemAPERValue{}, q6.OperationError(q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue), "Value.New")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return OTDOACellsElemAPERValue{}, q6.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOACellsElemAPERValue{}, q6.OperationError(err, "Value.New")
	}
	return OTDOACellsElemAPERValue{Value: value}, q6.OperationError(nil, "Value.New")
}
func (c OTDOACellsElemValueCodec) DecodeAPER(data []byte, options ...q6.DecodeOption) (OTDOACellsElemAPERValue, q6.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOACellsElemAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q6.FinishDecode(settings, err)
		return OTDOACellsElemAPERValue{}, report, q6.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOACellsElemAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q6.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q6.FinishDecode(settings, nil)
	if err != nil {
		return OTDOACellsElemAPERValue{}, report, q6.OperationError(err, c.path)
	}
	return OTDOACellsElemAPERValue{Value: value, received: q6.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOACellsElemValueCodec) EncodeAPER(value OTDOACellsElemAPERValue, options ...q6.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q6.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q6.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q6.OperationError(err, c.path)
}
func (c OTDOACellsElemValueCodec) encodeBudget(value OTDOACellsElem,

	fresh bool, budget q6.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOACellsElemValueCodec) encodeChanged(value OTDOACellsElem,

	fresh bool, plan q6.ReplayPlan, budget q6.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q6.OperationError(err, c.path)
}

// UTDOAInformationFailureValueCodec is the concrete ValueCodec[UTDOAInformationFailure].
type UTDOAInformationFailureValueCodec struct {
	context q4.BridgeCodecContext
	capture func(UTDOAInformationFailure, q6.DecodeState,

	) (UTDOAInformationFailure, q6.Snapshot,

	)
	compare func(UTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	path   q6.Path
	decode func([]byte, q6.DecodeState) (UTDOAInformationFailure,

		error)
	encode func(UTDOAInformationFailure,

		bool, *q6.DecodeBudget) ([]byte, error)
}

func (c UTDOAInformationFailureValueCodec) New(value UTDOAInformationFailure,

) (UTDOAInformationFailureAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationFailureAPERValue{}, q6.OperationError(q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue), "Value.New")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return UTDOAInformationFailureAPERValue{}, q6.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationFailureAPERValue{}, q6.OperationError(err, "Value.New")
	}
	return UTDOAInformationFailureAPERValue{Value: value}, q6.OperationError(nil, "Value.New")
}
func (c UTDOAInformationFailureValueCodec) DecodeAPER(data []byte, options ...q6.DecodeOption) (UTDOAInformationFailureAPERValue, q6.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationFailureAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q6.FinishDecode(settings, err)
		return UTDOAInformationFailureAPERValue{}, report, q6.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationFailureAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q6.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q6.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationFailureAPERValue{}, report, q6.OperationError(err, c.path)
	}
	return UTDOAInformationFailureAPERValue{Value: value, received: q6.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTDOAInformationFailureValueCodec) EncodeAPER(value UTDOAInformationFailureAPERValue, options ...q6.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q6.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q6.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q6.OperationError(err, c.path)
}
func (c UTDOAInformationFailureValueCodec) encodeBudget(value UTDOAInformationFailure,

	fresh bool, budget q6.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationFailureValueCodec) encodeChanged(value UTDOAInformationFailure,

	fresh bool, plan q6.ReplayPlan, budget q6.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q6.OperationError(err, c.path)
}

// UTDOAInformationRequestValueCodec is the concrete ValueCodec[UTDOAInformationRequest].
type UTDOAInformationRequestValueCodec struct {
	context q4.BridgeCodecContext
	capture func(UTDOAInformationRequest, q6.DecodeState,

	) (UTDOAInformationRequest, q6.Snapshot,

	)
	compare func(UTDOAInformationRequest, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	path   q6.Path
	decode func([]byte, q6.DecodeState) (UTDOAInformationRequest,

		error)
	encode func(UTDOAInformationRequest,

		bool, *q6.DecodeBudget) ([]byte, error)
}

func (c UTDOAInformationRequestValueCodec) New(value UTDOAInformationRequest,

) (UTDOAInformationRequestAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationRequestAPERValue{}, q6.OperationError(q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue), "Value.New")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return UTDOAInformationRequestAPERValue{}, q6.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationRequestAPERValue{}, q6.OperationError(err, "Value.New")
	}
	return UTDOAInformationRequestAPERValue{Value: value}, q6.OperationError(nil, "Value.New")
}
func (c UTDOAInformationRequestValueCodec) DecodeAPER(data []byte, options ...q6.DecodeOption) (UTDOAInformationRequestAPERValue, q6.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationRequestAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q6.FinishDecode(settings, err)
		return UTDOAInformationRequestAPERValue{}, report, q6.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationRequestAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q6.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q6.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationRequestAPERValue{}, report, q6.OperationError(err, c.path)
	}
	return UTDOAInformationRequestAPERValue{Value: value, received: q6.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTDOAInformationRequestValueCodec) EncodeAPER(value UTDOAInformationRequestAPERValue, options ...q6.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q6.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q6.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q6.OperationError(err, c.path)
}
func (c UTDOAInformationRequestValueCodec) encodeBudget(value UTDOAInformationRequest,

	fresh bool, budget q6.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationRequestValueCodec) encodeChanged(value UTDOAInformationRequest,

	fresh bool, plan q6.ReplayPlan, budget q6.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q6.OperationError(err, c.path)
}

// UnsuccessfulOutcomeValueCodec is the concrete ValueCodec[UnsuccessfulOutcome].
type UnsuccessfulOutcomeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(UnsuccessfulOutcome, q6.DecodeState,

	) (UnsuccessfulOutcome, q6.Snapshot,

	)
	compare func(UnsuccessfulOutcome, q6.Snapshot, q6.ComparisonLimits,

	) q6.ReplayPlan
	path   q6.Path
	decode func([]byte, q6.DecodeState) (UnsuccessfulOutcome,

		error)
	encode func(UnsuccessfulOutcome,

		bool, *q6.DecodeBudget) ([]byte, error)
}

func (c UnsuccessfulOutcomeValueCodec) New(value UnsuccessfulOutcome,

) (UnsuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return UnsuccessfulOutcomeAPERValue{}, q6.OperationError(q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue), "Value.New")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcomeAPERValue{}, q6.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UnsuccessfulOutcomeAPERValue{}, q6.OperationError(err, "Value.New")
	}
	return UnsuccessfulOutcomeAPERValue{Value: value}, q6.OperationError(nil, "Value.New")
}
func (c UnsuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...q6.DecodeOption) (UnsuccessfulOutcomeAPERValue, q6.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UnsuccessfulOutcomeAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q6.FinishDecode(settings, err)
		return UnsuccessfulOutcomeAPERValue{}, report, q6.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UnsuccessfulOutcomeAPERValue{}, q6.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q6.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q6.FinishDecode(settings, nil)
	if err != nil {
		return UnsuccessfulOutcomeAPERValue{}, report, q6.OperationError(err, c.path)
	}
	return UnsuccessfulOutcomeAPERValue{Value: value, received: q6.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UnsuccessfulOutcomeValueCodec) EncodeAPER(value UnsuccessfulOutcomeAPERValue, options ...q6.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q6.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q6.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q6.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q6.OperationError(err, c.path)
}
func (c UnsuccessfulOutcomeValueCodec) encodeBudget(value UnsuccessfulOutcome,

	fresh bool, budget q6.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UnsuccessfulOutcomeValueCodec) encodeChanged(value UnsuccessfulOutcome,

	fresh bool, plan q6.ReplayPlan, budget q6.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q6.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(fields q7.UTDOAInformationRequestIEContainer, rows []q4.FieldInfo, path string, budget *q6.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q6.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q6.Location{Path: q6.Path(q8.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q7.BridgeUTDOAInformationRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q7.BridgeUTDOAInformationRequestIEValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q6.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q6.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q11.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q11.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q11.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(fields q10.UTDOAInformationFailureIEContainer, rows []q4.FieldInfo, path string, budget *q6.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q6.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q6.Location{Path: q6.Path(q8.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q10.BridgeUTDOAInformationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q10.BridgeUTDOAInformationFailureIEValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q6.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q6.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q11.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q11.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q11.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeTDDConfigurationExtIEsValueValidateLPPaExtensionContainer(fields q11.TDDConfigurationExtIEsExtContainer, rows []q4.FieldInfo, path string, budget *q6.DecodeBudget) q7.ValidationReport {
	bb := q6.NewBudgetBuffer(budget)
	if err := q6.ChargeSlice[q11.TDDConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldErr(&sealed) = err
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q11.TDDConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTDDConfigurationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// tDDConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TDDConfigurationExtIEsValue].
type TDDConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q6.SemanticCapture) q12.TDDConfigurationExtIEsValue

	captureFraming() uint64
	captureSnapshot() q6.Snapshot
	compareSemantics(q6.SemanticComparison) q6.SemanticComparison
	decode(q4.ProtocolIEID, q6.OpaqueOpenType) (q12.TDDConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q6.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q6.DecodeBudget) bool
	reason(q4.ProtocolIEID) q6.OpaqueReason
	rule() q6.SourceRule
}

// uTDOAInformationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationFailureIEValue].
type UTDOAInformationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q6.SemanticCapture) q10.UTDOAInformationFailureIEValue

	captureFraming() uint64
	captureSnapshot() q6.Snapshot
	compareSemantics(q6.SemanticComparison) q6.SemanticComparison
	decode(q4.ProtocolIEID, q6.OpaqueOpenType) (q10.UTDOAInformationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q6.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q6.DecodeBudget) bool
	reason(q4.ProtocolIEID) q6.OpaqueReason
	rule() q6.SourceRule
}

func BridgeUTDOAInformationFailureIEValueCaptureLPPaProtocolIEField(v *q10.UTDOAInformationFailureIEField, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q10.BridgeUTDOAInformationFailureIEFieldFieldStream(v))
	q4.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q10.BridgeUTDOAInformationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = q10.BridgeUTDOAInformationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q10.BridgeUTDOAInformationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q10.BridgeUTDOAInformationFailureIEFieldFieldReplay(v), *q10.BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEField(v *q10.UTDOAInformationFailureIEField, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q10.BridgeUTDOAInformationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q10.BridgeUTDOAInformationFailureIEFieldFieldReplay(v), *q10.BridgeUTDOAInformationFailureIEFieldFieldWithoutReplay(v))
}

// uTDOAInformationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q6.SemanticCapture) q7.UTDOAInformationRequestIEValue

	captureFraming() uint64
	captureSnapshot() q6.Snapshot
	compareSemantics(q6.SemanticComparison) q6.SemanticComparison
	decode(q4.ProtocolIEID, q6.OpaqueOpenType) (q7.UTDOAInformationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q6.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q6.DecodeBudget) bool
	reason(q4.ProtocolIEID) q6.OpaqueReason
	rule() q6.SourceRule
}

func BridgeUTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(v *q7.UTDOAInformationRequestIEField, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q7.BridgeUTDOAInformationRequestIEFieldFieldStream(v))
	q4.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q7.BridgeUTDOAInformationRequestIEValueMethodCaptureFraming(v.Value))
	v.Value = q7.BridgeUTDOAInformationRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q7.BridgeUTDOAInformationRequestIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q7.BridgeUTDOAInformationRequestIEFieldFieldReplay(v), *q7.BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEField(v *q7.UTDOAInformationRequestIEField, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q7.BridgeUTDOAInformationRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q7.BridgeUTDOAInformationRequestIEFieldFieldReplay(v), *q7.BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(v *q10.UTDOAInformationResponseIEField, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q10.BridgeUTDOAInformationResponseIEFieldFieldStream(v))
	q4.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q10.BridgeUTDOAInformationResponseIEValueMethodCaptureFraming(v.Value))
	v.Value = q10.BridgeUTDOAInformationResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q10.BridgeUTDOAInformationResponseIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q10.BridgeUTDOAInformationResponseIEFieldFieldReplay(v), *q10.BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEField(v *q10.UTDOAInformationResponseIEField, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q10.BridgeUTDOAInformationResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q10.BridgeUTDOAInformationResponseIEFieldFieldReplay(v), *q10.BridgeUTDOAInformationResponseIEFieldFieldWithoutReplay(v))
}

// OTDOACellsAPERValue is the concrete APERValue[OTDOACells].
type OTDOACellsAPERValue struct {
	context q4.BridgeCodecContext
	Value   OTDOACells

	received      q6.WireSpan
	replay        q6.Snapshot
	withoutReplay bool
}

func (v OTDOACellsAPERValue) ReceivedForm() q6.ReceivedForm {
	return q6.NewReceivedSpanForm(v.received.Present(), v.received, q6.Location{}, nil)
}
func (v OTDOACellsAPERValue) WithoutReplay() OTDOACellsAPERValue {
	v.received = q6.WireSpan{}
	v.replay = q6.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOACellsElemAPERValue is the concrete APERValue[OTDOACellsElem].
type OTDOACellsElemAPERValue struct {
	context q4.BridgeCodecContext
	Value   OTDOACellsElem

	received      q6.WireSpan
	replay        q6.Snapshot
	withoutReplay bool
}

func (v OTDOACellsElemAPERValue) ReceivedForm() q6.ReceivedForm {
	return q6.NewReceivedSpanForm(v.received.Present(), v.received, q6.Location{}, nil)
}
func (v OTDOACellsElemAPERValue) WithoutReplay() OTDOACellsElemAPERValue {
	v.received = q6.WireSpan{}
	v.replay = q6.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationFailureAPERValue is the concrete APERValue[UTDOAInformationFailure].
type UTDOAInformationFailureAPERValue struct {
	context q4.BridgeCodecContext
	Value   UTDOAInformationFailure

	received      q6.WireSpan
	replay        q6.Snapshot
	withoutReplay bool
}

func (v UTDOAInformationFailureAPERValue) ReceivedForm() q6.ReceivedForm {
	return q6.NewReceivedSpanForm(v.received.Present(), v.received, q6.Location{}, nil)
}
func (v UTDOAInformationFailureAPERValue) WithoutReplay() UTDOAInformationFailureAPERValue {
	v.received = q6.WireSpan{}
	v.replay = q6.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationRequestAPERValue is the concrete APERValue[UTDOAInformationRequest].
type UTDOAInformationRequestAPERValue struct {
	context q4.BridgeCodecContext
	Value   UTDOAInformationRequest

	received      q6.WireSpan
	replay        q6.Snapshot
	withoutReplay bool
}

func (v UTDOAInformationRequestAPERValue) ReceivedForm() q6.ReceivedForm {
	return q6.NewReceivedSpanForm(v.received.Present(), v.received, q6.Location{}, nil)
}
func (v UTDOAInformationRequestAPERValue) WithoutReplay() UTDOAInformationRequestAPERValue {
	v.received = q6.WireSpan{}
	v.replay = q6.Snapshot{}
	v.withoutReplay = true
	return v
}

// UnsuccessfulOutcomeAPERValue is the concrete APERValue[UnsuccessfulOutcome].
type UnsuccessfulOutcomeAPERValue struct {
	context q4.BridgeCodecContext
	Value   UnsuccessfulOutcome

	received      q6.WireSpan
	replay        q6.Snapshot
	withoutReplay bool
}

func (v UnsuccessfulOutcomeAPERValue) ReceivedForm() q6.ReceivedForm {
	return q6.NewReceivedSpanForm(v.received.Present(), v.received, q6.Location{}, nil)
}
func (v UnsuccessfulOutcomeAPERValue) WithoutReplay() UnsuccessfulOutcomeAPERValue {
	v.received = q6.WireSpan{}
	v.replay = q6.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeTDDConfigurationExtIEsValueValidateLPPaIEContainer(fields q11.TDDConfigurationExtIEsIEContainer, rows []q4.FieldInfo, path string, budget *q6.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q6.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q6.Location{Path: q6.Path(q8.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgeTDDConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgeTDDConfigurationExtIEsValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q6.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q6.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q11.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q11.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(q8.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q11.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q11.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q6.SourceRule{q11.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q6.Location{Path: q6.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

type OTDOACells = []OTDOACellsElem

// NewOTDOACellInformationItemPCI creates a OTDOACellInformationItem with the pCI alternative.
func BridgeNewOTDOACellInformationItemPCILegacy(v q4.PCI) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoicePCI,
		PCI:    v,
	}
}

// NewOTDOACellInformationItemCellId creates a OTDOACellInformationItem with the cellId alternative.
func BridgeNewOTDOACellInformationItemCellIdLegacy(v q15.ECGI) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceCellId,
		CellId: &v,
	}
}

// NewOTDOACellInformationItemTAC creates a OTDOACellInformationItem with the tAC alternative.
func BridgeNewOTDOACellInformationItemTACLegacy(v q4.TAC) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceTAC,
		TAC:    &v,
	}
}

// NewOTDOACellInformationItemEARFCN creates a OTDOACellInformationItem with the eARFCN alternative.
func BridgeNewOTDOACellInformationItemEARFCNLegacy(v q4.EARFCN) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceEARFCN,
		EARFCN: v,
	}
}

// NewOTDOACellInformationItemPRSBandwidth creates a OTDOACellInformationItem with the pRS-Bandwidth alternative.
func BridgeNewOTDOACellInformationItemPRSBandwidthLegacy(v q4.PRSBandwidth) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:       q4.OTDOACellInformationItemChoicePRSBandwidth,
		PRSBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSConfigurationIndex creates a OTDOACellInformationItem with the pRS-ConfigurationIndex alternative.
func BridgeNewOTDOACellInformationItemPRSConfigurationIndexLegacy(v q4.PRSConfigurationIndex) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                q4.OTDOACellInformationItemChoicePRSConfigurationIndex,
		PRSConfigurationIndex: v,
	}
}

// NewOTDOACellInformationItemCPLength creates a OTDOACellInformationItem with the cPLength alternative.
func BridgeNewOTDOACellInformationItemCPLengthLegacy(v q4.CPLength) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:   q4.OTDOACellInformationItemChoiceCPLength,
		CPLength: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFrames creates a OTDOACellInformationItem with the numberOfDlFrames alternative.
func BridgeNewOTDOACellInformationItemNumberOfDlFramesLegacy(v q4.NumberOfDlFrames) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:           q4.OTDOACellInformationItemChoiceNumberOfDlFrames,
		NumberOfDlFrames: &v,
	}
}

// NewOTDOACellInformationItemNumberOfAntennaPorts creates a OTDOACellInformationItem with the numberOfAntennaPorts alternative.
func BridgeNewOTDOACellInformationItemNumberOfAntennaPortsLegacy(v q4.NumberOfAntennaPorts) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:               q4.OTDOACellInformationItemChoiceNumberOfAntennaPorts,
		NumberOfAntennaPorts: &v,
	}
}

// NewOTDOACellInformationItemSFNInitialisationTime creates a OTDOACellInformationItem with the sFNInitialisationTime alternative.
func BridgeNewOTDOACellInformationItemSFNInitialisationTimeLegacy(v q4.SFNInitialisationTime) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                q4.OTDOACellInformationItemChoiceSFNInitialisationTime,
		SFNInitialisationTime: &v,
	}
}

// NewOTDOACellInformationItemEUTRANAccessPointPosition creates a OTDOACellInformationItem with the e-UTRANAccessPointPosition alternative.
func BridgeNewOTDOACellInformationItemEUTRANAccessPointPositionLegacy(v q16.EUTRANAccessPointPosition) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                    q4.OTDOACellInformationItemChoiceEUTRANAccessPointPosition,
		EUTRANAccessPointPosition: &v,
	}
}

// NewOTDOACellInformationItemPRSMutingConfiguration creates a OTDOACellInformationItem with the pRSMutingConfiguration alternative.
func BridgeNewOTDOACellInformationItemPRSMutingConfigurationLegacy(v q17.PRSMutingConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                 q4.OTDOACellInformationItemChoicePRSMutingConfiguration,
		PRSMutingConfiguration: &v,
	}
}

// NewOTDOACellInformationItemPrsid creates a OTDOACellInformationItem with the prsid alternative.
func BridgeNewOTDOACellInformationItemPrsidLegacy(v q4.PRSID) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoicePrsid,
		Prsid:  v,
	}
}

// NewOTDOACellInformationItemTpid creates a OTDOACellInformationItem with the tpid alternative.
func BridgeNewOTDOACellInformationItemTpidLegacy(v q4.TPID) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceTpid,
		Tpid:   v,
	}
}

// NewOTDOACellInformationItemTpType creates a OTDOACellInformationItem with the tpType alternative.
func BridgeNewOTDOACellInformationItemTpTypeLegacy(v q4.TPType) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceTpType,
		TpType: &v,
	}
}

// NewOTDOACellInformationItemNumberOfDlFramesExtended creates a OTDOACellInformationItem with the numberOfDlFrames-Extended alternative.
func BridgeNewOTDOACellInformationItemNumberOfDlFramesExtendedLegacy(v q4.NumberOfDlFramesExtended) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                   q4.OTDOACellInformationItemChoiceNumberOfDlFramesExtended,
		NumberOfDlFramesExtended: v,
	}
}

// NewOTDOACellInformationItemCrsCPlength creates a OTDOACellInformationItem with the crsCPlength alternative.
func BridgeNewOTDOACellInformationItemCrsCPlengthLegacy(v q4.CPLength) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:      q4.OTDOACellInformationItemChoiceCrsCPlength,
		CrsCPlength: &v,
	}
}

// NewOTDOACellInformationItemMBSFNsubframeConfiguration creates a OTDOACellInformationItem with the mBSFNsubframeConfiguration alternative.
func BridgeNewOTDOACellInformationItemMBSFNsubframeConfigurationLegacy(v q7.MBSFNsubframeConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                     q4.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration,
		MBSFNsubframeConfiguration: v,
	}
}

// NewOTDOACellInformationItemNPRSConfiguration creates a OTDOACellInformationItem with the nPRSConfiguration alternative.
func BridgeNewOTDOACellInformationItemNPRSConfigurationLegacy(v q18.NPRSConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:            q4.OTDOACellInformationItemChoiceNPRSConfiguration,
		NPRSConfiguration: &v,
	}
}

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN creates a OTDOACellInformationItem with the offsetNBChanneltoEARFCN alternative.
func BridgeNewOTDOACellInformationItemOffsetNBChanneltoEARFCNLegacy(v q4.OffsetNBChanneltoEARFCN) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                  q4.OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN,
		OffsetNBChanneltoEARFCN: &v,
	}
}

// NewOTDOACellInformationItemOperationModeInfo creates a OTDOACellInformationItem with the operationModeInfo alternative.
func BridgeNewOTDOACellInformationItemOperationModeInfoLegacy(v q4.OperationModeInfo) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:            q4.OTDOACellInformationItemChoiceOperationModeInfo,
		OperationModeInfo: &v,
	}
}

// NewOTDOACellInformationItemNPRSID creates a OTDOACellInformationItem with the nPRS-ID alternative.
func BridgeNewOTDOACellInformationItemNPRSIDLegacy(v *q19.Int) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice: q4.OTDOACellInformationItemChoiceNPRSID,
		NPRSID: v,
	}
}

// NewOTDOACellInformationItemDLBandwidth creates a OTDOACellInformationItem with the dL-Bandwidth alternative.
func BridgeNewOTDOACellInformationItemDLBandwidthLegacy(v q4.DLBandwidth) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:      q4.OTDOACellInformationItemChoiceDLBandwidth,
		DLBandwidth: &v,
	}
}

// NewOTDOACellInformationItemPRSOccasionGroup creates a OTDOACellInformationItem with the pRSOccasionGroup alternative.
func BridgeNewOTDOACellInformationItemPRSOccasionGroupLegacy(v q4.PRSOccasionGroup) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:           q4.OTDOACellInformationItemChoicePRSOccasionGroup,
		PRSOccasionGroup: &v,
	}
}

// NewOTDOACellInformationItemPRSFreqHoppingConfig creates a OTDOACellInformationItem with the pRSFreqHoppingConfig alternative.
func BridgeNewOTDOACellInformationItemPRSFreqHoppingConfigLegacy(v q17.PRSFrequencyHoppingConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:               q4.OTDOACellInformationItemChoicePRSFreqHoppingConfig,
		PRSFreqHoppingConfig: &v,
	}
}

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB creates a OTDOACellInformationItem with the repetitionNumberofSIB1-NB alternative.
func BridgeNewOTDOACellInformationItemRepetitionNumberofSIB1NBLegacy(v q4.RepetitionNumberofSIB1NB) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:                   q4.OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB,
		RepetitionNumberofSIB1NB: &v,
	}
}

// NewOTDOACellInformationItemNPRSSequenceInfo creates a OTDOACellInformationItem with the nPRSSequenceInfo alternative.
func BridgeNewOTDOACellInformationItemNPRSSequenceInfoLegacy(v q4.NPRSSequenceInfo) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:           q4.OTDOACellInformationItemChoiceNPRSSequenceInfo,
		NPRSSequenceInfo: v,
	}
}

// NewOTDOACellInformationItemNPRSType2 creates a OTDOACellInformationItem with the nPRSType2 alternative.
func BridgeNewOTDOACellInformationItemNPRSType2Legacy(v q18.NPRSConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:    q4.OTDOACellInformationItemChoiceNPRSType2,
		NPRSType2: &v,
	}
}

// NewOTDOACellInformationItemTddConfiguration creates a OTDOACellInformationItem with the tddConfiguration alternative.
func BridgeNewOTDOACellInformationItemTddConfigurationLegacy(v q14.TDDConfiguration) q14.OTDOACellInformationItem {
	return q14.OTDOACellInformationItem{
		Choice:           q4.OTDOACellInformationItemChoiceTddConfiguration,
		TddConfiguration: &v,
	}
}

// OTDOACellsElem represents the ASN.1 type OTDOACells-Elem (SEQUENCE).
type OTDOACellsElem struct {
	replay             q6.Snapshot
	stream             q6.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q6.WireSpan
	OTDOACellInfo      q14.OTDOACellInformation         `asn1:"tag:0,context,implicit"`
	oTDOACellInfoIndef bool                             `asn1:"-" json:"-"`
	IEExtensions       q11.OTDOACellsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                             `asn1:"-" json:"-"`
	extCount           int64                            `asn1:"-" json:"-"`
	extPresent         []bool                           `asn1:"-" json:"-"`
	extData            [][]byte                         `asn1:"-" json:"-"`
	perPadding         q6.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding      []q6.CompletePadding             `asn1:"-" json:"-"`
	extOrigin          []q6.OpaqueOrigin
	extWire            []q6.WireSpan
}

// MarshalAPERAddOTDOACellsTo appends a AddOTDOACells list to bb.
func BridgeMarshalAPERAddOTDOACellsTo(list q14.AddOTDOACells, bb *q6.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q14.BridgeAsn1cAPERAddOTDOACellsListValue{Value: list}
	if err := q6.EncodeCollection(bb, int64(len(v.Value)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q14.BridgeAddOTDOACellsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERAddOTDOACellInformationTo appends a AddOTDOACellInformation list to bb.
func BridgeMarshalAPERAddOTDOACellInformationTo(list q14.AddOTDOACellInformation, bb *q6.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q14.BridgeAsn1cAPERAddOTDOACellInformationListValue{Value: list}
	if err := q6.EncodeCollection(bb, int64(len(v.Value)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

type BridgeAsn1cAPEROTDOACellsListValue struct{ Value OTDOACells }

// MarshalAPEROTDOACellsTo appends a OTDOACells list to bb.
func BridgeMarshalAPEROTDOACellsTo(list OTDOACells, bb *q6.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPEROTDOACellsListValue{Value: list}
	if err := q6.EncodeCollection(bb, int64(len(v.Value)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEROTDOACellInformationTo appends a OTDOACellInformation list to bb.
func BridgeMarshalAPEROTDOACellInformationTo(list q14.OTDOACellInformation, bb *q6.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q14.BridgeAsn1cAPEROTDOACellInformationListValue{Value: list}
	if err := q6.EncodeCollection(bb, int64(len(v.Value)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes OTDOACellsElem to APER format.
func (v *OTDOACellsElem) marshalAPERLegacy() ([]byte, error) {
	bb := q6.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOACellsElem) marshalAPERTo(bb *q6.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q6.CopyExtensionContents(v.extData,
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
	if err := q6.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q6.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q6.EncodeCollection(bb, int64(len(v.OTDOACellInfo)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_otdoacellinfo < 0 || fragmentOffset_otdoacellinfo > int64(len(v.OTDOACellInfo)) || fragmentLength_otdoacellinfo < 0 || fragmentLength_otdoacellinfo > int64(len(v.OTDOACellInfo[fragmentOffset_otdoacellinfo:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.OTDOACellInfo[fragmentOffset_otdoacellinfo : fragmentOffset_otdoacellinfo+fragmentLength_otdoacellinfo] {
			if err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding oTDOACellInfo element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding oTDOACellInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q6.EncodeCollection(bb, int64(len(v.IEExtensions)), q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q8.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q11.BridgeOTDOACellsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q8.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q8.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q8.Errorf("%w: extension bitmap index %d", q6.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q6.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q6.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q6.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q6.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q6.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes OTDOACellsElem from APER format.
func (v *OTDOACellsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q6.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACellsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellsElem) unmarshalAPERWithOptions(data []byte, options q6.DecodeState) error {
	bb := q6.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q20.WrapDecodePath(err, "OTDOACellsElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q20.WrapDecodePath(err, "OTDOACellsElem")
	}
	padding, err := q6.CaptureFinalBits(bb, "OTDOACellsElem")
	if err != nil {
		return q20.WrapDecodePath(err, "OTDOACellsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOACellsElem) unmarshalAPERFrom(bb *q6.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOACellsElem{}
	extAdditions := q6.BeginExtensionAdditions(bb)
	hasExtensions, err := q6.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q6.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_otdoacellinfo := bb.EnterComponent("OTDOACellInfo")
	v.OTDOACellInfo = make(q14.OTDOACellInformation, 0)
	_, errCollection_otdoacellinfo := q6.DecodeCollection(bb, q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_otdoacellinfo, fragmentLength_otdoacellinfo int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_otdoacellinfo < 0 || fragmentLength_otdoacellinfo < 0 || fragmentLength_otdoacellinfo > int64(^uint(0)>>1) || fragmentOffset_otdoacellinfo > int64(^uint(0)>>1)-fragmentLength_otdoacellinfo {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_otdoacellinfo; i++ {
			var elem q14.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_otdoacellinfo + i)
			if err := q14.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q20.WrapDecodePath(err, q8.Sprintf("OTDOACellInfo[%d]", fragmentOffset_otdoacellinfo+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q6.AppendValues(bb, v.OTDOACellInfo, elem); err != nil {
				return err
			} else {
				v.OTDOACellInfo = next
			}
		}
		return nil
	})
	if errCollection_otdoacellinfo != nil {
		return q20.WrapDecodePath(errCollection_otdoacellinfo, "OTDOACellInfo")
	}
	bb.LeaveComponent(toleranceMark_otdoacellinfo)
	if opt_ieextensions {
		tmp_ieextensions := make(q11.OTDOACellsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q6.DecodeCollection(bb, q6.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q8.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q11.OTDOACellsExtIEsExtField
				if err := q11.BridgeOTDOACellsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q20.WrapDecodePath(err, q8.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q6.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q20.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q20.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		if err := q6.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q6.ChargeSlice[q6.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q6.OpaqueOrigin, len(v.extData))
		if err := q6.ChargeSlice[q6.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q6.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q6.DecodeOpaqueOpenTypeAligned(bb, q6.UnknownSelector, q6.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q20.WrapDecodePath(err, q8.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q6.UnknownExtension, i); err != nil {
					return err
				}
				var retained q6.WireSpan
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
func (v *OTDOACellsElem) ReceivedForm() q6.ReceivedForm {
	if v == nil {
		return q6.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellsElem) WithoutReplay() OTDOACellsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q6.WireSpan{}
	var zero OTDOACellsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOACellsElem) Extensions() []q6.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q6.SequenceExtensionViews(v.extPresent, q6.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOACellsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if err := q6.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOACellsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if err := q6.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("OTDOACellsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *OTDOACellsElem) MarshalAPER(options ...q6.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q6.OperationError(q6.ErrInvalidValue, "OTDOACellsElem")
	}
	fresh := v.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, "OTDOACellsElem")
	}
	if !fresh && v.replay.Present() {

		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, "OTDOACellsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, "OTDOACellsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q6.OperationError(err, "OTDOACellsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q6.OperationError(err, "OTDOACellsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q6.OperationError(err, "OTDOACellsElem")
}
func (v *OTDOACellsElem) marshalAPERChangedValue(budget q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellsElem) marshalAPERFreshValue(budget q6.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellsElem) marshalAPERBudget(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q6.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q6.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(budget))
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
func (v *OTDOACellsElem) marshalAPERChanged(budget *q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	previous := q6.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellsElem) marshalAPERPlanned(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q6.NewBudgetBuffer(budget)
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
func (v *OTDOACellsElem) UnmarshalAPER(data []byte, options ...q6.DecodeOption) (q6.DecodeReport, error) {
	if v == nil {
		return q6.DecodeReport{}, q6.OperationError(q6.ErrInvalidValue, "OTDOACellsElem")
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q6.OriginalWire(data)
		s := q6.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellsElem(&decoded, &s)
	}
	report, err := q6.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellsElem{}
		return report, q6.OperationError(err, "OTDOACellsElem")
	}
	*v = decoded
	return report, q6.OperationError(nil, "OTDOACellsElem")
}

// NewOTDOACellInformationItemPCI constructs a checked complete value.
func NewOTDOACellInformationItemPCI(v q4.PCI, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPCI")
	}
	value := BridgeNewOTDOACellInformationItemPCILegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPCI")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPCI")
}

// NewOTDOACellInformationItemCellId constructs a checked complete value.
func NewOTDOACellInformationItemCellId(v q15.ECGI, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCellId")
	}
	value := BridgeNewOTDOACellInformationItemCellIdLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCellId")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemCellId")
}

// NewOTDOACellInformationItemTAC constructs a checked complete value.
func NewOTDOACellInformationItemTAC(v q4.TAC, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTAC")
	}
	value := BridgeNewOTDOACellInformationItemTACLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTAC")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemTAC")
}

// NewOTDOACellInformationItemEARFCN constructs a checked complete value.
func NewOTDOACellInformationItemEARFCN(v q4.EARFCN, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemEARFCN")
	}
	value := BridgeNewOTDOACellInformationItemEARFCNLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemEARFCN")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemEARFCN")
}

// NewOTDOACellInformationItemPRSBandwidth constructs a checked complete value.
func NewOTDOACellInformationItemPRSBandwidth(v q4.PRSBandwidth, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSBandwidth")
	}
	value := BridgeNewOTDOACellInformationItemPRSBandwidthLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSBandwidth")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPRSBandwidth")
}

// NewOTDOACellInformationItemPRSConfigurationIndex constructs a checked complete value.
func NewOTDOACellInformationItemPRSConfigurationIndex(v q4.PRSConfigurationIndex, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSConfigurationIndex")
	}
	value := BridgeNewOTDOACellInformationItemPRSConfigurationIndexLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSConfigurationIndex")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPRSConfigurationIndex")
}

// NewOTDOACellInformationItemCPLength constructs a checked complete value.
func NewOTDOACellInformationItemCPLength(v q4.CPLength, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCPLength")
	}
	value := BridgeNewOTDOACellInformationItemCPLengthLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCPLength")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemCPLength")
}

// NewOTDOACellInformationItemNumberOfDlFrames constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfDlFrames(v q4.NumberOfDlFrames, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfDlFrames")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfDlFramesLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfDlFrames")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNumberOfDlFrames")
}

// NewOTDOACellInformationItemNumberOfAntennaPorts constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfAntennaPorts(v q4.NumberOfAntennaPorts, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfAntennaPorts")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfAntennaPortsLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfAntennaPorts")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNumberOfAntennaPorts")
}

// NewOTDOACellInformationItemSFNInitialisationTime constructs a checked complete value.
func NewOTDOACellInformationItemSFNInitialisationTime(v q4.SFNInitialisationTime, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemSFNInitialisationTime")
	}
	value := BridgeNewOTDOACellInformationItemSFNInitialisationTimeLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemSFNInitialisationTime")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemSFNInitialisationTime")
}

// NewOTDOACellInformationItemEUTRANAccessPointPosition constructs a checked complete value.
func NewOTDOACellInformationItemEUTRANAccessPointPosition(v q16.EUTRANAccessPointPosition, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemEUTRANAccessPointPosition")
	}
	value := BridgeNewOTDOACellInformationItemEUTRANAccessPointPositionLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemEUTRANAccessPointPosition")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemEUTRANAccessPointPosition")
}

// NewOTDOACellInformationItemPRSMutingConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemPRSMutingConfiguration(v q17.PRSMutingConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSMutingConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemPRSMutingConfigurationLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSMutingConfiguration")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPRSMutingConfiguration")
}

// NewOTDOACellInformationItemPrsid constructs a checked complete value.
func NewOTDOACellInformationItemPrsid(v q4.PRSID, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPrsid")
	}
	value := BridgeNewOTDOACellInformationItemPrsidLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPrsid")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPrsid")
}

// NewOTDOACellInformationItemTpid constructs a checked complete value.
func NewOTDOACellInformationItemTpid(v q4.TPID, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTpid")
	}
	value := BridgeNewOTDOACellInformationItemTpidLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTpid")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemTpid")
}

// NewOTDOACellInformationItemTpType constructs a checked complete value.
func NewOTDOACellInformationItemTpType(v q4.TPType, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTpType")
	}
	value := BridgeNewOTDOACellInformationItemTpTypeLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTpType")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemTpType")
}

// NewOTDOACellInformationItemNumberOfDlFramesExtended constructs a checked complete value.
func NewOTDOACellInformationItemNumberOfDlFramesExtended(v q4.NumberOfDlFramesExtended, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfDlFramesExtended")
	}
	value := BridgeNewOTDOACellInformationItemNumberOfDlFramesExtendedLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNumberOfDlFramesExtended")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNumberOfDlFramesExtended")
}

// NewOTDOACellInformationItemCrsCPlength constructs a checked complete value.
func NewOTDOACellInformationItemCrsCPlength(v q4.CPLength, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCrsCPlength")
	}
	value := BridgeNewOTDOACellInformationItemCrsCPlengthLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemCrsCPlength")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemCrsCPlength")
}

// NewOTDOACellInformationItemMBSFNsubframeConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemMBSFNsubframeConfiguration(v q7.MBSFNsubframeConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemMBSFNsubframeConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemMBSFNsubframeConfigurationLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemMBSFNsubframeConfiguration")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemMBSFNsubframeConfiguration")
}

// NewOTDOACellInformationItemNPRSConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemNPRSConfiguration(v q18.NPRSConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemNPRSConfigurationLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSConfiguration")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNPRSConfiguration")
}

// NewOTDOACellInformationItemOffsetNBChanneltoEARFCN constructs a checked complete value.
func NewOTDOACellInformationItemOffsetNBChanneltoEARFCN(v q4.OffsetNBChanneltoEARFCN, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
	}
	value := BridgeNewOTDOACellInformationItemOffsetNBChanneltoEARFCNLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemOffsetNBChanneltoEARFCN")
}

// NewOTDOACellInformationItemOperationModeInfo constructs a checked complete value.
func NewOTDOACellInformationItemOperationModeInfo(v q4.OperationModeInfo, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemOperationModeInfo")
	}
	value := BridgeNewOTDOACellInformationItemOperationModeInfoLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemOperationModeInfo")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemOperationModeInfo")
}

// NewOTDOACellInformationItemNPRSID constructs a checked complete value.
func NewOTDOACellInformationItemNPRSID(v *q19.Int, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSID")
	}
	value := BridgeNewOTDOACellInformationItemNPRSIDLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSID")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNPRSID")
}

// NewOTDOACellInformationItemDLBandwidth constructs a checked complete value.
func NewOTDOACellInformationItemDLBandwidth(v q4.DLBandwidth, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemDLBandwidth")
	}
	value := BridgeNewOTDOACellInformationItemDLBandwidthLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemDLBandwidth")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemDLBandwidth")
}

// NewOTDOACellInformationItemPRSOccasionGroup constructs a checked complete value.
func NewOTDOACellInformationItemPRSOccasionGroup(v q4.PRSOccasionGroup, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSOccasionGroup")
	}
	value := BridgeNewOTDOACellInformationItemPRSOccasionGroupLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSOccasionGroup")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPRSOccasionGroup")
}

// NewOTDOACellInformationItemPRSFreqHoppingConfig constructs a checked complete value.
func NewOTDOACellInformationItemPRSFreqHoppingConfig(v q17.PRSFrequencyHoppingConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSFreqHoppingConfig")
	}
	value := BridgeNewOTDOACellInformationItemPRSFreqHoppingConfigLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemPRSFreqHoppingConfig")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemPRSFreqHoppingConfig")
}

// NewOTDOACellInformationItemRepetitionNumberofSIB1NB constructs a checked complete value.
func NewOTDOACellInformationItemRepetitionNumberofSIB1NB(v q4.RepetitionNumberofSIB1NB, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
	}
	value := BridgeNewOTDOACellInformationItemRepetitionNumberofSIB1NBLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemRepetitionNumberofSIB1NB")
}

// NewOTDOACellInformationItemNPRSSequenceInfo constructs a checked complete value.
func NewOTDOACellInformationItemNPRSSequenceInfo(v q4.NPRSSequenceInfo, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSSequenceInfo")
	}
	value := BridgeNewOTDOACellInformationItemNPRSSequenceInfoLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSSequenceInfo")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNPRSSequenceInfo")
}

// NewOTDOACellInformationItemNPRSType2 constructs a checked complete value.
func NewOTDOACellInformationItemNPRSType2(v q18.NPRSConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSType2")
	}
	value := BridgeNewOTDOACellInformationItemNPRSType2Legacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemNPRSType2")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemNPRSType2")
}

// NewOTDOACellInformationItemTddConfiguration constructs a checked complete value.
func NewOTDOACellInformationItemTddConfiguration(v q14.TDDConfiguration, options ...q6.BuildOption) (q14.OTDOACellInformationItem, error) {
	budget, err := q6.BuildBudget(options...)
	if err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTddConfiguration")
	}
	value := BridgeNewOTDOACellInformationItemTddConfigurationLegacy(v)
	if _, err := q14.BridgeOTDOACellInformationItemMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.OTDOACellInformationItem{}, q6.OperationError(err, "OTDOACellInformationItemTddConfiguration")
	}
	return value, q6.OperationError(nil, "OTDOACellInformationItemTddConfiguration")
}

// UTDOAInformationRequest represents the ASN.1 type UTDOAInformationRequest (SEQUENCE).
type UTDOAInformationRequest struct {
	replay           q6.Snapshot
	stream           q6.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q6.WireSpan
	ProtocolIEs      q7.UTDOAInformationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       q6.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []q6.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []q6.OpaqueOrigin
	extWire          []q6.WireSpan
}

// UTDOAInformationFailure represents the ASN.1 type UTDOAInformationFailure (SEQUENCE).
type UTDOAInformationFailure struct {
	replay           q6.Snapshot
	stream           q6.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q6.WireSpan
	ProtocolIEs      q10.UTDOAInformationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       q6.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []q6.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []q6.OpaqueOrigin
	extWire          []q6.WireSpan
}

// MarshalAPER encodes UTDOAInformationRequest to APER format.
func (v *UTDOAInformationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := q6.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationRequest) marshalAPERTo(bb *q6.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q6.CopyExtensionContents(v.extData,
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
	if err := q6.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q6.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q6.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q7.BridgeUTDOAInformationRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q8.Errorf("%w: extension bitmap index %d", q6.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q6.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q6.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q6.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q6.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q6.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes UTDOAInformationRequest from APER format.
func (v *UTDOAInformationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q6.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UTDOAInformationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UTDOAInformationRequest) unmarshalAPERWithOptions(data []byte, options q6.DecodeState) error {
	bb := q6.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	padding, err := q6.CaptureFinalBits(bb, "UTDOAInformationRequest")
	if err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UTDOAInformationRequest) unmarshalAPERFrom(bb *q6.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationRequest{}
	extAdditions := q6.BeginExtensionAdditions(bb)
	hasExtensions, err := q6.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q7.UTDOAInformationRequestIEContainer, 0)
	_, errCollection_protocolies := q6.DecodeCollection(bb, q6.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q7.UTDOAInformationRequestIEField
			if err := q7.BridgeUTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q20.WrapDecodePath(err, q8.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q6.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q20.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q20.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		if err := q6.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q6.ChargeSlice[q6.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q6.OpaqueOrigin, len(v.extData))
		if err := q6.ChargeSlice[q6.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q6.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q6.DecodeOpaqueOpenTypeAligned(bb, q6.UnknownSelector, q6.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q20.WrapDecodePath(err, q8.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q6.UnknownExtension, i); err != nil {
					return err
				}
				var retained q6.WireSpan
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

// MarshalAPER encodes UTDOAInformationFailure to APER format.
func (v *UTDOAInformationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := q6.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationFailure) marshalAPERTo(bb *q6.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q6.CopyExtensionContents(v.extData,
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
	if err := q6.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q6.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q6.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q10.BridgeUTDOAInformationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q8.Errorf("%w: extension bitmap index %d", q6.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q6.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q6.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q6.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q6.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q6.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes UTDOAInformationFailure from APER format.
func (v *UTDOAInformationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q6.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UTDOAInformationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UTDOAInformationFailure) unmarshalAPERWithOptions(data []byte, options q6.DecodeState) error {
	bb := q6.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	padding, err := q6.CaptureFinalBits(bb, "UTDOAInformationFailure")
	if err != nil {
		return q20.WrapDecodePath(err, "UTDOAInformationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UTDOAInformationFailure) unmarshalAPERFrom(bb *q6.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationFailure{}
	extAdditions := q6.BeginExtensionAdditions(bb)
	hasExtensions, err := q6.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q10.UTDOAInformationFailureIEContainer, 0)
	_, errCollection_protocolies := q6.DecodeCollection(bb, q6.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q10.UTDOAInformationFailureIEField
			if err := q10.BridgeUTDOAInformationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q20.WrapDecodePath(err, q8.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q6.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q20.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q20.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		if err := q6.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q6.ChargeSlice[q6.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q6.OpaqueOrigin, len(v.extData))
		if err := q6.ChargeSlice[q6.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q6.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q6.DecodeOpaqueOpenTypeAligned(bb, q6.UnknownSelector, q6.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q20.WrapDecodePath(err, q8.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q6.UnknownExtension, i); err != nil {
					return err
				}
				var retained q6.WireSpan
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
func (v *UTDOAInformationFailure) ReceivedForm() q6.ReceivedForm {
	if v == nil {
		return q6.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationFailure) WithoutReplay() UTDOAInformationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q6.WireSpan{}
	var zero UTDOAInformationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationRequest) ReceivedForm() q6.ReceivedForm {
	if v == nil {
		return q6.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationRequest) WithoutReplay() UTDOAInformationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q6.WireSpan{}
	var zero UTDOAInformationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationFailure) Extensions() []q6.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q6.SequenceExtensionViews(v.extPresent, q6.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := q6.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if err := q6.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("UTDOAInformationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationRequest) Extensions() []q6.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q6.SequenceExtensionViews(v.extPresent, q6.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := q6.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return q20.WrapDecodePath(q6.ErrInvalidValue, q8.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := q6.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q20.WrapDecodePath(err, q8.Sprintf("UTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q6.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *UTDOAInformationFailure) MarshalAPER(options ...q6.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q6.OperationError(q6.ErrInvalidValue, "UTDOAInformationFailure")
	}
	fresh := v.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, "UTDOAInformationFailure")
	}
	if !fresh && v.replay.Present() {

		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, "UTDOAInformationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, "UTDOAInformationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q6.OperationError(err, "UTDOAInformationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q6.OperationError(err, "UTDOAInformationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q6.OperationError(err, "UTDOAInformationFailure")
}
func (v *UTDOAInformationFailure) marshalAPERChangedValue(budget q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationFailure) marshalAPERFreshValue(budget q6.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationFailure) marshalAPERBudget(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q6.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q6.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(budget))
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
func (v *UTDOAInformationFailure) marshalAPERChanged(budget *q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	previous := q6.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationFailure) marshalAPERPlanned(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q6.NewBudgetBuffer(budget)
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
func (v *UTDOAInformationRequest) MarshalAPER(options ...q6.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q6.OperationError(q6.ErrInvalidValue, "UTDOAInformationRequest")
	}
	fresh := v.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, "UTDOAInformationRequest")
	}
	if !fresh && v.replay.Present() {

		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, "UTDOAInformationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, "UTDOAInformationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q6.OperationError(err, "UTDOAInformationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q6.OperationError(err, "UTDOAInformationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q6.OperationError(err, "UTDOAInformationRequest")
}
func (v *UTDOAInformationRequest) marshalAPERChangedValue(budget q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationRequest) marshalAPERFreshValue(budget q6.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationRequest) marshalAPERBudget(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q6.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q6.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(budget))
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
func (v *UTDOAInformationRequest) marshalAPERChanged(budget *q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	previous := q6.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationRequest) marshalAPERPlanned(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q6.NewBudgetBuffer(budget)
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
func (v *UTDOAInformationFailure) UnmarshalAPER(data []byte, options ...q6.DecodeOption) (q6.DecodeReport, error) {
	if v == nil {
		return q6.DecodeReport{}, q6.OperationError(q6.ErrInvalidValue, "UTDOAInformationFailure")
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q6.OriginalWire(data)
		s := q6.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationFailure(&decoded, &s)
	}
	report, err := q6.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationFailure{}
		return report, q6.OperationError(err, "UTDOAInformationFailure")
	}
	*v = decoded
	return report, q6.OperationError(nil, "UTDOAInformationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationRequest) UnmarshalAPER(data []byte, options ...q6.DecodeOption) (q6.DecodeReport, error) {
	if v == nil {
		return q6.DecodeReport{}, q6.OperationError(q6.ErrInvalidValue, "UTDOAInformationRequest")
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q6.OriginalWire(data)
		s := q6.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationRequest(&decoded, &s)
	}
	report, err := q6.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationRequest{}
		return report, q6.OperationError(err, "UTDOAInformationRequest")
	}
	*v = decoded
	return report, q6.OperationError(nil, "UTDOAInformationRequest")
}

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome struct {
	replay            q6.Snapshot
	stream            q6.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q6.WireSpan
	ProcedureCode     q4.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       q4.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID q4.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             UnsuccessfulValue    `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        q6.CompletePadding   `asn1:"-" json:"-"`
}

// MarshalAPER encodes UnsuccessfulOutcome to APER format.
func (v *UnsuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := q6.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UnsuccessfulOutcome) marshalAPERTo(bb *q6.BitBuffer, fresh ...bool) error {
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
		return q20.WrapDecodePath(q8.Errorf("%w: procedure code %d does not match its value selector", q6.ErrInvalidValue, v.ProcedureCode), "UnsuccessfulOutcome.ProcedureCode")
	}
	if err := q6.EncodeIntegerAligned(bb, int64(v.ProcedureCode), q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(255), false); err != nil {
		return q8.Errorf("encoding procedureCode: %w", err)
	}
	if err := q6.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q8.Errorf("encoding criticality: %w", err)
	}
	if err := q6.EncodeIntegerAligned(bb, int64(v.LppatransactionID), q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(32767), false); err != nil {
		return q8.Errorf("encoding lppatransactionID: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	if err := q6.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes UnsuccessfulOutcome from APER format.
func (v *UnsuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q6.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UnsuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UnsuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options q6.DecodeState) error {
	bb := q6.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q20.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q20.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	padding, err := q6.CaptureFinalBits(bb, "UnsuccessfulOutcome")
	if err != nil {
		return q20.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UnsuccessfulOutcome) unmarshalAPERFrom(bb *q6.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UnsuccessfulOutcome{}
	val_procedurecode, err := q6.DecodeIntegerAligned(bb, q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(255), false)
	if err != nil {
		return q20.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = q4.ProcedureCode(val_procedurecode)
	val_criticality, err := q6.DecodeEnumeratedAligned(bb, 3, false, q6.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return q20.WrapDecodePath(q8.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = q4.Criticality(val_criticality)
	val_lppatransactionid, err := q6.DecodeIntegerAligned(bb, q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(32767), false)
	if err != nil {
		return q20.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = q4.LPPATransactionID(val_lppatransactionid)
	opaque_value, err := q6.DecodeOpaqueOpenTypeAligned(bb, q4.UnsuccessfulReason(v.ProcedureCode), q6.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q6.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Unsuccessful"}})
	if err != nil {
		return q20.WrapDecodePath(q8.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("UnsuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeUnsuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return q20.WrapDecodePath(q8.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UnsuccessfulOutcome) ReceivedForm() q6.ReceivedForm {
	if v == nil {
		return q6.ReceivedForm{}
	}
	return q15.BridgeReceivedFormAt(v.received, v.receivedBytes, "UnsuccessfulOutcome", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UnsuccessfulOutcome) WithoutReplay() UnsuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q6.WireSpan{}
	var zero UnsuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}
func (v *UnsuccessfulOutcome) MarshalAPER(options ...q6.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q6.OperationError(q6.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	fresh := v.withoutReplay || q6.EncodeWithoutReplay(options...)
	var budget q6.DecodeBudget
	if err := q6.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q6.OperationError(err, "UnsuccessfulOutcome")
	}
	if !fresh && v.replay.Present() {

		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(&budget))
		BridgeCompareLPPaUnsuccessfulOutcome(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q6.OperationError(err, "UnsuccessfulOutcome")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q6.OperationError(err, "UnsuccessfulOutcome")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q6.OperationError(err, "UnsuccessfulOutcome")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q6.OperationError(err, "UnsuccessfulOutcome")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q6.OperationError(err, "UnsuccessfulOutcome")
}
func (v *UnsuccessfulOutcome) marshalAPERChangedValue(budget q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UnsuccessfulOutcome) marshalAPERFreshValue(budget q6.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UnsuccessfulOutcome) marshalAPERBudget(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q6.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q6.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q6.NewSemanticComparison(v.replay, q6.ComparisonBudget(budget))
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
func (v *UnsuccessfulOutcome) marshalAPERChanged(budget *q6.DecodeBudget, fresh bool, plan q6.ReplayPlan) ([]byte, error) {
	previous := q6.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UnsuccessfulOutcome) marshalAPERPlanned(budget *q6.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q6.NewBudgetBuffer(budget)
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
func (v *UnsuccessfulOutcome) UnmarshalAPER(data []byte, options ...q6.DecodeOption) (q6.DecodeReport, error) {
	if v == nil {
		return q6.DecodeReport{}, q6.OperationError(q6.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	data, settings := q6.OwnDecodeInputOptions(data, options...)
	var decoded UnsuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q6.OriginalWire(data)
		s := q6.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUnsuccessfulOutcome(&decoded, &s)
	}
	report, err := q6.FinishDecode(settings, err)
	if err != nil {
		*v = UnsuccessfulOutcome{}
		return report, q6.OperationError(err, "UnsuccessfulOutcome")
	}
	*v = decoded
	return report, q6.OperationError(nil, "UnsuccessfulOutcome")
}

type UnsuccessfulValue struct {
	code                                 q4.ProcedureCode
	withoutReplay                        bool
	received                             q6.WireSpan
	replay                               q6.Snapshot
	opaque                               *q6.OpaqueOpenType
	isOpaque                             bool
	bodyECIDMeasurementInitiationFailure *q5.ECIDMeasurementInitiationFailure
	bodyOTDOAInformationFailure          *q9.OTDOAInformationFailure
	bodyUTDOAInformationFailure          *UTDOAInformationFailure
}

func (v *UnsuccessfulValue) Opaque() (q6.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q6.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (v *UnsuccessfulValue) AsECIDMeasurementInitiationFailure() (*q5.ECIDMeasurementInitiationFailure, bool) {
	if v == nil || v.code != q4.ProcedureCode(2) || v.bodyECIDMeasurementInitiationFailure == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationFailure, true
}
func (v *UnsuccessfulValue) AsOTDOAInformationFailure() (*q9.OTDOAInformationFailure, bool) {
	if v == nil || v.code != q4.ProcedureCode(6) || v.bodyOTDOAInformationFailure == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationFailure, true
}
func (v *UnsuccessfulValue) AsUTDOAInformationFailure() (*UTDOAInformationFailure, bool) {
	if v == nil || v.code != q4.ProcedureCode(7) || v.bodyUTDOAInformationFailure == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationFailure, true
}
func BridgeDecodeUnsuccessfulValue(code q4.ProcedureCode, raw q6.OpaqueOpenType) (UnsuccessfulValue, error) {
	v := UnsuccessfulValue{code: code}
	var scope *q6.BitBuffer
	switch code {
	case 2, 6, 7:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case q4.ProcedureCode(2):
		var body q5.ECIDMeasurementInitiationFailure
		child := scope
		replayUsage := child.Usage()
		if err := q5.BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, q8.Errorf("%s %w", "UnsuccessfulMessage.value.ECIDMeasurementInitiationFailure:", err)
		}
		padding, err := q6.CaptureFinalBits(child, "ECIDMeasurementInitiationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*q5.BridgeECIDMeasurementInitiationFailureFieldPerPadding(&body) = padding
		*q5.BridgeECIDMeasurementInitiationFailureFieldReceived(&body) = true
		raw.RetainContents(q5.BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(&body))
		if err := q6.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q4.ProcedureCode(6):
		var body q9.OTDOAInformationFailure
		child := scope
		replayUsage := child.Usage()
		if err := q9.BridgeOTDOAInformationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, q8.Errorf("%s %w", "UnsuccessfulMessage.value.OTDOAInformationFailure:", err)
		}
		padding, err := q6.CaptureFinalBits(child, "OTDOAInformationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*q9.BridgeOTDOAInformationFailureFieldPerPadding(&body) = padding
		*q9.BridgeOTDOAInformationFailureFieldReceived(&body) = true
		raw.RetainContents(q9.BridgeOTDOAInformationFailureFieldReceivedBytes(&body))
		if err := q6.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q4.ProcedureCode(7):
		var body UTDOAInformationFailure
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return UnsuccessfulValue{}, q8.Errorf("%s %w", "UnsuccessfulMessage.value.UTDOAInformationFailure:", err)
		}
		padding, err := q6.CaptureFinalBits(child, "UTDOAInformationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := q6.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationFailure = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(q6.UnknownProcedure); err != nil {
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
	budget, err := q6.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UnsuccessfulValue) encodeFresh(fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q6.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q6.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.code {
	case q4.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationFailure == nil {
			return nil, q8.Errorf("%s value: missing ECIDMeasurementInitiationFailure", "Unsuccessful")
		}
		if !fresh && q6.NewBudgetBuffer(budget).ReplayPlan() != nil && q6.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q5.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v.bodyECIDMeasurementInitiationFailure, budget, fresh)
	case q4.ProcedureCode(6):
		if v.bodyOTDOAInformationFailure == nil {
			return nil, q8.Errorf("%s value: missing OTDOAInformationFailure", "Unsuccessful")
		}
		if !fresh && q6.NewBudgetBuffer(budget).ReplayPlan() != nil && q6.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q9.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v.bodyOTDOAInformationFailure, budget, fresh)
	case q4.ProcedureCode(7):
		if v.bodyUTDOAInformationFailure == nil {
			return nil, q8.Errorf("%s value: missing UTDOAInformationFailure", "Unsuccessful")
		}
		if !fresh && q6.NewBudgetBuffer(budget).ReplayPlan() != nil && q6.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyUTDOAInformationFailure.marshalAPERBudget(budget, fresh)
	default:
		return nil, q8.Errorf("%s value: unknown code %d without opaque content", "Unsuccessful", v.code)
	}
}
func NewOpaqueUnsuccessfulOutcome(code q4.ProcedureCode, criticality q4.Criticality, transactionID q4.LPPATransactionID, data []byte) (UnsuccessfulOutcome, error) {
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	switch code {
	case q4.ProcedureCode(2):
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("known Unsuccessful procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case q4.ProcedureCode(6):
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("known Unsuccessful procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case q4.ProcedureCode(7):
		return UnsuccessfulOutcome{}, q6.OperationError(q8.Errorf("known Unsuccessful procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	}
	budget, err := q6.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	opaque, err := q6.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	message := UnsuccessfulOutcome{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: UnsuccessfulValue{code: code, opaque: retained, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return UnsuccessfulOutcome{}, q6.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	return message, q6.OperationError(nil, "OpaqueUnsuccessfulOutcome")
}
func BridgeCaptureLPPaOTDOACells(v *OTDOACells, s *q6.SemanticCapture) {
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
func BridgeCompareLPPaOTDOACells(v *OTDOACells, s *q6.SemanticComparison) {
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
		s.End(f, q6.Snapshot{}, false)
	}
	s.End(f, q6.Snapshot{}, false)
}
func BridgeCaptureLPPaOTDOACellsElem(v *OTDOACellsElem, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q14.BridgeCaptureLPPaOTDOACellInformation(&v.OTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	q15.BridgeOTDOACellsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellsElem(v *OTDOACellsElem, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaOTDOACellInformation(&v.OTDOACellInfo, s)
	s.Bool(v.IEExtensions == nil)
	q15.BridgeOTDOACellsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationFailure(v *UTDOAInformationFailure, s *q6.SemanticCapture) {
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
func BridgeCompareLPPaUTDOAInformationFailure(v *UTDOAInformationFailure, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationRequest(v *UTDOAInformationRequest, s *q6.SemanticCapture) {
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
func BridgeCompareLPPaUTDOAInformationRequest(v *UTDOAInformationRequest, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q4.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	q4.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaUnsuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)
	q13.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaUnsuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUnsuccessfulValue(v *UnsuccessfulValue, s *q6.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q4.BridgeCaptureLPPaProcedureCode(&v.code, s)
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
		case q4.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationFailure == nil)
				if v.bodyECIDMeasurementInitiationFailure != nil {
					q5.BridgeCaptureLPPaECIDMeasurementInitiationFailure(v.bodyECIDMeasurementInitiationFailure, s)
				}
				s.End(f, nil, false)
			}
		case q4.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationFailure == nil)
				if v.bodyOTDOAInformationFailure != nil {
					q9.BridgeCaptureLPPaOTDOAInformationFailure(v.bodyOTDOAInformationFailure, s)
				}
				s.End(f, nil, false)
			}
		case q4.ProcedureCode(7):
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
func (v UnsuccessfulValue) captureSnapshot() q6.Snapshot { return v.replay }
func (v UnsuccessfulValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UnsuccessfulValue) captureSemantics(s q6.SemanticCapture) UnsuccessfulValue {
	BridgeCaptureLPPaUnsuccessfulValue(&v, &s)
	return v
}
func BridgeCompareLPPaUnsuccessfulValue(v *UnsuccessfulValue, s *q6.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q13.BridgeCompareLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q6.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case q4.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationFailure == nil)
				if v.bodyECIDMeasurementInitiationFailure != nil {
					q5.BridgeCompareLPPaECIDMeasurementInitiationFailure(v.bodyECIDMeasurementInitiationFailure, s)
				}
				s.End(f, q6.Snapshot{}, false)
			}
		case q4.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationFailure == nil)
				if v.bodyOTDOAInformationFailure != nil {
					q9.BridgeCompareLPPaOTDOAInformationFailure(v.bodyOTDOAInformationFailure, s)
				}
				s.End(f, q6.Snapshot{}, false)
			}
		case q4.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationFailure == nil)
				if v.bodyUTDOAInformationFailure != nil {
					BridgeCompareLPPaUTDOAInformationFailure(v.bodyUTDOAInformationFailure, s)
				}
				s.End(f, q6.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UnsuccessfulValue) compareSemantics(s q6.SemanticComparison) q6.SemanticComparison {
	BridgeCompareLPPaUnsuccessfulValue(&v, &s)
	return s
}
func (v UnsuccessfulValue) WithoutReplay() UnsuccessfulValue {
	v.withoutReplay = true
	v.replay = q6.Snapshot{}
	return v
}

// OTDOACellsElemCodec binds the complete source value type.
func OTDOACellsElemCodec() OTDOACellsElemValueCodec {
	return OTDOACellsElemValueCodec{path: "OTDOACellsElem", decode: func(data []byte, options q6.DecodeState) (OTDOACellsElem, error) {
		var value OTDOACellsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return OTDOACellsElem{}, err
		}
		value.received = true
		value.receivedBytes = q6.OriginalWire(data)
		return value, nil
	}, encode: func(value OTDOACellsElem, fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v OTDOACellsElem, options q6.DecodeState) (OTDOACellsElem, q6.Snapshot) {
		s := q6.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaOTDOACellsElem(&v, &s)
		var root q6.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v OTDOACellsElem, root q6.Snapshot, limits q6.ComparisonLimits) q6.ReplayPlan {
		s := q6.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaOTDOACellsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellsElem"
		return sealed
	}(),
	}
}

// UnsuccessfulOutcomeCodec binds the complete source value type.
func UnsuccessfulOutcomeCodec() UnsuccessfulOutcomeValueCodec {
	return UnsuccessfulOutcomeValueCodec{path: "UnsuccessfulOutcome", decode: func(data []byte, options q6.DecodeState) (UnsuccessfulOutcome, error) {
		var value UnsuccessfulOutcome
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return UnsuccessfulOutcome{}, err
		}
		value.received = true
		value.receivedBytes = q6.OriginalWire(data)
		return value, nil
	}, encode: func(value UnsuccessfulOutcome, fresh bool, budget *q6.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v UnsuccessfulOutcome, options q6.DecodeState) (UnsuccessfulOutcome, q6.Snapshot,
	) {
		s := q6.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaUnsuccessfulOutcome(&v, &s)
		var root q6.Snapshot
		s.OperationCounts()
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v UnsuccessfulOutcome, root q6.Snapshot, limits q6.ComparisonLimits) q6.ReplayPlan {
		s := q6.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaUnsuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:UnsuccessfulOutcome"
		return sealed
	}(),
	}
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCapture(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(q5.ECIDMeasurementInitiationFailure, q6.DecodeState) (q5.ECIDMeasurementInitiationFailure, q6.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCompare(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(q5.ECIDMeasurementInitiationFailure, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldContext(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldDecode(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func([]byte, q6.DecodeState) (q5.ECIDMeasurementInitiationFailure, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldEncode(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(*q5.ECIDMeasurementInitiationFailure, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInfo(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInject(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(q5.ECIDMeasurementInitiationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldValidate(v *ECIDMeasurementInitiationFailureUnsuccessfulBinding) *func(*q5.ECIDMeasurementInitiationFailure, *q6.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
func BridgeOTDOACellsAPERValueFieldContext(v *OTDOACellsAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsAPERValueFieldReceived(v *OTDOACellsAPERValue) *q6.WireSpan { return &v.received }
func BridgeOTDOACellsAPERValueFieldReplay(v *OTDOACellsAPERValue) *q6.Snapshot   { return &v.replay }
func BridgeOTDOACellsAPERValueFieldWithoutReplay(v *OTDOACellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsElemAPERValueFieldContext(v *OTDOACellsElemAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsElemAPERValueFieldReceived(v *OTDOACellsElemAPERValue) *q6.WireSpan {
	return &v.received
}
func BridgeOTDOACellsElemAPERValueFieldReplay(v *OTDOACellsElemAPERValue) *q6.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsElemAPERValueFieldWithoutReplay(v *OTDOACellsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsElemFieldExtCount(v *OTDOACellsElem) *int64              { return &v.extCount }
func BridgeOTDOACellsElemFieldExtData(v *OTDOACellsElem) *[][]byte            { return &v.extData }
func BridgeOTDOACellsElemFieldExtOrigin(v *OTDOACellsElem) *[]q6.OpaqueOrigin { return &v.extOrigin }
func BridgeOTDOACellsElemFieldExtPresent(v *OTDOACellsElem) *[]bool           { return &v.extPresent }
func BridgeOTDOACellsElemFieldExtWire(v *OTDOACellsElem) *[]q6.WireSpan       { return &v.extWire }
func BridgeOTDOACellsElemFieldIEExtensionsIndef(v *OTDOACellsElem) *bool      { return &v.iEExtensionsIndef }
func BridgeOTDOACellsElemFieldOTDOACellInfoIndef(v *OTDOACellsElem) *bool {
	return &v.oTDOACellInfoIndef
}
func BridgeOTDOACellsElemFieldPerExtPadding(v *OTDOACellsElem) *[]q6.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOACellsElemFieldPerPadding(v *OTDOACellsElem) *q6.FinalPadding { return &v.perPadding }
func BridgeOTDOACellsElemFieldReceived(v *OTDOACellsElem) *bool              { return &v.received }
func BridgeOTDOACellsElemFieldReceivedBytes(v *OTDOACellsElem) *q6.WireSpan  { return &v.receivedBytes }
func BridgeOTDOACellsElemFieldReplay(v *OTDOACellsElem) *q6.Snapshot         { return &v.replay }
func BridgeOTDOACellsElemFieldStream(v *OTDOACellsElem) *q6.WireSpan         { return &v.stream }
func BridgeOTDOACellsElemFieldWithoutReplay(v *OTDOACellsElem) *bool         { return &v.withoutReplay }
func BridgeOTDOACellsElemMethodMarshalAPERBudget(v *OTDOACellsElem, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERChanged(v *OTDOACellsElem, a0 *q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellsElemMethodMarshalAPERChangedValue(v *OTDOACellsElem, a0 q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellsElemMethodMarshalAPERFreshValue(v *OTDOACellsElem, a0 q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERLegacy(v *OTDOACellsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellsElemMethodMarshalAPERPlanned(v *OTDOACellsElem, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellsElemMethodMarshalAPERTo(v *OTDOACellsElem, a0 *q6.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERFrom(v *OTDOACellsElem, a0 *q6.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERLegacy(v *OTDOACellsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellsElemMethodUnmarshalAPERWithOptions(v *OTDOACellsElem, a0 []byte, a1 q6.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellsElemValueCodecFieldCapture(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, q6.DecodeState) (OTDOACellsElem, q6.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellsElemValueCodecFieldCompare(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellsElemValueCodecFieldContext(v *OTDOACellsElemValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsElemValueCodecFieldDecode(v *OTDOACellsElemValueCodec) *func([]byte, q6.DecodeState) (OTDOACellsElem, error) {
	return &v.decode
}
func BridgeOTDOACellsElemValueCodecFieldEncode(v *OTDOACellsElemValueCodec) *func(OTDOACellsElem, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellsElemValueCodecFieldPath(v *OTDOACellsElemValueCodec) *q6.Path { return &v.path }
func BridgeOTDOACellsElemValueCodecMethodEncodeBudget(v OTDOACellsElemValueCodec, a0 OTDOACellsElem, a1 bool, a2 q6.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellsElemValueCodecMethodEncodeChanged(v OTDOACellsElemValueCodec, a0 OTDOACellsElem, a1 bool, a2 q6.ReplayPlan, a3 q6.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOACellsValueCodecFieldCapture(v *OTDOACellsValueCodec) *func(OTDOACells, q6.DecodeState) (OTDOACells, q6.Snapshot) {
	return &v.capture
}
func BridgeOTDOACellsValueCodecFieldCompare(v *OTDOACellsValueCodec) *func(OTDOACells, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeOTDOACellsValueCodecFieldContext(v *OTDOACellsValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOACellsValueCodecFieldDecode(v *OTDOACellsValueCodec) *func([]byte, q6.DecodeState) (OTDOACells, error) {
	return &v.decode
}
func BridgeOTDOACellsValueCodecFieldEncode(v *OTDOACellsValueCodec) *func(OTDOACells, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOACellsValueCodecFieldPath(v *OTDOACellsValueCodec) *q6.Path { return &v.path }
func BridgeOTDOACellsValueCodecMethodEncodeBudget(v OTDOACellsValueCodec, a0 OTDOACells, a1 bool, a2 q6.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOACellsValueCodecMethodEncodeChanged(v OTDOACellsValueCodec, a0 OTDOACells, a1 bool, a2 q6.ReplayPlan, a3 q6.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCapture(v *OTDOAInformationFailureUnsuccessfulBinding) *func(q9.OTDOAInformationFailure, q6.DecodeState) (q9.OTDOAInformationFailure, q6.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCompare(v *OTDOAInformationFailureUnsuccessfulBinding) *func(q9.OTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldContext(v *OTDOAInformationFailureUnsuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldDecode(v *OTDOAInformationFailureUnsuccessfulBinding) *func([]byte, q6.DecodeState) (q9.OTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldEncode(v *OTDOAInformationFailureUnsuccessfulBinding) *func(*q9.OTDOAInformationFailure, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInfo(v *OTDOAInformationFailureUnsuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInject(v *OTDOAInformationFailureUnsuccessfulBinding) *func(q9.OTDOAInformationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeOTDOAInformationFailureUnsuccessfulBindingFieldValidate(v *OTDOAInformationFailureUnsuccessfulBinding) *func(*q9.OTDOAInformationFailure, *q6.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationFailureAPERValueFieldContext(v *UTDOAInformationFailureAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureAPERValueFieldReceived(v *UTDOAInformationFailureAPERValue) *q6.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationFailureAPERValueFieldReplay(v *UTDOAInformationFailureAPERValue) *q6.Snapshot {
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
func BridgeUTDOAInformationFailureFieldExtOrigin(v *UTDOAInformationFailure) *[]q6.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationFailureFieldExtPresent(v *UTDOAInformationFailure) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationFailureFieldExtWire(v *UTDOAInformationFailure) *[]q6.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationFailureFieldPerExtPadding(v *UTDOAInformationFailure) *[]q6.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationFailureFieldPerPadding(v *UTDOAInformationFailure) *q6.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationFailureFieldProtocolIEsIndef(v *UTDOAInformationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationFailureFieldReceived(v *UTDOAInformationFailure) *bool { return &v.received }
func BridgeUTDOAInformationFailureFieldReceivedBytes(v *UTDOAInformationFailure) *q6.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationFailureFieldReplay(v *UTDOAInformationFailure) *q6.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationFailureFieldStream(v *UTDOAInformationFailure) *q6.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationFailureFieldWithoutReplay(v *UTDOAInformationFailure) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v *UTDOAInformationFailure, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERChanged(v *UTDOAInformationFailure, a0 *q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERChangedValue(v *UTDOAInformationFailure, a0 q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERFreshValue(v *UTDOAInformationFailure, a0 q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERLegacy(v *UTDOAInformationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationFailureMethodMarshalAPERPlanned(v *UTDOAInformationFailure, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationFailureMethodMarshalAPERTo(v *UTDOAInformationFailure, a0 *q6.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERFrom(v *UTDOAInformationFailure, a0 *q6.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERLegacy(v *UTDOAInformationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationFailureMethodUnmarshalAPERWithOptions(v *UTDOAInformationFailure, a0 []byte, a1 q6.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCapture(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure, q6.DecodeState) (UTDOAInformationFailure, q6.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCompare(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldContext(v *UTDOAInformationFailureUnsuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldDecode(v *UTDOAInformationFailureUnsuccessfulBinding) *func([]byte, q6.DecodeState) (UTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldEncode(v *UTDOAInformationFailureUnsuccessfulBinding) *func(*UTDOAInformationFailure, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInfo(v *UTDOAInformationFailureUnsuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInject(v *UTDOAInformationFailureUnsuccessfulBinding) *func(UTDOAInformationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUTDOAInformationFailureUnsuccessfulBindingFieldValidate(v *UTDOAInformationFailureUnsuccessfulBinding) *func(*UTDOAInformationFailure, *q6.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationFailureValueCodecFieldCapture(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, q6.DecodeState) (UTDOAInformationFailure, q6.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationFailureValueCodecFieldCompare(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationFailureValueCodecFieldContext(v *UTDOAInformationFailureValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationFailureValueCodecFieldDecode(v *UTDOAInformationFailureValueCodec) *func([]byte, q6.DecodeState) (UTDOAInformationFailure, error) {
	return &v.decode
}
func BridgeUTDOAInformationFailureValueCodecFieldEncode(v *UTDOAInformationFailureValueCodec) *func(UTDOAInformationFailure, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationFailureValueCodecFieldPath(v *UTDOAInformationFailureValueCodec) *q6.Path {
	return &v.path
}
func BridgeUTDOAInformationFailureValueCodecMethodEncodeBudget(v UTDOAInformationFailureValueCodec, a0 UTDOAInformationFailure, a1 bool, a2 q6.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationFailureValueCodecMethodEncodeChanged(v UTDOAInformationFailureValueCodec, a0 UTDOAInformationFailure, a1 bool, a2 q6.ReplayPlan, a3 q6.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationRequestAPERValueFieldContext(v *UTDOAInformationRequestAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestAPERValueFieldReceived(v *UTDOAInformationRequestAPERValue) *q6.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationRequestAPERValueFieldReplay(v *UTDOAInformationRequestAPERValue) *q6.Snapshot {
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
func BridgeUTDOAInformationRequestFieldExtOrigin(v *UTDOAInformationRequest) *[]q6.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationRequestFieldExtPresent(v *UTDOAInformationRequest) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationRequestFieldExtWire(v *UTDOAInformationRequest) *[]q6.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationRequestFieldPerExtPadding(v *UTDOAInformationRequest) *[]q6.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationRequestFieldPerPadding(v *UTDOAInformationRequest) *q6.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationRequestFieldProtocolIEsIndef(v *UTDOAInformationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationRequestFieldReceived(v *UTDOAInformationRequest) *bool { return &v.received }
func BridgeUTDOAInformationRequestFieldReceivedBytes(v *UTDOAInformationRequest) *q6.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationRequestFieldReplay(v *UTDOAInformationRequest) *q6.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestFieldStream(v *UTDOAInformationRequest) *q6.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationRequestFieldWithoutReplay(v *UTDOAInformationRequest) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v *UTDOAInformationRequest, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERChanged(v *UTDOAInformationRequest, a0 *q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERChangedValue(v *UTDOAInformationRequest, a0 q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERFreshValue(v *UTDOAInformationRequest, a0 q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERLegacy(v *UTDOAInformationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationRequestMethodMarshalAPERPlanned(v *UTDOAInformationRequest, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationRequestMethodMarshalAPERTo(v *UTDOAInformationRequest, a0 *q6.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERFrom(v *UTDOAInformationRequest, a0 *q6.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERLegacy(v *UTDOAInformationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationRequestMethodUnmarshalAPERWithOptions(v *UTDOAInformationRequest, a0 []byte, a1 q6.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationRequestValueCodecFieldCapture(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, q6.DecodeState) (UTDOAInformationRequest, q6.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationRequestValueCodecFieldCompare(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationRequestValueCodecFieldContext(v *UTDOAInformationRequestValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestValueCodecFieldDecode(v *UTDOAInformationRequestValueCodec) *func([]byte, q6.DecodeState) (UTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeUTDOAInformationRequestValueCodecFieldEncode(v *UTDOAInformationRequestValueCodec) *func(UTDOAInformationRequest, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationRequestValueCodecFieldPath(v *UTDOAInformationRequestValueCodec) *q6.Path {
	return &v.path
}
func BridgeUTDOAInformationRequestValueCodecMethodEncodeBudget(v UTDOAInformationRequestValueCodec, a0 UTDOAInformationRequest, a1 bool, a2 q6.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationRequestValueCodecMethodEncodeChanged(v UTDOAInformationRequestValueCodec, a0 UTDOAInformationRequest, a1 bool, a2 q6.ReplayPlan, a3 q6.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnsuccessfulOutcomeAPERValueFieldContext(v *UnsuccessfulOutcomeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReceived(v *UnsuccessfulOutcomeAPERValue) *q6.WireSpan {
	return &v.received
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReplay(v *UnsuccessfulOutcomeAPERValue) *q6.Snapshot {
	return &v.replay
}
func BridgeUnsuccessfulOutcomeAPERValueFieldWithoutReplay(v *UnsuccessfulOutcomeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeFieldPerPadding(v *UnsuccessfulOutcome) *q6.CompletePadding {
	return &v.perPadding
}
func BridgeUnsuccessfulOutcomeFieldReceived(v *UnsuccessfulOutcome) *bool { return &v.received }
func BridgeUnsuccessfulOutcomeFieldReceivedBytes(v *UnsuccessfulOutcome) *q6.WireSpan {
	return &v.receivedBytes
}
func BridgeUnsuccessfulOutcomeFieldReplay(v *UnsuccessfulOutcome) *q6.Snapshot { return &v.replay }
func BridgeUnsuccessfulOutcomeFieldStream(v *UnsuccessfulOutcome) *q6.WireSpan { return &v.stream }
func BridgeUnsuccessfulOutcomeFieldWithoutReplay(v *UnsuccessfulOutcome) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERBudget(v *UnsuccessfulOutcome, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChanged(v *UnsuccessfulOutcome, a0 *q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChangedValue(v *UnsuccessfulOutcome, a0 q6.DecodeBudget, a1 bool, a2 q6.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERFreshValue(v *UnsuccessfulOutcome, a0 q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERLegacy(v *UnsuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERPlanned(v *UnsuccessfulOutcome, a0 *q6.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v *UnsuccessfulOutcome, a0 *q6.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(v *UnsuccessfulOutcome, a0 *q6.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERLegacy(v *UnsuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *UnsuccessfulOutcome, a0 []byte, a1 q6.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCapture(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, q6.DecodeState) (UnsuccessfulOutcome, q6.Snapshot) {
	return &v.capture
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCompare(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, q6.Snapshot, q6.ComparisonLimits) q6.ReplayPlan {
	return &v.compare
}
func BridgeUnsuccessfulOutcomeValueCodecFieldContext(v *UnsuccessfulOutcomeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeValueCodecFieldDecode(v *UnsuccessfulOutcomeValueCodec) *func([]byte, q6.DecodeState) (UnsuccessfulOutcome, error) {
	return &v.decode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldEncode(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, bool, *q6.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldPath(v *UnsuccessfulOutcomeValueCodec) *q6.Path {
	return &v.path
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeBudget(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 q6.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeChanged(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 q6.ReplayPlan, a3 q6.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnsuccessfulValueFieldBodyECIDMeasurementInitiationFailure(v *UnsuccessfulValue) **q5.ECIDMeasurementInitiationFailure {
	return &v.bodyECIDMeasurementInitiationFailure
}
func BridgeUnsuccessfulValueFieldBodyOTDOAInformationFailure(v *UnsuccessfulValue) **q9.OTDOAInformationFailure {
	return &v.bodyOTDOAInformationFailure
}
func BridgeUnsuccessfulValueFieldBodyUTDOAInformationFailure(v *UnsuccessfulValue) **UTDOAInformationFailure {
	return &v.bodyUTDOAInformationFailure
}
func BridgeUnsuccessfulValueFieldCode(v *UnsuccessfulValue) *q4.ProcedureCode     { return &v.code }
func BridgeUnsuccessfulValueFieldIsOpaque(v *UnsuccessfulValue) *bool             { return &v.isOpaque }
func BridgeUnsuccessfulValueFieldOpaque(v *UnsuccessfulValue) **q6.OpaqueOpenType { return &v.opaque }
func BridgeUnsuccessfulValueFieldReceived(v *UnsuccessfulValue) *q6.WireSpan      { return &v.received }
func BridgeUnsuccessfulValueFieldReplay(v *UnsuccessfulValue) *q6.Snapshot        { return &v.replay }
func BridgeUnsuccessfulValueFieldWithoutReplay(v *UnsuccessfulValue) *bool        { return &v.withoutReplay }
func BridgeUnsuccessfulValueMethodCaptureFraming(v UnsuccessfulValue) uint64 {
	return v.captureFraming()
}
func BridgeUnsuccessfulValueMethodCaptureSemantics(v UnsuccessfulValue, a0 q6.SemanticCapture) UnsuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeUnsuccessfulValueMethodCaptureSnapshot(v UnsuccessfulValue) q6.Snapshot {
	return v.captureSnapshot()
}
func BridgeUnsuccessfulValueMethodCompareSemantics(v UnsuccessfulValue, a0 q6.SemanticComparison) q6.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUnsuccessfulValueMethodEncode(v UnsuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeUnsuccessfulValueMethodEncodeFresh(v UnsuccessfulValue, a0 bool, a1 *q6.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
