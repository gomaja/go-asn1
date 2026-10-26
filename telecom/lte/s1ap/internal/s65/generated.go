// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s65 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s65

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

type InitiatingBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s25.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b InitiatingBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitiatingBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b InitiatingBinding[T]) Build(body T, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type SuccessfulBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s25.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s64.SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b SuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SuccessfulBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b SuccessfulBinding[T]) Build(body T, options ...aper.BuildOption) (s64.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s64.SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s64.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type UnsuccessfulBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s25.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s46.UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UnsuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UnsuccessfulBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b UnsuccessfulBinding[T]) Build(body T, options ...aper.BuildOption) (s46.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s46.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// Initiating returns the typed binding for the initiating message of HandoverPreparationDescriptor.
func (HandoverPreparationDescriptor) Initiating() HandoverRequiredInitiatingBinding {
	return HandoverRequiredInitiatingBinding{info: HandoverPreparationProcedure().Info(), validate: func(v *s43.HandoverRequired, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateHandoverRequiredBudget(v, budget)
	}, encode: func(v *s43.HandoverRequired, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s43.BridgeHandoverRequiredMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s43.HandoverRequired, error) {
		var v s43.HandoverRequired
		err := s43.BridgeHandoverRequiredMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s43.HandoverRequired{}, err
		}
		*s43.BridgeHandoverRequiredFieldReceived(&v) = true
		*s43.BridgeHandoverRequiredFieldReceivedAbsolute(&v) = true
		*s43.BridgeHandoverRequiredFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s43.HandoverRequired) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(0), bodyHandoverRequired: &v}
	}, capture: func(v s43.HandoverRequired, options aper.DecodeState) (s43.HandoverRequired, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s43.BridgeCaptureS1APHandoverRequired(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s43.HandoverRequired, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s43.BridgeCompareS1APHandoverRequired(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRequired"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of HandoverPreparationDescriptor.
func (HandoverPreparationDescriptor) Successful() s64.HandoverCommandSuccessfulBinding {
	return func() s64.HandoverCommandSuccessfulBinding {
		sealed := s64.HandoverCommandSuccessfulBinding{}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldInfo(&sealed) = HandoverPreparationProcedure().Info()
		*s64.BridgeHandoverCommandSuccessfulBindingFieldValidate(&sealed) = func(v *s50.HandoverCommand, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateHandoverCommandBudget(v, budget)
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldEncode(&sealed) = func(v *s50.HandoverCommand, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s50.BridgeHandoverCommandMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s50.HandoverCommand, error) {
			var v s50.HandoverCommand
			err := s50.BridgeHandoverCommandMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s50.HandoverCommand{}, err
			}
			*s50.BridgeHandoverCommandFieldReceived(&v) = true
			*s50.BridgeHandoverCommandFieldReceivedAbsolute(&v) = true
			*s50.BridgeHandoverCommandFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldInject(&sealed) = func(v s50.HandoverCommand) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s64.BridgeSuccessfulValueFieldBodyHandoverCommand(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldCapture(&sealed) = func(v s50.HandoverCommand, options aper.DecodeState) (s50.HandoverCommand, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s50.BridgeCaptureS1APHandoverCommand(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldCompare(&sealed) = func(v s50.HandoverCommand, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s50.BridgeCompareS1APHandoverCommand(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s64.BridgeHandoverCommandSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverCommand"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of HandoverPreparationDescriptor.
func (HandoverPreparationDescriptor) Unsuccessful() s46.HandoverPreparationFailureUnsuccessfulBinding {
	return func() s46.HandoverPreparationFailureUnsuccessfulBinding {
		sealed := s46.HandoverPreparationFailureUnsuccessfulBinding{}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInfo(&sealed) = HandoverPreparationProcedure().Info()
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s29.HandoverPreparationFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateHandoverPreparationFailureBudget(v, budget)
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s29.HandoverPreparationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s29.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.HandoverPreparationFailure, error) {
			var v s29.HandoverPreparationFailure
			err := s29.BridgeHandoverPreparationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s29.HandoverPreparationFailure{}, err
			}
			*s29.BridgeHandoverPreparationFailureFieldReceived(&v) = true
			*s29.BridgeHandoverPreparationFailureFieldReceivedAbsolute(&v) = true
			*s29.BridgeHandoverPreparationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s29.HandoverPreparationFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s46.BridgeUnsuccessfulValueFieldBodyHandoverPreparationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s29.HandoverPreparationFailure, options aper.DecodeState) (s29.HandoverPreparationFailure, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APHandoverPreparationFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s29.HandoverPreparationFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APHandoverPreparationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeHandoverPreparationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverPreparationFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of HandoverResourceAllocationDescriptor.
func (HandoverResourceAllocationDescriptor) Initiating() HandoverRequestInitiatingBinding {
	return HandoverRequestInitiatingBinding{info: HandoverResourceAllocationProcedure().Info(), validate: func(v *s60.HandoverRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateHandoverRequestBudget(v, budget)
	}, encode: func(v *s60.HandoverRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s60.BridgeHandoverRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s60.HandoverRequest, error) {
		var v s60.HandoverRequest
		err := s60.BridgeHandoverRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s60.HandoverRequest{}, err
		}
		*s60.BridgeHandoverRequestFieldReceived(&v) = true
		*s60.BridgeHandoverRequestFieldReceivedAbsolute(&v) = true
		*s60.BridgeHandoverRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s60.HandoverRequest) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(1), bodyHandoverRequest: &v}
	}, capture: func(v s60.HandoverRequest, options aper.DecodeState) (s60.HandoverRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s60.BridgeCaptureS1APHandoverRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s60.HandoverRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s60.BridgeCompareS1APHandoverRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of HandoverResourceAllocationDescriptor.
func (HandoverResourceAllocationDescriptor) Successful() s64.HandoverRequestAcknowledgeSuccessfulBinding {
	return func() s64.HandoverRequestAcknowledgeSuccessfulBinding {
		sealed := s64.HandoverRequestAcknowledgeSuccessfulBinding{}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInfo(&sealed) = HandoverResourceAllocationProcedure().Info()
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s49.HandoverRequestAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateHandoverRequestAcknowledgeBudget(v, budget)
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s49.HandoverRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s49.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s49.HandoverRequestAcknowledge, error) {
			var v s49.HandoverRequestAcknowledge
			err := s49.BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s49.HandoverRequestAcknowledge{}, err
			}
			*s49.BridgeHandoverRequestAcknowledgeFieldReceived(&v) = true
			*s49.BridgeHandoverRequestAcknowledgeFieldReceivedAbsolute(&v) = true
			*s49.BridgeHandoverRequestAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s49.HandoverRequestAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s64.BridgeSuccessfulValueFieldBodyHandoverRequestAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s49.HandoverRequestAcknowledge, options aper.DecodeState) (s49.HandoverRequestAcknowledge, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s49.BridgeCaptureS1APHandoverRequestAcknowledge(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s49.HandoverRequestAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s49.BridgeCompareS1APHandoverRequestAcknowledge(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRequestAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of HandoverResourceAllocationDescriptor.
func (HandoverResourceAllocationDescriptor) Unsuccessful() s46.HandoverFailureUnsuccessfulBinding {
	return func() s46.HandoverFailureUnsuccessfulBinding {
		sealed := s46.HandoverFailureUnsuccessfulBinding{}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldInfo(&sealed) = HandoverResourceAllocationProcedure().Info()
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s29.HandoverFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateHandoverFailureBudget(v, budget)
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s29.HandoverFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s29.BridgeHandoverFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.HandoverFailure, error) {
			var v s29.HandoverFailure
			err := s29.BridgeHandoverFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s29.HandoverFailure{}, err
			}
			*s29.BridgeHandoverFailureFieldReceived(&v) = true
			*s29.BridgeHandoverFailureFieldReceivedAbsolute(&v) = true
			*s29.BridgeHandoverFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s29.HandoverFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s46.BridgeUnsuccessfulValueFieldBodyHandoverFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s29.HandoverFailure, options aper.DecodeState) (s29.HandoverFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s29.BridgeCaptureS1APHandoverFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s29.HandoverFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APHandoverFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s46.BridgeHandoverFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of HandoverNotificationDescriptor.
func (HandoverNotificationDescriptor) Initiating() HandoverNotifyInitiatingBinding {
	return HandoverNotifyInitiatingBinding{info: HandoverNotificationProcedure().Info(), validate: func(v *s44.HandoverNotify, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateHandoverNotifyBudget(v, budget)
	}, encode: func(v *s44.HandoverNotify, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeHandoverNotifyMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.HandoverNotify, error) {
		var v s44.HandoverNotify
		err := s44.BridgeHandoverNotifyMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.HandoverNotify{}, err
		}
		*s44.BridgeHandoverNotifyFieldReceived(&v) = true
		*s44.BridgeHandoverNotifyFieldReceivedAbsolute(&v) = true
		*s44.BridgeHandoverNotifyFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.HandoverNotify) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(2), bodyHandoverNotify: &v}
	}, capture: func(v s44.HandoverNotify, options aper.DecodeState) (s44.HandoverNotify, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s44.BridgeCaptureS1APHandoverNotify(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.HandoverNotify, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APHandoverNotify(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverNotify"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of HandoverCancelDescriptor.
func (HandoverCancelDescriptor) Initiating() HandoverCancelInitiatingBinding {
	return HandoverCancelInitiatingBinding{info: HandoverCancelProcedure().Info(), validate: func(v *s29.HandoverCancel, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateHandoverCancelBudget(v, budget)
	}, encode: func(v *s29.HandoverCancel, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s29.BridgeHandoverCancelMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s29.HandoverCancel, error) {
		var v s29.HandoverCancel
		err := s29.BridgeHandoverCancelMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s29.HandoverCancel{}, err
		}
		*s29.BridgeHandoverCancelFieldReceived(&v) = true
		*s29.BridgeHandoverCancelFieldReceivedAbsolute(&v) = true
		*s29.BridgeHandoverCancelFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s29.HandoverCancel) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(4), bodyHandoverCancel: &v}
	}, capture: func(v s29.HandoverCancel, options aper.DecodeState) (s29.HandoverCancel, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s29.BridgeCaptureS1APHandoverCancel(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s29.HandoverCancel, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s29.BridgeCompareS1APHandoverCancel(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverCancel"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of HandoverCancelDescriptor.
func (HandoverCancelDescriptor) Successful() s64.HandoverCancelAcknowledgeSuccessfulBinding {
	return func() s64.HandoverCancelAcknowledgeSuccessfulBinding {
		sealed := s64.HandoverCancelAcknowledgeSuccessfulBinding{}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInfo(&sealed) = HandoverCancelProcedure().Info()
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s29.HandoverCancelAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateHandoverCancelAcknowledgeBudget(v, budget)
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s29.HandoverCancelAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s29.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.HandoverCancelAcknowledge, error) {
			var v s29.HandoverCancelAcknowledge
			err := s29.BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s29.HandoverCancelAcknowledge{}, err
			}
			*s29.BridgeHandoverCancelAcknowledgeFieldReceived(&v) = true
			*s29.BridgeHandoverCancelAcknowledgeFieldReceivedAbsolute(&v) = true
			*s29.BridgeHandoverCancelAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s29.HandoverCancelAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s64.BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s29.HandoverCancelAcknowledge, options aper.DecodeState) (s29.HandoverCancelAcknowledge, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APHandoverCancelAcknowledge(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s29.HandoverCancelAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APHandoverCancelAcknowledge(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverCancelAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ERABSetupDescriptor.
func (ERABSetupDescriptor) Initiating() ERABSetupRequestInitiatingBinding {
	return ERABSetupRequestInitiatingBinding{info: ERABSetupProcedure().Info(), validate: func(v *s51.ERABSetupRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateERABSetupRequestBudget(v, budget)
	}, encode: func(v *s51.ERABSetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s51.BridgeERABSetupRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s51.ERABSetupRequest, error) {
		var v s51.ERABSetupRequest
		err := s51.BridgeERABSetupRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s51.ERABSetupRequest{}, err
		}
		*s51.BridgeERABSetupRequestFieldReceived(&v) = true
		*s51.BridgeERABSetupRequestFieldReceivedAbsolute(&v) = true
		*s51.BridgeERABSetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s51.ERABSetupRequest) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(5), bodyERABSetupRequest: &v}
	}, capture: func(v s51.ERABSetupRequest, options aper.DecodeState) (s51.ERABSetupRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s51.BridgeCaptureS1APERABSetupRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s51.ERABSetupRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s51.BridgeCompareS1APERABSetupRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ERABSetupDescriptor.
func (ERABSetupDescriptor) Successful() s64.ERABSetupResponseSuccessfulBinding {
	return func() s64.ERABSetupResponseSuccessfulBinding {
		sealed := s64.ERABSetupResponseSuccessfulBinding{}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldInfo(&sealed) = ERABSetupProcedure().Info()
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s57.ERABSetupResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateERABSetupResponseBudget(v, budget)
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s57.ERABSetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s57.BridgeERABSetupResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s57.ERABSetupResponse, error) {
			var v s57.ERABSetupResponse
			err := s57.BridgeERABSetupResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s57.ERABSetupResponse{}, err
			}
			*s57.BridgeERABSetupResponseFieldReceived(&v) = true
			*s57.BridgeERABSetupResponseFieldReceivedAbsolute(&v) = true
			*s57.BridgeERABSetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldInject(&sealed) = func(v s57.ERABSetupResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s64.BridgeSuccessfulValueFieldBodyERABSetupResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldCapture(&sealed) = func(v s57.ERABSetupResponse, options aper.DecodeState) (s57.ERABSetupResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options,
			)
			f := s.Begin()
			s57.BridgeCaptureS1APERABSetupResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldCompare(&sealed) = func(v s57.ERABSetupResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APERABSetupResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s64.BridgeERABSetupResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ERABModifyDescriptor.
func (ERABModifyDescriptor) Initiating() ERABModifyRequestInitiatingBinding {
	return ERABModifyRequestInitiatingBinding{info: ERABModifyProcedure().Info(), validate: func(v *s51.ERABModifyRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateERABModifyRequestBudget(v, budget)
	}, encode: func(v *s51.ERABModifyRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s51.BridgeERABModifyRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s51.ERABModifyRequest, error) {
		var v s51.ERABModifyRequest
		err := s51.BridgeERABModifyRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s51.ERABModifyRequest{}, err
		}
		*s51.BridgeERABModifyRequestFieldReceived(&v) = true
		*s51.BridgeERABModifyRequestFieldReceivedAbsolute(&v) = true
		*s51.BridgeERABModifyRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s51.ERABModifyRequest) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(6), bodyERABModifyRequest: &v}
	}, capture: func(v s51.ERABModifyRequest, options aper.DecodeState) (s51.ERABModifyRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s51.BridgeCaptureS1APERABModifyRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s51.ERABModifyRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s51.BridgeCompareS1APERABModifyRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ERABModifyDescriptor.
func (ERABModifyDescriptor) Successful() s64.ERABModifyResponseSuccessfulBinding {
	return func() s64.ERABModifyResponseSuccessfulBinding {
		sealed := s64.ERABModifyResponseSuccessfulBinding{}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldInfo(&sealed) = ERABModifyProcedure().Info()
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s57.ERABModifyResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateERABModifyResponseBudget(v, budget)
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s57.ERABModifyResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s57.BridgeERABModifyResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s57.ERABModifyResponse, error) {
			var v s57.ERABModifyResponse
			err := s57.BridgeERABModifyResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s57.ERABModifyResponse{}, err
			}
			*s57.BridgeERABModifyResponseFieldReceived(&v) = true
			*s57.BridgeERABModifyResponseFieldReceivedAbsolute(&v) = true
			*s57.BridgeERABModifyResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldInject(&sealed) = func(v s57.ERABModifyResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s64.BridgeSuccessfulValueFieldBodyERABModifyResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldCapture(&sealed) = func(v s57.ERABModifyResponse, options aper.DecodeState) (s57.ERABModifyResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeCaptureS1APERABModifyResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldCompare(&sealed) = func(v s57.ERABModifyResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APERABModifyResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeERABModifyResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ERABReleaseDescriptor.
func (ERABReleaseDescriptor) Initiating() ERABReleaseCommandInitiatingBinding {
	return ERABReleaseCommandInitiatingBinding{info: ERABReleaseProcedure().Info(), validate: func(v *s49.ERABReleaseCommand, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateERABReleaseCommandBudget(v, budget)
	}, encode: func(v *s49.ERABReleaseCommand, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s49.BridgeERABReleaseCommandMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s49.ERABReleaseCommand, error) {
		var v s49.ERABReleaseCommand
		err := s49.BridgeERABReleaseCommandMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s49.ERABReleaseCommand{}, err
		}
		*s49.BridgeERABReleaseCommandFieldReceived(&v) = true
		*s49.BridgeERABReleaseCommandFieldReceivedAbsolute(&v) = true
		*s49.BridgeERABReleaseCommandFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s49.ERABReleaseCommand) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(7), bodyERABReleaseCommand: &v}
	}, capture: func(v s49.ERABReleaseCommand, options aper.DecodeState) (s49.ERABReleaseCommand, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s49.BridgeCaptureS1APERABReleaseCommand(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s49.ERABReleaseCommand, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s49.BridgeCompareS1APERABReleaseCommand(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseCommand"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ERABReleaseDescriptor.
func (ERABReleaseDescriptor) Successful() s64.ERABReleaseResponseSuccessfulBinding {
	return func() s64.ERABReleaseResponseSuccessfulBinding {
		sealed := s64.ERABReleaseResponseSuccessfulBinding{}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldInfo(&sealed) = ERABReleaseProcedure().Info()
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s57.ERABReleaseResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateERABReleaseResponseBudget(v, budget)
		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s57.ERABReleaseResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s57.BridgeERABReleaseResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s57.ERABReleaseResponse, error) {
			var v s57.ERABReleaseResponse
			err := s57.BridgeERABReleaseResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s57.ERABReleaseResponse{}, err
			}
			*s57.BridgeERABReleaseResponseFieldReceived(&v) = true
			*s57.BridgeERABReleaseResponseFieldReceivedAbsolute(&v) = true
			*s57.BridgeERABReleaseResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldInject(&sealed) = func(v s57.ERABReleaseResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s64.BridgeSuccessfulValueFieldBodyERABReleaseResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldCapture(&sealed) = func(v s57.ERABReleaseResponse, options aper.DecodeState) (s57.ERABReleaseResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeCaptureS1APERABReleaseResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldCompare(&sealed) = func(v s57.ERABReleaseResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APERABReleaseResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeERABReleaseResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ERABReleaseIndicationDescriptor.
func (ERABReleaseIndicationDescriptor) Initiating() ERABReleaseIndicationInitiatingBinding {
	return ERABReleaseIndicationInitiatingBinding{info: ERABReleaseIndicationProcedure().Info(), validate: func(v *s57.ERABReleaseIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateERABReleaseIndicationBudget(v, budget)
	}, encode: func(v *s57.ERABReleaseIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s57.BridgeERABReleaseIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s57.ERABReleaseIndication, error) {
		var v s57.ERABReleaseIndication
		err := s57.BridgeERABReleaseIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s57.ERABReleaseIndication{}, err
		}
		*s57.BridgeERABReleaseIndicationFieldReceived(&v) = true
		*s57.BridgeERABReleaseIndicationFieldReceivedAbsolute(&v) = true
		*s57.BridgeERABReleaseIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s57.ERABReleaseIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(8), bodyERABReleaseIndication: &v}
	}, capture: func(v s57.ERABReleaseIndication, options aper.DecodeState) (s57.ERABReleaseIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s57.BridgeCaptureS1APERABReleaseIndication(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s57.ERABReleaseIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s57.BridgeCompareS1APERABReleaseIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of InitialContextSetupDescriptor.
func (InitialContextSetupDescriptor) Initiating() InitialContextSetupRequestInitiatingBinding {
	return InitialContextSetupRequestInitiatingBinding{info: InitialContextSetupProcedure().Info(), validate: func(v *s60.InitialContextSetupRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateInitialContextSetupRequestBudget(v, budget)
	}, encode: func(v *s60.InitialContextSetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s60.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s60.InitialContextSetupRequest, error) {
		var v s60.InitialContextSetupRequest
		err := s60.BridgeInitialContextSetupRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s60.InitialContextSetupRequest{}, err
		}
		*s60.BridgeInitialContextSetupRequestFieldReceived(&v) = true
		*s60.BridgeInitialContextSetupRequestFieldReceivedAbsolute(&v) = true
		*s60.BridgeInitialContextSetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s60.InitialContextSetupRequest) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(9), bodyInitialContextSetupRequest: &v}
	}, capture: func(v s60.InitialContextSetupRequest, options aper.DecodeState) (s60.InitialContextSetupRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s60.BridgeCaptureS1APInitialContextSetupRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s60.InitialContextSetupRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s60.BridgeCompareS1APInitialContextSetupRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitialContextSetupRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of InitialContextSetupDescriptor.
func (InitialContextSetupDescriptor) Successful() s64.InitialContextSetupResponseSuccessfulBinding {
	return func() s64.InitialContextSetupResponseSuccessfulBinding {
		sealed := s64.InitialContextSetupResponseSuccessfulBinding{}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldInfo(&sealed) = InitialContextSetupProcedure().Info()
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s50.InitialContextSetupResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateInitialContextSetupResponseBudget(v, budget)
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s50.InitialContextSetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s50.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s50.InitialContextSetupResponse, error) {
			var v s50.InitialContextSetupResponse
			err := s50.BridgeInitialContextSetupResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s50.InitialContextSetupResponse{}, err
			}
			*s50.BridgeInitialContextSetupResponseFieldReceived(&v) = true
			*s50.BridgeInitialContextSetupResponseFieldReceivedAbsolute(&v) = true
			*s50.BridgeInitialContextSetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldInject(&sealed) = func(v s50.InitialContextSetupResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s64.BridgeSuccessfulValueFieldBodyInitialContextSetupResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldCapture(&sealed) = func(v s50.InitialContextSetupResponse, options aper.DecodeState) (s50.InitialContextSetupResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s50.BridgeCaptureS1APInitialContextSetupResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldCompare(&sealed) = func(v s50.InitialContextSetupResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s50.BridgeCompareS1APInitialContextSetupResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeInitialContextSetupResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitialContextSetupResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of InitialContextSetupDescriptor.
func (InitialContextSetupDescriptor) Unsuccessful() s46.InitialContextSetupFailureUnsuccessfulBinding {
	return func() s46.InitialContextSetupFailureUnsuccessfulBinding {
		sealed := s46.InitialContextSetupFailureUnsuccessfulBinding{}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInfo(&sealed) = InitialContextSetupProcedure().Info()
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s30.InitialContextSetupFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateInitialContextSetupFailureBudget(v, budget)
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s30.InitialContextSetupFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.InitialContextSetupFailure, error) {
			var v s30.InitialContextSetupFailure
			err := s30.BridgeInitialContextSetupFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s30.InitialContextSetupFailure{}, err
			}
			*s30.BridgeInitialContextSetupFailureFieldReceived(&v) = true
			*s30.BridgeInitialContextSetupFailureFieldReceivedAbsolute(&v) = true
			*s30.BridgeInitialContextSetupFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s30.InitialContextSetupFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s46.BridgeUnsuccessfulValueFieldBodyInitialContextSetupFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s30.InitialContextSetupFailure, options aper.DecodeState) (s30.InitialContextSetupFailure, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APInitialContextSetupFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s30.InitialContextSetupFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APInitialContextSetupFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeInitialContextSetupFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitialContextSetupFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of DownlinkNASTransportDescriptor.
func (DownlinkNASTransportDescriptor) Initiating() DownlinkNASTransportInitiatingBinding {
	return DownlinkNASTransportInitiatingBinding{info: DownlinkNASTransportProcedure().Info(), validate: func(v *s53.DownlinkNASTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateDownlinkNASTransportBudget(v, budget)
	}, encode: func(v *s53.DownlinkNASTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s53.BridgeDownlinkNASTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s53.DownlinkNASTransport, error) {
		var v s53.DownlinkNASTransport
		err := s53.BridgeDownlinkNASTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s53.DownlinkNASTransport{}, err
		}
		*s53.BridgeDownlinkNASTransportFieldReceived(&v) = true
		*s53.BridgeDownlinkNASTransportFieldReceivedAbsolute(&v) = true
		*s53.BridgeDownlinkNASTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s53.DownlinkNASTransport) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(11), bodyDownlinkNASTransport: &v}
	}, capture: func(v s53.DownlinkNASTransport, options aper.DecodeState) (s53.DownlinkNASTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s53.BridgeCaptureS1APDownlinkNASTransport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v s53.DownlinkNASTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s53.BridgeCompareS1APDownlinkNASTransport(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DownlinkNASTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of InitialUEMessageDescriptor.
func (InitialUEMessageDescriptor) Initiating() InitialUEMessageInitiatingBinding {
	return InitialUEMessageInitiatingBinding{info: InitialUEMessageProcedure().Info(), validate: func(v *s45.InitialUEMessage, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateInitialUEMessageBudget(v, budget)
	}, encode: func(v *s45.InitialUEMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeInitialUEMessageMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.InitialUEMessage, error) {
		var v s45.InitialUEMessage
		err := s45.BridgeInitialUEMessageMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.InitialUEMessage{}, err
		}
		*s45.BridgeInitialUEMessageFieldReceived(&v) = true
		*s45.BridgeInitialUEMessageFieldReceivedAbsolute(&v) = true
		*s45.BridgeInitialUEMessageFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.InitialUEMessage) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(12), bodyInitialUEMessage: &v}
	}, capture: func(v s45.InitialUEMessage, options aper.DecodeState) (s45.InitialUEMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APInitialUEMessage(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s45.InitialUEMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APInitialUEMessage(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitialUEMessage"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ErrorIndicationDescriptor.
func (ErrorIndicationDescriptor) Initiating() ErrorIndicationInitiatingBinding {
	return ErrorIndicationInitiatingBinding{info: ErrorIndicationProcedure().Info(), validate: func(v *s36.ErrorIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateErrorIndicationBudget(v, budget)
	}, encode: func(v *s36.ErrorIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.ErrorIndication, error) {
		var v s36.ErrorIndication
		err := s36.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.ErrorIndication{}, err
		}
		*s36.BridgeErrorIndicationFieldReceived(&v) = true
		*s36.BridgeErrorIndicationFieldReceivedAbsolute(&v) = true
		*s36.BridgeErrorIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.ErrorIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(15), bodyErrorIndication: &v}
	}, capture: func(v s36.ErrorIndication, options aper.DecodeState) (s36.ErrorIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s36.BridgeCaptureS1APErrorIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.ErrorIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APErrorIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ErrorIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of NASNonDeliveryIndicationDescriptor.
func (NASNonDeliveryIndicationDescriptor) Initiating() NASNonDeliveryIndicationInitiatingBinding {
	return NASNonDeliveryIndicationInitiatingBinding{info: NASNonDeliveryIndicationProcedure().Info(), validate: func(v *s30.NASNonDeliveryIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateNASNonDeliveryIndicationBudget(v, budget)
	}, encode: func(v *s30.NASNonDeliveryIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s30.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s30.NASNonDeliveryIndication, error) {
		var v s30.NASNonDeliveryIndication
		err := s30.BridgeNASNonDeliveryIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s30.NASNonDeliveryIndication{}, err
		}
		*s30.BridgeNASNonDeliveryIndicationFieldReceived(&v) = true
		*s30.BridgeNASNonDeliveryIndicationFieldReceivedAbsolute(&v) = true
		*s30.BridgeNASNonDeliveryIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s30.NASNonDeliveryIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(16), bodyNASNonDeliveryIndication: &v}
	}, capture: func(v s30.NASNonDeliveryIndication, options aper.DecodeState) (s30.NASNonDeliveryIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s30.BridgeCaptureS1APNASNonDeliveryIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.NASNonDeliveryIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s30.BridgeCompareS1APNASNonDeliveryIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASNonDeliveryIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of DownlinkS1cdma2000tunnellingDescriptor.
func (DownlinkS1cdma2000tunnellingDescriptor) Initiating() DownlinkS1cdma2000tunnellingInitiatingBinding {
	return DownlinkS1cdma2000tunnellingInitiatingBinding{info: DownlinkS1cdma2000tunnellingProcedure().Info(), validate: func(v *s50.DownlinkS1cdma2000tunnelling, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateDownlinkS1cdma2000tunnellingBudget(v, budget)
	}, encode: func(v *s50.DownlinkS1cdma2000tunnelling, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s50.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s50.DownlinkS1cdma2000tunnelling, error) {
		var v s50.DownlinkS1cdma2000tunnelling
		err := s50.BridgeDownlinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s50.DownlinkS1cdma2000tunnelling{}, err
		}
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldReceived(&v) = true
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldReceivedAbsolute(&v) = true
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s50.DownlinkS1cdma2000tunnelling) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(19), bodyDownlinkS1cdma2000tunnelling: &v}
	}, capture: func(v s50.DownlinkS1cdma2000tunnelling, options aper.DecodeState) (s50.DownlinkS1cdma2000tunnelling, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s50.BridgeCaptureS1APDownlinkS1cdma2000tunnelling(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s50.DownlinkS1cdma2000tunnelling, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s50.BridgeCompareS1APDownlinkS1cdma2000tunnelling(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DownlinkS1cdma2000tunnelling"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBStatusTransferDescriptor.
func (ENBStatusTransferDescriptor) Initiating() ENBStatusTransferInitiatingBinding {
	return ENBStatusTransferInitiatingBinding{info: ENBStatusTransferProcedure().Info(), validate: func(v *s28.ENBStatusTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateENBStatusTransferBudget(v, budget)
	}, encode: func(v *s28.ENBStatusTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s28.BridgeENBStatusTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s28.ENBStatusTransfer, error) {
		var v s28.ENBStatusTransfer
		err := s28.BridgeENBStatusTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s28.ENBStatusTransfer{}, err
		}
		*s28.BridgeENBStatusTransferFieldReceived(&v) = true
		*s28.BridgeENBStatusTransferFieldReceivedAbsolute(&v) = true
		*s28.BridgeENBStatusTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s28.ENBStatusTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(24), bodyENBStatusTransfer: &v}
	}, capture: func(v s28.ENBStatusTransfer, options aper.DecodeState) (s28.ENBStatusTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s28.BridgeCaptureS1APENBStatusTransfer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s28.ENBStatusTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s28.BridgeCompareS1APENBStatusTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBStatusTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of MMEStatusTransferDescriptor.
func (MMEStatusTransferDescriptor) Initiating() MMEStatusTransferInitiatingBinding {
	return MMEStatusTransferInitiatingBinding{info: MMEStatusTransferProcedure().Info(), validate: func(v *s30.MMEStatusTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateMMEStatusTransferBudget(v, budget)
	}, encode: func(v *s30.MMEStatusTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s30.BridgeMMEStatusTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s30.MMEStatusTransfer, error) {
		var v s30.MMEStatusTransfer
		err := s30.BridgeMMEStatusTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s30.MMEStatusTransfer{}, err
		}
		*s30.BridgeMMEStatusTransferFieldReceived(&v) = true
		*s30.BridgeMMEStatusTransferFieldReceivedAbsolute(&v) = true
		*s30.BridgeMMEStatusTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s30.MMEStatusTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(25), bodyMMEStatusTransfer: &v}
	}, capture: func(v s30.MMEStatusTransfer, options aper.DecodeState) (s30.MMEStatusTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s30.BridgeCaptureS1APMMEStatusTransfer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.MMEStatusTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s30.BridgeCompareS1APMMEStatusTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEStatusTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of DeactivateTraceDescriptor.
func (DeactivateTraceDescriptor) Initiating() DeactivateTraceInitiatingBinding {
	return DeactivateTraceInitiatingBinding{info: DeactivateTraceProcedure().Info(), validate: func(v *s18.DeactivateTrace, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateDeactivateTraceBudget(v, budget)
	}, encode: func(v *s18.DeactivateTrace, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.BridgeDeactivateTraceMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s18.DeactivateTrace, error) {
		var v s18.DeactivateTrace
		err := s18.BridgeDeactivateTraceMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.DeactivateTrace{}, err
		}
		*s18.BridgeDeactivateTraceFieldReceived(&v) = true
		*s18.BridgeDeactivateTraceFieldReceivedAbsolute(&v) = true
		*s18.BridgeDeactivateTraceFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s18.DeactivateTrace) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(26), bodyDeactivateTrace: &v}
	}, capture: func(v s18.DeactivateTrace, options aper.DecodeState) (s18.DeactivateTrace, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s18.BridgeCaptureS1APDeactivateTrace(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s18.DeactivateTrace, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s18.BridgeCompareS1APDeactivateTrace(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DeactivateTrace"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBConfigurationUpdateDescriptor.
func (ENBConfigurationUpdateDescriptor) Initiating() ENBConfigurationUpdateInitiatingBinding {
	return ENBConfigurationUpdateInitiatingBinding{info: ENBConfigurationUpdateProcedure().Info(), validate: func(v *s54.ENBConfigurationUpdate, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateENBConfigurationUpdateBudget(v, budget)
	}, encode: func(v *s54.ENBConfigurationUpdate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s54.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s54.ENBConfigurationUpdate, error) {
		var v s54.ENBConfigurationUpdate
		err := s54.BridgeENBConfigurationUpdateMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s54.ENBConfigurationUpdate{}, err
		}
		*s54.BridgeENBConfigurationUpdateFieldReceived(&v) = true
		*s54.BridgeENBConfigurationUpdateFieldReceivedAbsolute(&v) = true
		*s54.BridgeENBConfigurationUpdateFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s54.ENBConfigurationUpdate) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(29), bodyENBConfigurationUpdate: &v}
	}, capture: func(v s54.ENBConfigurationUpdate, options aper.DecodeState) (s54.ENBConfigurationUpdate, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s54.BridgeCaptureS1APENBConfigurationUpdate(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s54.ENBConfigurationUpdate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s54.BridgeCompareS1APENBConfigurationUpdate(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationUpdate"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ENBConfigurationUpdateDescriptor.
func (ENBConfigurationUpdateDescriptor) Successful() s64.ENBConfigurationUpdateAcknowledgeSuccessfulBinding {
	return func() s64.ENBConfigurationUpdateAcknowledgeSuccessfulBinding {
		sealed := s64.ENBConfigurationUpdateAcknowledgeSuccessfulBinding{}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(&sealed) = ENBConfigurationUpdateProcedure().Info()
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s28.ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateENBConfigurationUpdateAcknowledgeBudget(v, budget)
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s28.ENBConfigurationUpdateAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s28.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ENBConfigurationUpdateAcknowledge, error) {
			var v s28.ENBConfigurationUpdateAcknowledge
			err := s28.BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s28.ENBConfigurationUpdateAcknowledge{}, err
			}
			*s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceived(&v) = true
			*s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedAbsolute(&v) = true
			*s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s28.ENBConfigurationUpdateAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s64.BridgeSuccessfulValueFieldBodyENBConfigurationUpdateAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s28.ENBConfigurationUpdateAcknowledge, options aper.DecodeState) (s28.ENBConfigurationUpdateAcknowledge, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APENBConfigurationUpdateAcknowledge(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s28.ENBConfigurationUpdateAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APENBConfigurationUpdateAcknowledge(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationUpdateAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of ENBConfigurationUpdateDescriptor.
func (ENBConfigurationUpdateDescriptor) Unsuccessful() s46.ENBConfigurationUpdateFailureUnsuccessfulBinding {
	return func() s46.ENBConfigurationUpdateFailureUnsuccessfulBinding {
		sealed := s46.ENBConfigurationUpdateFailureUnsuccessfulBinding{}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(&sealed) = ENBConfigurationUpdateProcedure().Info()
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s28.ENBConfigurationUpdateFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateENBConfigurationUpdateFailureBudget(v, budget)
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s28.ENBConfigurationUpdateFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s28.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.ENBConfigurationUpdateFailure, error) {
			var v s28.ENBConfigurationUpdateFailure
			err := s28.BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s28.ENBConfigurationUpdateFailure{}, err
			}
			*s28.BridgeENBConfigurationUpdateFailureFieldReceived(&v) = true
			*s28.BridgeENBConfigurationUpdateFailureFieldReceivedAbsolute(&v) = true
			*s28.BridgeENBConfigurationUpdateFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s28.ENBConfigurationUpdateFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s46.BridgeUnsuccessfulValueFieldBodyENBConfigurationUpdateFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s28.ENBConfigurationUpdateFailure, options aper.DecodeState) (s28.ENBConfigurationUpdateFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APENBConfigurationUpdateFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s28.ENBConfigurationUpdateFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APENBConfigurationUpdateFailure(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationUpdateFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of MMEConfigurationUpdateDescriptor.
func (MMEConfigurationUpdateDescriptor) Initiating() MMEConfigurationUpdateInitiatingBinding {
	return MMEConfigurationUpdateInitiatingBinding{info: MMEConfigurationUpdateProcedure().Info(), validate: func(v *s54.MMEConfigurationUpdate, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateMMEConfigurationUpdateBudget(v, budget)
	}, encode: func(v *s54.MMEConfigurationUpdate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s54.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s54.MMEConfigurationUpdate, error) {
		var v s54.MMEConfigurationUpdate
		err := s54.BridgeMMEConfigurationUpdateMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s54.MMEConfigurationUpdate{}, err
		}
		*s54.BridgeMMEConfigurationUpdateFieldReceived(&v) = true
		*s54.BridgeMMEConfigurationUpdateFieldReceivedAbsolute(&v) = true
		*s54.BridgeMMEConfigurationUpdateFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s54.MMEConfigurationUpdate) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(30), bodyMMEConfigurationUpdate: &v}
	}, capture: func(v s54.MMEConfigurationUpdate, options aper.DecodeState) (s54.MMEConfigurationUpdate, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s54.BridgeCaptureS1APMMEConfigurationUpdate(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s54.MMEConfigurationUpdate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s54.BridgeCompareS1APMMEConfigurationUpdate(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEConfigurationUpdate"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of MMEConfigurationUpdateDescriptor.
func (MMEConfigurationUpdateDescriptor) Successful() s64.MMEConfigurationUpdateAcknowledgeSuccessfulBinding {
	return func() s64.MMEConfigurationUpdateAcknowledgeSuccessfulBinding {
		sealed := s64.MMEConfigurationUpdateAcknowledgeSuccessfulBinding{}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(&sealed) = MMEConfigurationUpdateProcedure().Info()
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s30.MMEConfigurationUpdateAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(v, budget)
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s30.MMEConfigurationUpdateAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.MMEConfigurationUpdateAcknowledge, error) {
			var v s30.MMEConfigurationUpdateAcknowledge
			err := s30.BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s30.MMEConfigurationUpdateAcknowledge{}, err
			}
			*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceived(&v) = true
			*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedAbsolute(&v) = true
			*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s30.MMEConfigurationUpdateAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s64.BridgeSuccessfulValueFieldBodyMMEConfigurationUpdateAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s30.MMEConfigurationUpdateAcknowledge, options aper.DecodeState) (s30.MMEConfigurationUpdateAcknowledge, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APMMEConfigurationUpdateAcknowledge(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s30.MMEConfigurationUpdateAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APMMEConfigurationUpdateAcknowledge(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEConfigurationUpdateAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of MMEConfigurationUpdateDescriptor.
func (MMEConfigurationUpdateDescriptor) Unsuccessful() s46.MMEConfigurationUpdateFailureUnsuccessfulBinding {
	return func() s46.MMEConfigurationUpdateFailureUnsuccessfulBinding {
		sealed := s46.MMEConfigurationUpdateFailureUnsuccessfulBinding{}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(&sealed) = MMEConfigurationUpdateProcedure().Info()
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s30.MMEConfigurationUpdateFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateMMEConfigurationUpdateFailureBudget(v, budget)
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s30.MMEConfigurationUpdateFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.MMEConfigurationUpdateFailure, error) {
			var v s30.MMEConfigurationUpdateFailure
			err := s30.BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s30.MMEConfigurationUpdateFailure{}, err
			}
			*s30.BridgeMMEConfigurationUpdateFailureFieldReceived(&v) = true
			*s30.BridgeMMEConfigurationUpdateFailureFieldReceivedAbsolute(&v) = true
			*s30.BridgeMMEConfigurationUpdateFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s30.MMEConfigurationUpdateFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s46.BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s30.MMEConfigurationUpdateFailure, options aper.DecodeState) (s30.MMEConfigurationUpdateFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APMMEConfigurationUpdateFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s30.MMEConfigurationUpdateFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APMMEConfigurationUpdateFailure(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEConfigurationUpdateFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of LocationReportingControlDescriptor.
func (LocationReportingControlDescriptor) Initiating() LocationReportingControlInitiatingBinding {
	return LocationReportingControlInitiatingBinding{info: LocationReportingControlProcedure().Info(), validate: func(v *s31.LocationReportingControl, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateLocationReportingControlBudget(v, budget)
	}, encode: func(v *s31.LocationReportingControl, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s31.BridgeLocationReportingControlMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s31.LocationReportingControl, error) {
		var v s31.LocationReportingControl
		err := s31.BridgeLocationReportingControlMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s31.LocationReportingControl{}, err
		}
		*s31.BridgeLocationReportingControlFieldReceived(&v) = true
		*s31.BridgeLocationReportingControlFieldReceivedAbsolute(&v) = true
		*s31.BridgeLocationReportingControlFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s31.LocationReportingControl) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(31), bodyLocationReportingControl: &v}
	}, capture: func(v s31.LocationReportingControl, options aper.DecodeState) (s31.LocationReportingControl, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s31.BridgeCaptureS1APLocationReportingControl(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s31.LocationReportingControl, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s31.BridgeCompareS1APLocationReportingControl(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LocationReportingControl"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of LocationReportingFailureIndicationDescriptor.
func (LocationReportingFailureIndicationDescriptor) Initiating() LocationReportingFailureIndicationInitiatingBinding {
	return LocationReportingFailureIndicationInitiatingBinding{info: LocationReportingFailureIndicationProcedure().Info(), validate: func(v *s30.LocationReportingFailureIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateLocationReportingFailureIndicationBudget(v, budget)
	}, encode: func(v *s30.LocationReportingFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s30.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s30.LocationReportingFailureIndication, error) {
		var v s30.LocationReportingFailureIndication
		err := s30.BridgeLocationReportingFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s30.LocationReportingFailureIndication{}, err
		}
		*s30.BridgeLocationReportingFailureIndicationFieldReceived(&v) = true
		*s30.BridgeLocationReportingFailureIndicationFieldReceivedAbsolute(&v) = true
		*s30.BridgeLocationReportingFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s30.LocationReportingFailureIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(32), bodyLocationReportingFailureIndication: &v}
	}, capture: func(v s30.LocationReportingFailureIndication, options aper.DecodeState) (s30.LocationReportingFailureIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s30.BridgeCaptureS1APLocationReportingFailureIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.LocationReportingFailureIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s30.BridgeCompareS1APLocationReportingFailureIndication(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LocationReportingFailureIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of LocationReportDescriptor.
func (LocationReportDescriptor) Initiating() LocationReportInitiatingBinding {
	return LocationReportInitiatingBinding{info: LocationReportProcedure().Info(), validate: func(v *s42.LocationReport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateLocationReportBudget(v, budget)
	}, encode: func(v *s42.LocationReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s42.BridgeLocationReportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s42.LocationReport, error) {
		var v s42.LocationReport
		err := s42.BridgeLocationReportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s42.LocationReport{}, err
		}
		*s42.BridgeLocationReportFieldReceived(&v) = true
		*s42.BridgeLocationReportFieldReceivedAbsolute(&v) = true
		*s42.BridgeLocationReportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s42.LocationReport) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(33), bodyLocationReport: &v}
	}, capture: func(v s42.LocationReport, options aper.DecodeState) (s42.LocationReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s42.BridgeCaptureS1APLocationReport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s42.LocationReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s42.BridgeCompareS1APLocationReport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LocationReport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBDirectInformationTransferDescriptor.
func (ENBDirectInformationTransferDescriptor) Initiating() ENBDirectInformationTransferInitiatingBinding {
	return ENBDirectInformationTransferInitiatingBinding{info: ENBDirectInformationTransferProcedure().Info(), validate: func(v *s43.ENBDirectInformationTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateENBDirectInformationTransferBudget(v, budget)
	}, encode: func(v *s43.ENBDirectInformationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s43.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s43.ENBDirectInformationTransfer, error) {
		var v s43.ENBDirectInformationTransfer
		err := s43.BridgeENBDirectInformationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s43.ENBDirectInformationTransfer{}, err
		}
		*s43.BridgeENBDirectInformationTransferFieldReceived(&v) = true
		*s43.BridgeENBDirectInformationTransferFieldReceivedAbsolute(&v) = true
		*s43.BridgeENBDirectInformationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s43.ENBDirectInformationTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(37), bodyENBDirectInformationTransfer: &v}
	}, capture: func(v s43.ENBDirectInformationTransfer, options aper.DecodeState) (s43.ENBDirectInformationTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s43.BridgeCaptureS1APENBDirectInformationTransfer(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s43.ENBDirectInformationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s43.BridgeCompareS1APENBDirectInformationTransfer(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBDirectInformationTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of MMEDirectInformationTransferDescriptor.
func (MMEDirectInformationTransferDescriptor) Initiating() MMEDirectInformationTransferInitiatingBinding {
	return MMEDirectInformationTransferInitiatingBinding{info: MMEDirectInformationTransferProcedure().Info(), validate: func(v *s43.MMEDirectInformationTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateMMEDirectInformationTransferBudget(v, budget)
	}, encode: func(v *s43.MMEDirectInformationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s43.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s43.MMEDirectInformationTransfer, error) {
		var v s43.MMEDirectInformationTransfer
		err := s43.BridgeMMEDirectInformationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s43.MMEDirectInformationTransfer{}, err
		}
		*s43.BridgeMMEDirectInformationTransferFieldReceived(&v) = true
		*s43.BridgeMMEDirectInformationTransferFieldReceivedAbsolute(&v) = true
		*s43.BridgeMMEDirectInformationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s43.MMEDirectInformationTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(38), bodyMMEDirectInformationTransfer: &v}
	}, capture: func(v s43.MMEDirectInformationTransfer, options aper.DecodeState) (s43.MMEDirectInformationTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s43.BridgeCaptureS1APMMEDirectInformationTransfer(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s43.MMEDirectInformationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s43.BridgeCompareS1APMMEDirectInformationTransfer(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEDirectInformationTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of CellTrafficTraceDescriptor.
func (CellTrafficTraceDescriptor) Initiating() CellTrafficTraceInitiatingBinding {
	return CellTrafficTraceInitiatingBinding{info: CellTrafficTraceProcedure().Info(), validate: func(v *s25.CellTrafficTrace, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateCellTrafficTraceBudget(v, budget)
	}, encode: func(v *s25.CellTrafficTrace, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s25.BridgeCellTrafficTraceMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s25.CellTrafficTrace, error) {
		var v s25.CellTrafficTrace
		err := s25.BridgeCellTrafficTraceMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s25.CellTrafficTrace{}, err
		}
		*s25.BridgeCellTrafficTraceFieldReceived(&v) = true
		*s25.BridgeCellTrafficTraceFieldReceivedAbsolute(&v) = true
		*s25.BridgeCellTrafficTraceFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s25.CellTrafficTrace) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(42), bodyCellTrafficTrace: &v}
	}, capture: func(v s25.CellTrafficTrace, options aper.DecodeState) (s25.CellTrafficTrace, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s25.BridgeCaptureS1APCellTrafficTrace(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s25.CellTrafficTrace, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s25.BridgeCompareS1APCellTrafficTrace(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellTrafficTrace"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of KillDescriptor.
func (KillDescriptor) Initiating() KillRequestInitiatingBinding {
	return KillRequestInitiatingBinding{info: KillProcedure().Info(), validate: func(v *s42.KillRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateKillRequestBudget(v, budget)
	}, encode: func(v *s42.KillRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s42.BridgeKillRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s42.KillRequest, error) {
		var v s42.KillRequest
		err := s42.BridgeKillRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s42.KillRequest{}, err
		}
		*s42.BridgeKillRequestFieldReceived(&v) = true
		*s42.BridgeKillRequestFieldReceivedAbsolute(&v) = true
		*s42.BridgeKillRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s42.KillRequest) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(43), bodyKillRequest: &v}
	}, capture: func(v s42.KillRequest, options aper.DecodeState) (s42.KillRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s42.BridgeCaptureS1APKillRequest(&v, &s)
		var root aper.Snapshot
		s.End(
			f, &root, false)
		return v, root
	}, compare: func(v s42.KillRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s42.BridgeCompareS1APKillRequest(&v,
			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:KillRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of KillDescriptor.
func (KillDescriptor) Successful() s64.KillResponseSuccessfulBinding {
	return func() s64.KillResponseSuccessfulBinding {
		sealed := s64.KillResponseSuccessfulBinding{}
		*s64.BridgeKillResponseSuccessfulBindingFieldInfo(&sealed) = KillProcedure().Info()
		*s64.BridgeKillResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s42.KillResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateKillResponseBudget(v, budget)
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s42.KillResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s42.BridgeKillResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.KillResponse, error) {
			var v s42.KillResponse
			err := s42.BridgeKillResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s42.KillResponse{}, err
			}
			*s42.BridgeKillResponseFieldReceived(&v) = true
			*s42.BridgeKillResponseFieldReceivedAbsolute(&v) = true
			*s42.BridgeKillResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldInject(&sealed) = func(v s42.KillResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(43)
				*s64.BridgeSuccessfulValueFieldBodyKillResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldCapture(&sealed) = func(v s42.KillResponse, options aper.DecodeState) (s42.KillResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options,
			)
			f := s.Begin()
			s42.BridgeCaptureS1APKillResponse(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldCompare(&sealed) = func(v s42.KillResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s42.BridgeCompareS1APKillResponse(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeKillResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:KillResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of DownlinkUEAssociatedLPPaTransportDescriptor.
func (DownlinkUEAssociatedLPPaTransportDescriptor) Initiating() DownlinkUEAssociatedLPPaTransportInitiatingBinding {
	return DownlinkUEAssociatedLPPaTransportInitiatingBinding{info: DownlinkUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s18.DownlinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s18.DownlinkUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s18.DownlinkUEAssociatedLPPaTransport, error) {
		var v s18.DownlinkUEAssociatedLPPaTransport
		err := s18.BridgeDownlinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.DownlinkUEAssociatedLPPaTransport{}, err
		}
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s18.DownlinkUEAssociatedLPPaTransport) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(44), bodyDownlinkUEAssociatedLPPaTransport: &v}
	}, capture: func(v s18.DownlinkUEAssociatedLPPaTransport, options aper.DecodeState) (s18.DownlinkUEAssociatedLPPaTransport, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s18.BridgeCaptureS1APDownlinkUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s18.DownlinkUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s18.BridgeCompareS1APDownlinkUEAssociatedLPPaTransport(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DownlinkUEAssociatedLPPaTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of DownlinkNonUEAssociatedLPPaTransportDescriptor.
func (DownlinkNonUEAssociatedLPPaTransportDescriptor) Initiating() DownlinkNonUEAssociatedLPPaTransportInitiatingBinding {
	return DownlinkNonUEAssociatedLPPaTransportInitiatingBinding{info: DownlinkNonUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s18.DownlinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s18.DownlinkNonUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s18.DownlinkNonUEAssociatedLPPaTransport, error) {
		var v s18.DownlinkNonUEAssociatedLPPaTransport
		err := s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.DownlinkNonUEAssociatedLPPaTransport{}, err
		}
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s18.DownlinkNonUEAssociatedLPPaTransport) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(46), bodyDownlinkNonUEAssociatedLPPaTransport: &v}
	}, capture: func(v s18.DownlinkNonUEAssociatedLPPaTransport, options aper.DecodeState) (s18.DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s18.BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s18.DownlinkNonUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s18.BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransport(&v,
			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DownlinkNonUEAssociatedLPPaTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ERABModificationIndicationDescriptor.
func (ERABModificationIndicationDescriptor) Initiating() ERABModificationIndicationInitiatingBinding {
	return ERABModificationIndicationInitiatingBinding{info: ERABModificationIndicationProcedure().Info(), validate: func(v *s57.ERABModificationIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateERABModificationIndicationBudget(v, budget)
	}, encode: func(v *s57.ERABModificationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s57.BridgeERABModificationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s57.ERABModificationIndication, error) {
		var v s57.ERABModificationIndication
		err := s57.BridgeERABModificationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s57.ERABModificationIndication{}, err
		}
		*s57.BridgeERABModificationIndicationFieldReceived(&v) = true
		*s57.BridgeERABModificationIndicationFieldReceivedAbsolute(&v) = true
		*s57.BridgeERABModificationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s57.ERABModificationIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(50), bodyERABModificationIndication: &v}
	}, capture: func(v s57.ERABModificationIndication, options aper.DecodeState) (s57.ERABModificationIndication, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s57.BridgeCaptureS1APERABModificationIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s57.ERABModificationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s57.BridgeCompareS1APERABModificationIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModificationIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ERABModificationIndicationDescriptor.
func (ERABModificationIndicationDescriptor) Successful() s64.ERABModificationConfirmSuccessfulBinding {
	return func() s64.ERABModificationConfirmSuccessfulBinding {
		sealed := s64.ERABModificationConfirmSuccessfulBinding{}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldInfo(&sealed) = ERABModificationIndicationProcedure().Info()
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldValidate(&sealed) = func(v *s49.ERABModificationConfirm, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s61.BridgeValidateERABModificationConfirmBudget(v, budget)
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldEncode(&sealed) = func(v *s49.ERABModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s49.BridgeERABModificationConfirmMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s49.ERABModificationConfirm, error) {
			var v s49.ERABModificationConfirm
			err := s49.BridgeERABModificationConfirmMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s49.ERABModificationConfirm{}, err
			}
			*s49.BridgeERABModificationConfirmFieldReceived(&v) = true
			*s49.BridgeERABModificationConfirmFieldReceivedAbsolute(&v) = true
			*s49.BridgeERABModificationConfirmFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldInject(&sealed) = func(v s49.ERABModificationConfirm) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(50)
				*s64.BridgeSuccessfulValueFieldBodyERABModificationConfirm(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldCapture(&sealed) = func(v s49.ERABModificationConfirm, options aper.DecodeState) (s49.ERABModificationConfirm, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s49.BridgeCaptureS1APERABModificationConfirm(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldCompare(&sealed) = func(v s49.ERABModificationConfirm, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s49.BridgeCompareS1APERABModificationConfirm(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeERABModificationConfirmSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModificationConfirm"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ConnectionEstablishmentIndicationDescriptor.
func (ConnectionEstablishmentIndicationDescriptor) Initiating() ConnectionEstablishmentIndicationInitiatingBinding {
	return ConnectionEstablishmentIndicationInitiatingBinding{info: ConnectionEstablishmentIndicationProcedure().Info(), validate: func(v *s40.ConnectionEstablishmentIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateConnectionEstablishmentIndicationBudget(v, budget)
	}, encode: func(v *s40.ConnectionEstablishmentIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s40.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s40.ConnectionEstablishmentIndication, error) {
		var v s40.ConnectionEstablishmentIndication
		err := s40.BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s40.ConnectionEstablishmentIndication{}, err
		}
		*s40.BridgeConnectionEstablishmentIndicationFieldReceived(&v) = true
		*s40.BridgeConnectionEstablishmentIndicationFieldReceivedAbsolute(&v) = true
		*s40.BridgeConnectionEstablishmentIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s40.ConnectionEstablishmentIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(54), bodyConnectionEstablishmentIndication: &v}
	}, capture: func(v s40.ConnectionEstablishmentIndication, options aper.DecodeState) (s40.ConnectionEstablishmentIndication, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s40.BridgeCaptureS1APConnectionEstablishmentIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s40.ConnectionEstablishmentIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s40.BridgeCompareS1APConnectionEstablishmentIndication(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConnectionEstablishmentIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of NASDeliveryIndicationDescriptor.
func (NASDeliveryIndicationDescriptor) Initiating() NASDeliveryIndicationInitiatingBinding {
	return NASDeliveryIndicationInitiatingBinding{info: NASDeliveryIndicationProcedure().Info(), validate: func(v *s22.NASDeliveryIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateNASDeliveryIndicationBudget(v, budget)
	}, encode: func(v *s22.NASDeliveryIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s22.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s22.NASDeliveryIndication, error) {
		var v s22.NASDeliveryIndication
		err := s22.BridgeNASDeliveryIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s22.NASDeliveryIndication{}, err
		}
		*s22.BridgeNASDeliveryIndicationFieldReceived(&v) = true
		*s22.BridgeNASDeliveryIndicationFieldReceivedAbsolute(&v) = true
		*s22.BridgeNASDeliveryIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s22.NASDeliveryIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(57), bodyNASDeliveryIndication: &v}
	}, capture: func(v s22.NASDeliveryIndication, options aper.DecodeState) (s22.NASDeliveryIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s22.BridgeCaptureS1APNASDeliveryIndication(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s22.NASDeliveryIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s22.BridgeCompareS1APNASDeliveryIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASDeliveryIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBCPRelocationIndicationDescriptor.
func (ENBCPRelocationIndicationDescriptor) Initiating() ENBCPRelocationIndicationInitiatingBinding {
	return ENBCPRelocationIndicationInitiatingBinding{info: ENBCPRelocationIndicationProcedure().Info(), validate: func(v *s47.ENBCPRelocationIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateENBCPRelocationIndicationBudget(v, budget)
	}, encode: func(v *s47.ENBCPRelocationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s47.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s47.ENBCPRelocationIndication, error) {
		var v s47.ENBCPRelocationIndication
		err := s47.BridgeENBCPRelocationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s47.ENBCPRelocationIndication{}, err
		}
		*s47.BridgeENBCPRelocationIndicationFieldReceived(&v) = true
		*s47.BridgeENBCPRelocationIndicationFieldReceivedAbsolute(&v) = true
		*s47.BridgeENBCPRelocationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s47.ENBCPRelocationIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(60), bodyENBCPRelocationIndication: &v}
	}, capture: func(v s47.ENBCPRelocationIndication, options aper.DecodeState) (s47.ENBCPRelocationIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s47.BridgeCaptureS1APENBCPRelocationIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s47.ENBCPRelocationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s47.BridgeCompareS1APENBCPRelocationIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBCPRelocationIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of MMECPRelocationIndicationDescriptor.
func (MMECPRelocationIndicationDescriptor) Initiating() MMECPRelocationIndicationInitiatingBinding {
	return MMECPRelocationIndicationInitiatingBinding{info: MMECPRelocationIndicationProcedure().Info(), validate: func(v *s22.MMECPRelocationIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateMMECPRelocationIndicationBudget(v, budget)
	}, encode: func(v *s22.MMECPRelocationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s22.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s22.MMECPRelocationIndication, error) {
		var v s22.MMECPRelocationIndication
		err := s22.BridgeMMECPRelocationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s22.MMECPRelocationIndication{}, err
		}
		*s22.BridgeMMECPRelocationIndicationFieldReceived(&v) = true
		*s22.BridgeMMECPRelocationIndicationFieldReceivedAbsolute(&v) = true
		*s22.BridgeMMECPRelocationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s22.MMECPRelocationIndication) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(61), bodyMMECPRelocationIndication: &v}
	}, capture: func(v s22.MMECPRelocationIndication, options aper.DecodeState) (s22.MMECPRelocationIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s22.BridgeCaptureS1APMMECPRelocationIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s22.MMECPRelocationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s22.BridgeCompareS1APMMECPRelocationIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMECPRelocationIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of HandoverSuccessDescriptor.
func (HandoverSuccessDescriptor) Initiating() HandoverSuccessInitiatingBinding {
	return HandoverSuccessInitiatingBinding{info: HandoverSuccessProcedure().Info(), validate: func(v *s21.HandoverSuccess, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateHandoverSuccessBudget(v, budget)
	}, encode: func(v *s21.HandoverSuccess, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s21.BridgeHandoverSuccessMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s21.HandoverSuccess, error) {
		var v s21.HandoverSuccess
		err := s21.BridgeHandoverSuccessMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s21.HandoverSuccess{}, err
		}
		*s21.BridgeHandoverSuccessFieldReceived(&v) = true
		*s21.BridgeHandoverSuccessFieldReceivedAbsolute(&v) = true
		*s21.BridgeHandoverSuccessFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s21.HandoverSuccess) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(64), bodyHandoverSuccess: &v}
	}, capture: func(v s21.HandoverSuccess, options aper.DecodeState) (s21.HandoverSuccess, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s21.BridgeCaptureS1APHandoverSuccess(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s21.HandoverSuccess, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s21.BridgeCompareS1APHandoverSuccess(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverSuccess"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBEarlyStatusTransferDescriptor.
func (ENBEarlyStatusTransferDescriptor) Initiating() ENBEarlyStatusTransferInitiatingBinding {
	return ENBEarlyStatusTransferInitiatingBinding{info: ENBEarlyStatusTransferProcedure().Info(), validate: func(v *s47.ENBEarlyStatusTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s61.BridgeValidateENBEarlyStatusTransferBudget(v, budget)
	}, encode: func(v *s47.ENBEarlyStatusTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s47.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s47.ENBEarlyStatusTransfer, error) {
		var v s47.ENBEarlyStatusTransfer
		err := s47.BridgeENBEarlyStatusTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s47.ENBEarlyStatusTransfer{}, err
		}
		*s47.BridgeENBEarlyStatusTransferFieldReceived(&v) = true
		*s47.BridgeENBEarlyStatusTransferFieldReceivedAbsolute(&v) = true
		*s47.BridgeENBEarlyStatusTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s47.ENBEarlyStatusTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(65), bodyENBEarlyStatusTransfer: &v}
	}, capture: func(v s47.ENBEarlyStatusTransfer, options aper.DecodeState) (s47.ENBEarlyStatusTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s47.BridgeCaptureS1APENBEarlyStatusTransfer(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s47.ENBEarlyStatusTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s47.BridgeCompareS1APENBEarlyStatusTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBEarlyStatusTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of MMEEarlyStatusTransferDescriptor.
func (MMEEarlyStatusTransferDescriptor) Initiating() MMEEarlyStatusTransferInitiatingBinding {
	return MMEEarlyStatusTransferInitiatingBinding{info: MMEEarlyStatusTransferProcedure().Info(), validate: func(v *s48.MMEEarlyStatusTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateMMEEarlyStatusTransferBudget(v, budget)
	}, encode: func(v *s48.MMEEarlyStatusTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s48.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s48.MMEEarlyStatusTransfer, error) {
		var v s48.MMEEarlyStatusTransfer
		err := s48.BridgeMMEEarlyStatusTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s48.MMEEarlyStatusTransfer{}, err
		}
		*s48.BridgeMMEEarlyStatusTransferFieldReceived(&v) = true
		*s48.BridgeMMEEarlyStatusTransferFieldReceivedAbsolute(&v) = true
		*s48.BridgeMMEEarlyStatusTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s48.MMEEarlyStatusTransfer) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(66), bodyMMEEarlyStatusTransfer: &v}
	}, capture: func(v s48.MMEEarlyStatusTransfer, options aper.DecodeState) (s48.MMEEarlyStatusTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s48.BridgeCaptureS1APMMEEarlyStatusTransfer(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s48.MMEEarlyStatusTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s48.BridgeCompareS1APMMEEarlyStatusTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEEarlyStatusTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// HandoverRequiredInitiatingBinding is the concrete InitiatingBinding[HandoverRequired].
type HandoverRequiredInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.HandoverRequired, aper.DecodeState,

	) (s43.HandoverRequired, aper.Snapshot,

	)
	compare func(s43.HandoverRequired, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.HandoverRequired,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s43.HandoverRequired,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.HandoverRequired,

		error)
	inject func(s43.HandoverRequired,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredInitiatingBinding) Codec() s43.HandoverRequiredValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.HandoverRequiredValueCodec{}
	}
	return func() s43.HandoverRequiredValueCodec {
		sealed := s43.HandoverRequiredValueCodec{}
		*s43.BridgeHandoverRequiredValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeHandoverRequiredValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeHandoverRequiredValueCodecFieldEncode(&sealed) = func(value s43.HandoverRequired,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeHandoverRequiredValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeHandoverRequiredValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeHandoverRequiredValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverRequiredInitiatingBinding) Build(body s43.HandoverRequired,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverRequestInitiatingBinding is the concrete InitiatingBinding[HandoverRequest].
type HandoverRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s60.HandoverRequest, aper.DecodeState,

	) (s60.HandoverRequest, aper.Snapshot,

	)
	compare func(s60.HandoverRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s60.HandoverRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s60.HandoverRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s60.HandoverRequest,

		error)
	inject func(s60.HandoverRequest,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestInitiatingBinding) Codec() s60.HandoverRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s60.HandoverRequestValueCodec{}
	}
	return func() s60.HandoverRequestValueCodec {
		sealed := s60.HandoverRequestValueCodec{}
		*s60.BridgeHandoverRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s60.BridgeHandoverRequestValueCodecFieldDecode(&sealed) = b.decode
		*s60.BridgeHandoverRequestValueCodecFieldEncode(&sealed) = func(value s60.HandoverRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s60.BridgeHandoverRequestValueCodecFieldCapture(&sealed) = b.capture
		*s60.BridgeHandoverRequestValueCodecFieldCompare(&sealed) = b.compare
		*s60.BridgeHandoverRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverRequestInitiatingBinding) Build(body s60.HandoverRequest,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverNotifyInitiatingBinding is the concrete InitiatingBinding[HandoverNotify].
type HandoverNotifyInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.HandoverNotify, aper.DecodeState,

	) (s44.HandoverNotify, aper.Snapshot,

	)
	compare func(s44.HandoverNotify, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.HandoverNotify,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s44.HandoverNotify,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.HandoverNotify,

		error)
	inject func(s44.HandoverNotify,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyInitiatingBinding) Codec() s45.HandoverNotifyValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.HandoverNotifyValueCodec{}
	}
	return func() s45.HandoverNotifyValueCodec {
		sealed := s45.HandoverNotifyValueCodec{}
		*s45.BridgeHandoverNotifyValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeHandoverNotifyValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeHandoverNotifyValueCodecFieldEncode(&sealed) = func(value s44.HandoverNotify,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeHandoverNotifyValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeHandoverNotifyValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeHandoverNotifyValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverNotifyInitiatingBinding) Build(body s44.HandoverNotify,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverCancelInitiatingBinding is the concrete InitiatingBinding[HandoverCancel].
type HandoverCancelInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s29.HandoverCancel, aper.DecodeState,

	) (s29.HandoverCancel, aper.Snapshot,

	)
	compare func(s29.HandoverCancel, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s29.HandoverCancel,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s29.HandoverCancel,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s29.HandoverCancel,

		error)
	inject func(s29.HandoverCancel,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelInitiatingBinding) Codec() s29.HandoverCancelValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s29.HandoverCancelValueCodec{}
	}
	return func() s29.HandoverCancelValueCodec {
		sealed := s29.HandoverCancelValueCodec{}
		*s29.BridgeHandoverCancelValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s29.BridgeHandoverCancelValueCodecFieldDecode(&sealed) = b.decode
		*s29.BridgeHandoverCancelValueCodecFieldEncode(&sealed) = func(value s29.HandoverCancel,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s29.BridgeHandoverCancelValueCodecFieldCapture(&sealed) = b.capture
		*s29.BridgeHandoverCancelValueCodecFieldCompare(&sealed) = b.compare
		*s29.BridgeHandoverCancelValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCancelInitiatingBinding) Build(body s29.HandoverCancel,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABSetupRequestInitiatingBinding is the concrete InitiatingBinding[ERABSetupRequest].
type ERABSetupRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s51.ERABSetupRequest, aper.DecodeState,

	) (s51.ERABSetupRequest, aper.Snapshot,

	)
	compare func(s51.ERABSetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s51.ERABSetupRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s51.ERABSetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s51.ERABSetupRequest,

		error)
	inject func(s51.ERABSetupRequest,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ERABSetupRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupRequestInitiatingBinding) Codec() s51.ERABSetupRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.ERABSetupRequestValueCodec{}
	}
	return func() s51.ERABSetupRequestValueCodec {
		sealed := s51.ERABSetupRequestValueCodec{}
		*s51.BridgeERABSetupRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s51.BridgeERABSetupRequestValueCodecFieldDecode(&sealed) = b.decode
		*s51.BridgeERABSetupRequestValueCodecFieldEncode(&sealed) = func(value s51.ERABSetupRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s51.BridgeERABSetupRequestValueCodecFieldCapture(&sealed) = b.capture
		*s51.BridgeERABSetupRequestValueCodecFieldCompare(&sealed) = b.compare
		*s51.BridgeERABSetupRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABSetupRequestInitiatingBinding) Build(body s51.ERABSetupRequest,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABModifyRequestInitiatingBinding is the concrete InitiatingBinding[ERABModifyRequest].
type ERABModifyRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s51.ERABModifyRequest, aper.DecodeState,

	) (s51.ERABModifyRequest, aper.Snapshot,

	)
	compare func(s51.ERABModifyRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s51.ERABModifyRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s51.ERABModifyRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s51.ERABModifyRequest,

		error)
	inject func(s51.ERABModifyRequest,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ERABModifyRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyRequestInitiatingBinding) Codec() s51.ERABModifyRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.ERABModifyRequestValueCodec{}
	}
	return func() s51.ERABModifyRequestValueCodec {
		sealed := s51.ERABModifyRequestValueCodec{}
		*s51.BridgeERABModifyRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s51.BridgeERABModifyRequestValueCodecFieldDecode(&sealed) = b.decode
		*s51.BridgeERABModifyRequestValueCodecFieldEncode(&sealed) = func(value s51.ERABModifyRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s51.BridgeERABModifyRequestValueCodecFieldCapture(&sealed) = b.capture
		*s51.BridgeERABModifyRequestValueCodecFieldCompare(&sealed) = b.compare
		*s51.BridgeERABModifyRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModifyRequestInitiatingBinding) Build(body s51.ERABModifyRequest,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABReleaseCommandInitiatingBinding is the concrete InitiatingBinding[ERABReleaseCommand].
type ERABReleaseCommandInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s49.ERABReleaseCommand, aper.DecodeState,

	) (s49.ERABReleaseCommand, aper.Snapshot,

	)
	compare func(s49.ERABReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s49.ERABReleaseCommand,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s49.ERABReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s49.ERABReleaseCommand,

		error)
	inject func(s49.ERABReleaseCommand,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseCommandInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseCommandInitiatingBinding) Codec() s49.ERABReleaseCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s49.ERABReleaseCommandValueCodec{}
	}
	return func() s49.ERABReleaseCommandValueCodec {
		sealed := s49.ERABReleaseCommandValueCodec{}
		*s49.BridgeERABReleaseCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s49.BridgeERABReleaseCommandValueCodecFieldDecode(&sealed) = b.decode
		*s49.BridgeERABReleaseCommandValueCodecFieldEncode(&sealed) = func(value s49.ERABReleaseCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s49.BridgeERABReleaseCommandValueCodecFieldCapture(&sealed) = b.capture
		*s49.BridgeERABReleaseCommandValueCodecFieldCompare(&sealed) = b.compare
		*s49.BridgeERABReleaseCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABReleaseCommandInitiatingBinding) Build(body s49.ERABReleaseCommand,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABReleaseIndicationInitiatingBinding is the concrete InitiatingBinding[ERABReleaseIndication].
type ERABReleaseIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s57.ERABReleaseIndication, aper.DecodeState,

	) (s57.ERABReleaseIndication, aper.Snapshot,

	)
	compare func(s57.ERABReleaseIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.ERABReleaseIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.ERABReleaseIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.ERABReleaseIndication,

		error)
	inject func(s57.ERABReleaseIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseIndicationInitiatingBinding) Codec() s57.ERABReleaseIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.ERABReleaseIndicationValueCodec{}
	}
	return func() s57.ERABReleaseIndicationValueCodec {
		sealed := s57.ERABReleaseIndicationValueCodec{}
		*s57.BridgeERABReleaseIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeERABReleaseIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeERABReleaseIndicationValueCodecFieldEncode(&sealed) = func(value s57.ERABReleaseIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeERABReleaseIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeERABReleaseIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeERABReleaseIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABReleaseIndicationInitiatingBinding) Build(body s57.ERABReleaseIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// InitialContextSetupRequestInitiatingBinding is the concrete InitiatingBinding[InitialContextSetupRequest].
type InitialContextSetupRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s60.InitialContextSetupRequest, aper.DecodeState,

	) (s60.InitialContextSetupRequest, aper.Snapshot,

	)
	compare func(s60.InitialContextSetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s60.InitialContextSetupRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s60.InitialContextSetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s60.InitialContextSetupRequest,

		error)
	inject func(s60.InitialContextSetupRequest,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestInitiatingBinding) Codec() s60.InitialContextSetupRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s60.InitialContextSetupRequestValueCodec{}
	}
	return func() s60.InitialContextSetupRequestValueCodec {
		sealed := s60.InitialContextSetupRequestValueCodec{}
		*s60.BridgeInitialContextSetupRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s60.BridgeInitialContextSetupRequestValueCodecFieldDecode(&sealed) = b.decode
		*s60.BridgeInitialContextSetupRequestValueCodecFieldEncode(&sealed) = func(value s60.InitialContextSetupRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s60.BridgeInitialContextSetupRequestValueCodecFieldCapture(&sealed) = b.capture
		*s60.BridgeInitialContextSetupRequestValueCodecFieldCompare(&sealed) = b.compare
		*s60.BridgeInitialContextSetupRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialContextSetupRequestInitiatingBinding) Build(body s60.InitialContextSetupRequest,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// DownlinkNASTransportInitiatingBinding is the concrete InitiatingBinding[DownlinkNASTransport].
type DownlinkNASTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s53.DownlinkNASTransport, aper.DecodeState,

	) (s53.DownlinkNASTransport, aper.Snapshot,

	)
	compare func(s53.DownlinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s53.DownlinkNASTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s53.DownlinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s53.DownlinkNASTransport,

		error)
	inject func(s53.DownlinkNASTransport,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportInitiatingBinding) Codec() s53.DownlinkNASTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s53.DownlinkNASTransportValueCodec{}
	}
	return func() s53.DownlinkNASTransportValueCodec {
		sealed := s53.DownlinkNASTransportValueCodec{}
		*s53.BridgeDownlinkNASTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s53.BridgeDownlinkNASTransportValueCodecFieldDecode(&sealed) = b.decode
		*s53.BridgeDownlinkNASTransportValueCodecFieldEncode(&sealed) = func(value s53.DownlinkNASTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s53.BridgeDownlinkNASTransportValueCodecFieldCapture(&sealed) = b.capture
		*s53.BridgeDownlinkNASTransportValueCodecFieldCompare(&sealed) = b.compare
		*s53.BridgeDownlinkNASTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b DownlinkNASTransportInitiatingBinding) Build(body s53.DownlinkNASTransport,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// InitialUEMessageInitiatingBinding is the concrete InitiatingBinding[InitialUEMessage].
type InitialUEMessageInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.InitialUEMessage, aper.DecodeState,

	) (s45.InitialUEMessage, aper.Snapshot,

	)
	compare func(s45.InitialUEMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.InitialUEMessage,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s45.InitialUEMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.InitialUEMessage,

		error)
	inject func(s45.InitialUEMessage,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageInitiatingBinding) Codec() s45.InitialUEMessageValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.InitialUEMessageValueCodec{}
	}
	return func() s45.InitialUEMessageValueCodec {
		sealed := s45.InitialUEMessageValueCodec{}
		*s45.BridgeInitialUEMessageValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeInitialUEMessageValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeInitialUEMessageValueCodecFieldEncode(&sealed) = func(value s45.InitialUEMessage,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeInitialUEMessageValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeInitialUEMessageValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeInitialUEMessageValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialUEMessageInitiatingBinding) Build(body s45.InitialUEMessage,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ErrorIndicationInitiatingBinding is the concrete InitiatingBinding[ErrorIndication].
type ErrorIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.ErrorIndication, aper.DecodeState,

	) (s36.ErrorIndication, aper.Snapshot,

	)
	compare func(s36.ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.ErrorIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s36.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.ErrorIndication,

		error)
	inject func(s36.ErrorIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationInitiatingBinding) Codec() s36.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.ErrorIndicationValueCodec{}
	}
	return func() s36.ErrorIndicationValueCodec {
		sealed := s36.ErrorIndicationValueCodec{}
		*s36.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s36.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ErrorIndicationInitiatingBinding) Build(body s36.ErrorIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// NASNonDeliveryIndicationInitiatingBinding is the concrete InitiatingBinding[NASNonDeliveryIndication].
type NASNonDeliveryIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s30.NASNonDeliveryIndication, aper.DecodeState,

	) (s30.NASNonDeliveryIndication, aper.Snapshot,

	)
	compare func(s30.NASNonDeliveryIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.NASNonDeliveryIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.NASNonDeliveryIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.NASNonDeliveryIndication,

		error)
	inject func(s30.NASNonDeliveryIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationInitiatingBinding) Codec() s30.NASNonDeliveryIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.NASNonDeliveryIndicationValueCodec{}
	}
	return func() s30.NASNonDeliveryIndicationValueCodec {
		sealed := s30.NASNonDeliveryIndicationValueCodec{}
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldEncode(&sealed) = func(value s30.NASNonDeliveryIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeNASNonDeliveryIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b NASNonDeliveryIndicationInitiatingBinding) Build(body s30.NASNonDeliveryIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// DownlinkS1cdma2000tunnellingInitiatingBinding is the concrete InitiatingBinding[DownlinkS1cdma2000tunnelling].
type DownlinkS1cdma2000tunnellingInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s50.DownlinkS1cdma2000tunnelling, aper.DecodeState,

	) (s50.DownlinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(s50.DownlinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s50.DownlinkS1cdma2000tunnelling,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s50.DownlinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s50.DownlinkS1cdma2000tunnelling,

		error)
	inject func(s50.DownlinkS1cdma2000tunnelling,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b DownlinkS1cdma2000tunnellingInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkS1cdma2000tunnellingInitiatingBinding) Codec() s50.DownlinkS1cdma2000tunnellingValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s50.DownlinkS1cdma2000tunnellingValueCodec{}
	}
	return func() s50.DownlinkS1cdma2000tunnellingValueCodec {
		sealed := s50.DownlinkS1cdma2000tunnellingValueCodec{}
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldDecode(&sealed) = b.decode
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldEncode(&sealed) = func(value s50.DownlinkS1cdma2000tunnelling,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldCapture(&sealed) = b.capture
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldCompare(&sealed) = b.compare
		*s50.BridgeDownlinkS1cdma2000tunnellingValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b DownlinkS1cdma2000tunnellingInitiatingBinding) Build(body s50.DownlinkS1cdma2000tunnelling,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBStatusTransferInitiatingBinding is the concrete InitiatingBinding[ENBStatusTransfer].
type ENBStatusTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s28.ENBStatusTransfer, aper.DecodeState,

	) (s28.ENBStatusTransfer, aper.Snapshot,

	)
	compare func(s28.ENBStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.ENBStatusTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s28.ENBStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.ENBStatusTransfer,

		error)
	inject func(s28.ENBStatusTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferInitiatingBinding) Codec() s28.ENBStatusTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.ENBStatusTransferValueCodec{}
	}
	return func() s28.ENBStatusTransferValueCodec {
		sealed := s28.ENBStatusTransferValueCodec{}
		*s28.BridgeENBStatusTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeENBStatusTransferValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeENBStatusTransferValueCodecFieldEncode(&sealed) = func(value s28.ENBStatusTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeENBStatusTransferValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeENBStatusTransferValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeENBStatusTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBStatusTransferInitiatingBinding) Build(body s28.ENBStatusTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEStatusTransferInitiatingBinding is the concrete InitiatingBinding[MMEStatusTransfer].
type MMEStatusTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s30.MMEStatusTransfer, aper.DecodeState,

	) (s30.MMEStatusTransfer, aper.Snapshot,

	)
	compare func(s30.MMEStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.MMEStatusTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.MMEStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.MMEStatusTransfer,

		error)
	inject func(s30.MMEStatusTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferInitiatingBinding) Codec() s30.MMEStatusTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.MMEStatusTransferValueCodec{}
	}
	return func() s30.MMEStatusTransferValueCodec {
		sealed := s30.MMEStatusTransferValueCodec{}
		*s30.BridgeMMEStatusTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeMMEStatusTransferValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeMMEStatusTransferValueCodecFieldEncode(&sealed) = func(value s30.MMEStatusTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeMMEStatusTransferValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeMMEStatusTransferValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeMMEStatusTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEStatusTransferInitiatingBinding) Build(body s30.MMEStatusTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// DeactivateTraceInitiatingBinding is the concrete InitiatingBinding[DeactivateTrace].
type DeactivateTraceInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s18.DeactivateTrace, aper.DecodeState,

	) (s18.DeactivateTrace, aper.Snapshot,

	)
	compare func(s18.DeactivateTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s18.DeactivateTrace,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s18.DeactivateTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s18.DeactivateTrace,

		error)
	inject func(s18.DeactivateTrace,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b DeactivateTraceInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DeactivateTraceInitiatingBinding) Codec() s18.DeactivateTraceValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s18.DeactivateTraceValueCodec{}
	}
	return func() s18.DeactivateTraceValueCodec {
		sealed := s18.DeactivateTraceValueCodec{}
		*s18.BridgeDeactivateTraceValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s18.BridgeDeactivateTraceValueCodecFieldDecode(&sealed) = b.decode
		*s18.BridgeDeactivateTraceValueCodecFieldEncode(&sealed) = func(value s18.DeactivateTrace,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s18.BridgeDeactivateTraceValueCodecFieldCapture(&sealed) = b.capture
		*s18.BridgeDeactivateTraceValueCodecFieldCompare(&sealed) = b.compare
		*s18.BridgeDeactivateTraceValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b DeactivateTraceInitiatingBinding) Build(body s18.DeactivateTrace,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBConfigurationUpdateInitiatingBinding is the concrete InitiatingBinding[ENBConfigurationUpdate].
type ENBConfigurationUpdateInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s54.ENBConfigurationUpdate, aper.DecodeState,

	) (s54.ENBConfigurationUpdate, aper.Snapshot,

	)
	compare func(s54.ENBConfigurationUpdate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s54.ENBConfigurationUpdate,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s54.ENBConfigurationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s54.ENBConfigurationUpdate,

		error)
	inject func(s54.ENBConfigurationUpdate,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateInitiatingBinding) Codec() s54.ENBConfigurationUpdateValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s54.ENBConfigurationUpdateValueCodec{}
	}
	return func() s54.ENBConfigurationUpdateValueCodec {
		sealed := s54.ENBConfigurationUpdateValueCodec{}
		*s54.BridgeENBConfigurationUpdateValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s54.BridgeENBConfigurationUpdateValueCodecFieldDecode(&sealed) = b.decode
		*s54.BridgeENBConfigurationUpdateValueCodecFieldEncode(&sealed) = func(value s54.ENBConfigurationUpdate,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s54.BridgeENBConfigurationUpdateValueCodecFieldCapture(&sealed) = b.capture
		*s54.BridgeENBConfigurationUpdateValueCodecFieldCompare(&sealed) = b.compare
		*s54.BridgeENBConfigurationUpdateValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationUpdateInitiatingBinding) Build(body s54.ENBConfigurationUpdate,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEConfigurationUpdateInitiatingBinding is the concrete InitiatingBinding[MMEConfigurationUpdate].
type MMEConfigurationUpdateInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s54.MMEConfigurationUpdate, aper.DecodeState,

	) (s54.MMEConfigurationUpdate, aper.Snapshot,

	)
	compare func(s54.MMEConfigurationUpdate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s54.MMEConfigurationUpdate,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s54.MMEConfigurationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s54.MMEConfigurationUpdate,

		error)
	inject func(s54.MMEConfigurationUpdate,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateInitiatingBinding) Codec() s54.MMEConfigurationUpdateValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s54.MMEConfigurationUpdateValueCodec{}
	}
	return func() s54.MMEConfigurationUpdateValueCodec {
		sealed := s54.MMEConfigurationUpdateValueCodec{}
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldDecode(&sealed) = b.decode
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldEncode(&sealed) = func(value s54.MMEConfigurationUpdate,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldCapture(&sealed) = b.capture
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldCompare(&sealed) = b.compare
		*s54.BridgeMMEConfigurationUpdateValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateInitiatingBinding) Build(body s54.MMEConfigurationUpdate,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// LocationReportingControlInitiatingBinding is the concrete InitiatingBinding[LocationReportingControl].
type LocationReportingControlInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s31.LocationReportingControl, aper.DecodeState,

	) (s31.LocationReportingControl, aper.Snapshot,

	)
	compare func(s31.LocationReportingControl, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.LocationReportingControl,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.LocationReportingControl,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.LocationReportingControl,

		error)
	inject func(s31.LocationReportingControl,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b LocationReportingControlInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingControlInitiatingBinding) Codec() s31.LocationReportingControlValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.LocationReportingControlValueCodec{}
	}
	return func() s31.LocationReportingControlValueCodec {
		sealed := s31.LocationReportingControlValueCodec{}
		*s31.BridgeLocationReportingControlValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeLocationReportingControlValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeLocationReportingControlValueCodecFieldEncode(&sealed) = func(value s31.LocationReportingControl,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeLocationReportingControlValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeLocationReportingControlValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeLocationReportingControlValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b LocationReportingControlInitiatingBinding) Build(body s31.LocationReportingControl,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// LocationReportingFailureIndicationInitiatingBinding is the concrete InitiatingBinding[LocationReportingFailureIndication].
type LocationReportingFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s30.LocationReportingFailureIndication, aper.DecodeState,

	) (s30.LocationReportingFailureIndication, aper.Snapshot,

	)
	compare func(s30.LocationReportingFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.LocationReportingFailureIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.LocationReportingFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.LocationReportingFailureIndication,

		error)
	inject func(s30.LocationReportingFailureIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b LocationReportingFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingFailureIndicationInitiatingBinding) Codec() s30.LocationReportingFailureIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.LocationReportingFailureIndicationValueCodec{}
	}
	return func() s30.LocationReportingFailureIndicationValueCodec {
		sealed := s30.LocationReportingFailureIndicationValueCodec{}
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldEncode(&sealed) = func(value s30.LocationReportingFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeLocationReportingFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b LocationReportingFailureIndicationInitiatingBinding) Build(body s30.LocationReportingFailureIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// LocationReportInitiatingBinding is the concrete InitiatingBinding[LocationReport].
type LocationReportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s42.LocationReport, aper.DecodeState,

	) (s42.LocationReport, aper.Snapshot,

	)
	compare func(s42.LocationReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s42.LocationReport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s42.LocationReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s42.LocationReport,

		error)
	inject func(s42.LocationReport,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b LocationReportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportInitiatingBinding) Codec() s42.LocationReportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s42.LocationReportValueCodec{}
	}
	return func() s42.LocationReportValueCodec {
		sealed := s42.LocationReportValueCodec{}
		*s42.BridgeLocationReportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s42.BridgeLocationReportValueCodecFieldDecode(&sealed) = b.decode
		*s42.BridgeLocationReportValueCodecFieldEncode(&sealed) = func(value s42.LocationReport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s42.BridgeLocationReportValueCodecFieldCapture(&sealed) = b.capture
		*s42.BridgeLocationReportValueCodecFieldCompare(&sealed) = b.compare
		*s42.BridgeLocationReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b LocationReportInitiatingBinding) Build(body s42.LocationReport,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBDirectInformationTransferInitiatingBinding is the concrete InitiatingBinding[ENBDirectInformationTransfer].
type ENBDirectInformationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.ENBDirectInformationTransfer, aper.DecodeState,

	) (s43.ENBDirectInformationTransfer, aper.Snapshot,

	)
	compare func(s43.ENBDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.ENBDirectInformationTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s43.ENBDirectInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.ENBDirectInformationTransfer,

		error)
	inject func(s43.ENBDirectInformationTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBDirectInformationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBDirectInformationTransferInitiatingBinding) Codec() s43.ENBDirectInformationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.ENBDirectInformationTransferValueCodec{}
	}
	return func() s43.ENBDirectInformationTransferValueCodec {
		sealed := s43.ENBDirectInformationTransferValueCodec{}
		*s43.BridgeENBDirectInformationTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeENBDirectInformationTransferValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeENBDirectInformationTransferValueCodecFieldEncode(&sealed) = func(value s43.ENBDirectInformationTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeENBDirectInformationTransferValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeENBDirectInformationTransferValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeENBDirectInformationTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBDirectInformationTransferInitiatingBinding) Build(body s43.ENBDirectInformationTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEDirectInformationTransferInitiatingBinding is the concrete InitiatingBinding[MMEDirectInformationTransfer].
type MMEDirectInformationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.MMEDirectInformationTransfer, aper.DecodeState,

	) (s43.MMEDirectInformationTransfer, aper.Snapshot,

	)
	compare func(s43.MMEDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.MMEDirectInformationTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s43.MMEDirectInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.MMEDirectInformationTransfer,

		error)
	inject func(s43.MMEDirectInformationTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMEDirectInformationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEDirectInformationTransferInitiatingBinding) Codec() s43.MMEDirectInformationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.MMEDirectInformationTransferValueCodec{}
	}
	return func() s43.MMEDirectInformationTransferValueCodec {
		sealed := s43.MMEDirectInformationTransferValueCodec{}
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldEncode(&sealed) = func(value s43.MMEDirectInformationTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeMMEDirectInformationTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEDirectInformationTransferInitiatingBinding) Build(body s43.MMEDirectInformationTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBConfigurationTransferInitiatingBinding is the concrete InitiatingBinding[ENBConfigurationTransfer].
type ENBConfigurationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(ENBConfigurationTransfer, aper.DecodeState,

	) (ENBConfigurationTransfer, aper.Snapshot,

	)
	compare func(ENBConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*ENBConfigurationTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*ENBConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (ENBConfigurationTransfer,

		error)
	inject func(ENBConfigurationTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationTransferInitiatingBinding) Codec() ENBConfigurationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENBConfigurationTransferValueCodec{}
	}
	return ENBConfigurationTransferValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENBConfigurationTransfer,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationTransferInitiatingBinding) Build(body ENBConfigurationTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEConfigurationTransferInitiatingBinding is the concrete InitiatingBinding[MMEConfigurationTransfer].
type MMEConfigurationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(MMEConfigurationTransfer, aper.DecodeState,

	) (MMEConfigurationTransfer, aper.Snapshot,

	)
	compare func(MMEConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*MMEConfigurationTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*MMEConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (MMEConfigurationTransfer,

		error)
	inject func(MMEConfigurationTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationTransferInitiatingBinding) Codec() MMEConfigurationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return MMEConfigurationTransferValueCodec{}
	}
	return MMEConfigurationTransferValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value MMEConfigurationTransfer,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationTransferInitiatingBinding) Build(body MMEConfigurationTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// CellTrafficTraceInitiatingBinding is the concrete InitiatingBinding[CellTrafficTrace].
type CellTrafficTraceInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.CellTrafficTrace, aper.DecodeState,

	) (s25.CellTrafficTrace, aper.Snapshot,

	)
	compare func(s25.CellTrafficTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.CellTrafficTrace,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s25.CellTrafficTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.CellTrafficTrace,

		error)
	inject func(s25.CellTrafficTrace,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceInitiatingBinding) Codec() s25.CellTrafficTraceValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.CellTrafficTraceValueCodec{}
	}
	return func() s25.CellTrafficTraceValueCodec {
		sealed := s25.CellTrafficTraceValueCodec{}
		*s25.BridgeCellTrafficTraceValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeCellTrafficTraceValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeCellTrafficTraceValueCodecFieldEncode(&sealed) = func(value s25.CellTrafficTrace,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeCellTrafficTraceValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeCellTrafficTraceValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeCellTrafficTraceValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b CellTrafficTraceInitiatingBinding) Build(body s25.CellTrafficTrace,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// KillRequestInitiatingBinding is the concrete InitiatingBinding[KillRequest].
type KillRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s42.KillRequest, aper.DecodeState,

	) (s42.KillRequest, aper.Snapshot,

	)
	compare func(s42.KillRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s42.KillRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s42.KillRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s42.KillRequest,

		error)
	inject func(s42.KillRequest,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b KillRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillRequestInitiatingBinding) Codec() s42.KillRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s42.KillRequestValueCodec{}
	}
	return func() s42.KillRequestValueCodec {
		sealed := s42.KillRequestValueCodec{}
		*s42.BridgeKillRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s42.BridgeKillRequestValueCodecFieldDecode(&sealed) = b.decode
		*s42.BridgeKillRequestValueCodecFieldEncode(&sealed) = func(value s42.KillRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s42.BridgeKillRequestValueCodecFieldCapture(&sealed) = b.capture
		*s42.BridgeKillRequestValueCodecFieldCompare(&sealed) = b.compare
		*s42.BridgeKillRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b KillRequestInitiatingBinding) Build(body s42.KillRequest,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// DownlinkUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[DownlinkUEAssociatedLPPaTransport].
type DownlinkUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s18.DownlinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (s18.DownlinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s18.DownlinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s18.DownlinkUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s18.DownlinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s18.DownlinkUEAssociatedLPPaTransport,

		error)
	inject func(s18.DownlinkUEAssociatedLPPaTransport,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b DownlinkUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkUEAssociatedLPPaTransportInitiatingBinding) Codec() s18.DownlinkUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s18.DownlinkUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s18.DownlinkUEAssociatedLPPaTransportValueCodec {
		sealed := s18.DownlinkUEAssociatedLPPaTransportValueCodec{}
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s18.DownlinkUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s18.BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b DownlinkUEAssociatedLPPaTransportInitiatingBinding) Build(body s18.DownlinkUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// DownlinkNonUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[DownlinkNonUEAssociatedLPPaTransport].
type DownlinkNonUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s18.DownlinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (s18.DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s18.DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s18.DownlinkNonUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s18.DownlinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s18.DownlinkNonUEAssociatedLPPaTransport,

		error)
	inject func(s18.DownlinkNonUEAssociatedLPPaTransport,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b DownlinkNonUEAssociatedLPPaTransportInitiatingBinding) Codec() s18.DownlinkNonUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s18.DownlinkNonUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s18.DownlinkNonUEAssociatedLPPaTransportValueCodec {
		sealed := s18.DownlinkNonUEAssociatedLPPaTransportValueCodec{}
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s18.DownlinkNonUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b DownlinkNonUEAssociatedLPPaTransportInitiatingBinding) Build(body s18.DownlinkNonUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABModificationIndicationInitiatingBinding is the concrete InitiatingBinding[ERABModificationIndication].
type ERABModificationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s57.ERABModificationIndication, aper.DecodeState,

	) (s57.ERABModificationIndication, aper.Snapshot,

	)
	compare func(s57.ERABModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.ERABModificationIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.ERABModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.ERABModificationIndication,

		error)
	inject func(s57.ERABModificationIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationInitiatingBinding) Codec() s57.ERABModificationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.ERABModificationIndicationValueCodec{}
	}
	return func() s57.ERABModificationIndicationValueCodec {
		sealed := s57.ERABModificationIndicationValueCodec{}
		*s57.BridgeERABModificationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeERABModificationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeERABModificationIndicationValueCodecFieldEncode(&sealed) = func(value s57.ERABModificationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeERABModificationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeERABModificationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeERABModificationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModificationIndicationInitiatingBinding) Build(body s57.ERABModificationIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ConnectionEstablishmentIndicationInitiatingBinding is the concrete InitiatingBinding[ConnectionEstablishmentIndication].
type ConnectionEstablishmentIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s40.ConnectionEstablishmentIndication, aper.DecodeState,

	) (s40.ConnectionEstablishmentIndication, aper.Snapshot,

	)
	compare func(s40.ConnectionEstablishmentIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s40.ConnectionEstablishmentIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s40.ConnectionEstablishmentIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s40.ConnectionEstablishmentIndication,

		error)
	inject func(s40.ConnectionEstablishmentIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ConnectionEstablishmentIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ConnectionEstablishmentIndicationInitiatingBinding) Codec() s40.ConnectionEstablishmentIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s40.ConnectionEstablishmentIndicationValueCodec{}
	}
	return func() s40.ConnectionEstablishmentIndicationValueCodec {
		sealed := s40.ConnectionEstablishmentIndicationValueCodec{}
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldEncode(&sealed) = func(value s40.ConnectionEstablishmentIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s40.BridgeConnectionEstablishmentIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ConnectionEstablishmentIndicationInitiatingBinding) Build(body s40.ConnectionEstablishmentIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// NASDeliveryIndicationInitiatingBinding is the concrete InitiatingBinding[NASDeliveryIndication].
type NASDeliveryIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s22.NASDeliveryIndication, aper.DecodeState,

	) (s22.NASDeliveryIndication, aper.Snapshot,

	)
	compare func(s22.NASDeliveryIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s22.NASDeliveryIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s22.NASDeliveryIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s22.NASDeliveryIndication,

		error)
	inject func(s22.NASDeliveryIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b NASDeliveryIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASDeliveryIndicationInitiatingBinding) Codec() s22.NASDeliveryIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s22.NASDeliveryIndicationValueCodec{}
	}
	return func() s22.NASDeliveryIndicationValueCodec {
		sealed := s22.NASDeliveryIndicationValueCodec{}
		*s22.BridgeNASDeliveryIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s22.BridgeNASDeliveryIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s22.BridgeNASDeliveryIndicationValueCodecFieldEncode(&sealed) = func(value s22.NASDeliveryIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s22.BridgeNASDeliveryIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s22.BridgeNASDeliveryIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s22.BridgeNASDeliveryIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b NASDeliveryIndicationInitiatingBinding) Build(body s22.NASDeliveryIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBCPRelocationIndicationInitiatingBinding is the concrete InitiatingBinding[ENBCPRelocationIndication].
type ENBCPRelocationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.ENBCPRelocationIndication, aper.DecodeState,

	) (s47.ENBCPRelocationIndication, aper.Snapshot,

	)
	compare func(s47.ENBCPRelocationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.ENBCPRelocationIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s47.ENBCPRelocationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.ENBCPRelocationIndication,

		error)
	inject func(s47.ENBCPRelocationIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationInitiatingBinding) Codec() s47.ENBCPRelocationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.ENBCPRelocationIndicationValueCodec{}
	}
	return func() s47.ENBCPRelocationIndicationValueCodec {
		sealed := s47.ENBCPRelocationIndicationValueCodec{}
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldEncode(&sealed) = func(value s47.ENBCPRelocationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeENBCPRelocationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBCPRelocationIndicationInitiatingBinding) Build(body s47.ENBCPRelocationIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMECPRelocationIndicationInitiatingBinding is the concrete InitiatingBinding[MMECPRelocationIndication].
type MMECPRelocationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s22.MMECPRelocationIndication, aper.DecodeState,

	) (s22.MMECPRelocationIndication, aper.Snapshot,

	)
	compare func(s22.MMECPRelocationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s22.MMECPRelocationIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s22.MMECPRelocationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s22.MMECPRelocationIndication,

		error)
	inject func(s22.MMECPRelocationIndication,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMECPRelocationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMECPRelocationIndicationInitiatingBinding) Codec() s22.MMECPRelocationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s22.MMECPRelocationIndicationValueCodec{}
	}
	return func() s22.MMECPRelocationIndicationValueCodec {
		sealed := s22.MMECPRelocationIndicationValueCodec{}
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldEncode(&sealed) = func(value s22.MMECPRelocationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s22.BridgeMMECPRelocationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMECPRelocationIndicationInitiatingBinding) Build(body s22.MMECPRelocationIndication,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverSuccessInitiatingBinding is the concrete InitiatingBinding[HandoverSuccess].
type HandoverSuccessInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s21.HandoverSuccess, aper.DecodeState,

	) (s21.HandoverSuccess, aper.Snapshot,

	)
	compare func(s21.HandoverSuccess, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s21.HandoverSuccess,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s21.HandoverSuccess,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s21.HandoverSuccess,

		error)
	inject func(s21.HandoverSuccess,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b HandoverSuccessInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverSuccessInitiatingBinding) Codec() s21.HandoverSuccessValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s21.HandoverSuccessValueCodec{}
	}
	return func() s21.HandoverSuccessValueCodec {
		sealed := s21.HandoverSuccessValueCodec{}
		*s21.BridgeHandoverSuccessValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s21.BridgeHandoverSuccessValueCodecFieldDecode(&sealed) = b.decode
		*s21.BridgeHandoverSuccessValueCodecFieldEncode(&sealed) = func(value s21.HandoverSuccess,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s21.BridgeHandoverSuccessValueCodecFieldCapture(&sealed) = b.capture
		*s21.BridgeHandoverSuccessValueCodecFieldCompare(&sealed) = b.compare
		*s21.BridgeHandoverSuccessValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverSuccessInitiatingBinding) Build(body s21.HandoverSuccess,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBEarlyStatusTransferInitiatingBinding is the concrete InitiatingBinding[ENBEarlyStatusTransfer].
type ENBEarlyStatusTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.ENBEarlyStatusTransfer, aper.DecodeState,

	) (s47.ENBEarlyStatusTransfer, aper.Snapshot,

	)
	compare func(s47.ENBEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.ENBEarlyStatusTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s47.ENBEarlyStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.ENBEarlyStatusTransfer,

		error)
	inject func(s47.ENBEarlyStatusTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferInitiatingBinding) Codec() s47.ENBEarlyStatusTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.ENBEarlyStatusTransferValueCodec{}
	}
	return func() s47.ENBEarlyStatusTransferValueCodec {
		sealed := s47.ENBEarlyStatusTransferValueCodec{}
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldEncode(&sealed) = func(value s47.ENBEarlyStatusTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeENBEarlyStatusTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBEarlyStatusTransferInitiatingBinding) Build(body s47.ENBEarlyStatusTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEEarlyStatusTransferInitiatingBinding is the concrete InitiatingBinding[MMEEarlyStatusTransfer].
type MMEEarlyStatusTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s48.MMEEarlyStatusTransfer, aper.DecodeState,

	) (s48.MMEEarlyStatusTransfer, aper.Snapshot,

	)
	compare func(s48.MMEEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s48.MMEEarlyStatusTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s48.MMEEarlyStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s48.MMEEarlyStatusTransfer,

		error)
	inject func(s48.MMEEarlyStatusTransfer,

	) InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferInitiatingBinding) Codec() s48.MMEEarlyStatusTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s48.MMEEarlyStatusTransferValueCodec{}
	}
	return func() s48.MMEEarlyStatusTransferValueCodec {
		sealed := s48.MMEEarlyStatusTransferValueCodec{}
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldDecode(&sealed) = b.decode
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldEncode(&sealed) = func(value s48.MMEEarlyStatusTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldCapture(&sealed) = b.capture
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldCompare(&sealed) = b.compare
		*s48.BridgeMMEEarlyStatusTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEEarlyStatusTransferInitiatingBinding) Build(body s48.MMEEarlyStatusTransfer,

	options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEContainer(v *s64.ENBConfigurationTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEContainer(v *s64.ENBConfigurationTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainer(v *s64.MMEConfigurationTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainer(v *s64.MMEConfigurationTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationTransferSONConfigurationTransferIEBinding binds SONConfigurationTransfer to the ENBConfigurationTransferIEs object set of TS 36.413.
type ENBConfigurationTransferSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  s64.SONConfigurationTransferValueCodec
	inject func(s64.SONConfigurationTransfer,

	) s64.ENBConfigurationTransferIEValue

	get func(*s64.ENBConfigurationTransferIEValue,

	) (*s64.SONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationTransferSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationTransferSONConfigurationTransferIEBinding) Codec() s64.SONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationTransferSONConfigurationTransferIEBinding) New(value s64.SONConfigurationTransfer,

) (s64.ENBConfigurationTransferIEField, error) {
	if b.inject == nil {
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s64.BridgeSONConfigurationTransferValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return s64.ENBConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationTransferSONConfigurationTransferIEBinding) Get(field *s64.ENBConfigurationTransferIEField) (*s64.SONConfigurationTransfer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationTransferSONConfigurationTransferIEBinding binds SONConfigurationTransfer to the MMEConfigurationTransferIEs object set of TS 36.413.
type MMEConfigurationTransferSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  s64.SONConfigurationTransferValueCodec
	inject func(s64.SONConfigurationTransfer,

	) s64.MMEConfigurationTransferIEValue

	get func(*s64.MMEConfigurationTransferIEValue,

	) (*s64.SONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationTransferSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationTransferSONConfigurationTransferIEBinding) Codec() s64.SONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationTransferSONConfigurationTransferIEBinding) New(value s64.SONConfigurationTransfer,

) (s64.MMEConfigurationTransferIEField, error) {
	if b.inject == nil {
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s64.BridgeSONConfigurationTransferValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return s64.MMEConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationTransferSONConfigurationTransferIEBinding) Get(field *s64.MMEConfigurationTransferIEField) (*s64.SONConfigurationTransfer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBConfigurationTransferValueCodec is the concrete ValueCodec[ENBConfigurationTransfer].
type ENBConfigurationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransfer,

		error)
	encode func(ENBConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransfer, aper.DecodeState,

	) (ENBConfigurationTransfer, aper.Snapshot,

	)
	compare func(ENBConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferValueCodec) New(value ENBConfigurationTransfer,

) (ENBConfigurationTransferAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferValueCodec) EncodeAPER(value ENBConfigurationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationTransferValueCodec) encodeBudgetValue(value ENBConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferValueCodec) encodeChanged(value ENBConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitiatingMessageValueCodec is the concrete ValueCodec[InitiatingMessage].
type InitiatingMessageValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitiatingMessage,

		error)
	encode func(InitiatingMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitiatingMessage, aper.DecodeState,

	) (InitiatingMessage, aper.Snapshot,

	)
	compare func(InitiatingMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitiatingMessageValueCodec) New(value InitiatingMessage,

) (InitiatingMessageAPERValue, error) {
	if c.encode == nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitiatingMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitiatingMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitiatingMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitiatingMessageAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitiatingMessageAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitiatingMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitiatingMessageAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitiatingMessageValueCodec) EncodeAPER(value InitiatingMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitiatingMessageValueCodec) encodeBudgetValue(value InitiatingMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitiatingMessageValueCodec) encodeChanged(value InitiatingMessage,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationTransferValueCodec is the concrete ValueCodec[MMEConfigurationTransfer].
type MMEConfigurationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransfer,

		error)
	encode func(MMEConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransfer, aper.DecodeState,

	) (MMEConfigurationTransfer, aper.Snapshot,

	)
	compare func(MMEConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferValueCodec) New(value MMEConfigurationTransfer,

) (MMEConfigurationTransferAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferValueCodec) EncodeAPER(value MMEConfigurationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEConfigurationTransferValueCodec) encodeBudgetValue(value MMEConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferValueCodec) encodeChanged(value MMEConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(fields s64.ENBConfigurationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s64.BridgeENBConfigurationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s64.BridgeENBConfigurationTransferIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s64.BridgeENBConfigurationTransferIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// ENBConfigurationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBConfigurationTransferIEs}} codec of TS 36.413.
func ENBConfigurationTransferIEValueERABIEContainerListCodec(table s00.ENBConfigurationTransferIEValueIETable) s64.ENBConfigurationTransferIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.ENBConfigurationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s64.ENBConfigurationTransferIEValueERABIEContainerListValueCodec {
		sealed := s64.ENBConfigurationTransferIEValueERABIEContainerListValueCodec{}
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationTransferIEValueERABIEContainerList"
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.ENBConfigurationTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s64.ENBConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.ENBConfigurationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.ENBConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.ENBConfigurationTransferIEValueERABIEContainerList, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.ENBConfigurationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBConfigurationTransferIEs}} codec of TS 36.413.
func ENBConfigurationTransferIEValueIEFieldTableCodec(table s00.ENBConfigurationTransferIEValueIETable) s64.ENBConfigurationTransferIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationTransferIEValueIETableFieldBound(&table) {
		return s64.ENBConfigurationTransferIEFieldValueCodec{}
	}
	return func() s64.ENBConfigurationTransferIEFieldValueCodec {
		sealed := s64.ENBConfigurationTransferIEFieldValueCodec{}
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldPath(&sealed) = "ENBConfigurationTransferIEField"
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENBConfigurationTransferIEField, error) {
			var field s64.ENBConfigurationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEField")
			}
			return field, nil
		}
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s64.ENBConfigurationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s64.BridgeENBConfigurationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s64.ENBConfigurationTransferIEField, options aper.DecodeState) (s64.ENBConfigurationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s64.ENBConfigurationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueIEFieldTableCodec(table s00.MMEConfigurationTransferIEValueIETable) s64.MMEConfigurationTransferIEFieldValueCodec {
	if !*s00.BridgeMMEConfigurationTransferIEValueIETableFieldBound(&table) {
		return s64.MMEConfigurationTransferIEFieldValueCodec{}
	}
	return func() s64.MMEConfigurationTransferIEFieldValueCodec {
		sealed := s64.MMEConfigurationTransferIEFieldValueCodec{}
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldPath(&sealed) = "MMEConfigurationTransferIEField"
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.MMEConfigurationTransferIEField, error) {
			var field s64.MMEConfigurationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s64.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEField")
			}
			return field, nil
		}
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s64.MMEConfigurationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s64.BridgeMMEConfigurationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s64.MMEConfigurationTransferIEField, options aper.DecodeState) (s64.MMEConfigurationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s64.MMEConfigurationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{ENBConfigurationTransferIEs}} codec of TS 36.413.
func ENBConfigurationTransferIEValueIETableCodec(table s00.ENBConfigurationTransferIEValueIETable, bounds aper.ListBounds) s64.ENBConfigurationTransferIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationTransferIEValueIETableFieldBound(&table) {
		return s64.ENBConfigurationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s64.ENBConfigurationTransferIEContainerValueCodec {
		sealed := s64.ENBConfigurationTransferIEContainerValueCodec{}
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldPath(&sealed) = "ENBConfigurationTransferIEContainer"
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENBConfigurationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.ENBConfigurationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s64.ENBConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEContainer")
			}
			return fields, nil
		}
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s64.ENBConfigurationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s64.BridgeENBConfigurationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s64.ENBConfigurationTransferIEContainer, options aper.DecodeState) (s64.ENBConfigurationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s64.ENBConfigurationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueIETableCodec(table s00.MMEConfigurationTransferIEValueIETable, bounds aper.ListBounds) s64.MMEConfigurationTransferIEContainerValueCodec {
	if !*s00.BridgeMMEConfigurationTransferIEValueIETableFieldBound(&table) {
		return s64.MMEConfigurationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s64.MMEConfigurationTransferIEContainerValueCodec {
		sealed := s64.MMEConfigurationTransferIEContainerValueCodec{}
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldPath(&sealed) = "MMEConfigurationTransferIEContainer"
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.MMEConfigurationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.MMEConfigurationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s64.MMEConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s64.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEContainer")
			}
			return fields, nil
		}
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s64.MMEConfigurationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s64.BridgeMMEConfigurationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s64.MMEConfigurationTransferIEContainer, options aper.DecodeState) (s64.MMEConfigurationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s64.MMEConfigurationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBConfigurationTransferIEs}} codec of TS 36.413.
func ENBConfigurationTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationTransferIEValueIETable) s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationTransferIEValueProtocolErrorIEContainerList"
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s64.ENBConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.ENBConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBConfigurationTransferIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationTransferIEValueIETable, bounds aper.ListBounds) s64.ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationTransferIEValueIETableCodec(table, bounds)
	if *s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s64.ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s64.ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationTransferIEValueProtocolIEContainerList"
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.ENBConfigurationTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s64.ENBConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.ENBConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeENBConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.ENBConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.ENBConfigurationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s64.ENBConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.ENBConfigurationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eNBConfigurationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationTransferIEValue].
type ENBConfigurationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s64.ENBConfigurationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s64.ENBConfigurationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEField(v *s64.ENBConfigurationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s64.BridgeENBConfigurationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s64.BridgeENBConfigurationTransferIEFieldFieldReplay(v), *s64.BridgeENBConfigurationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEField(v *s64.ENBConfigurationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s64.BridgeENBConfigurationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s64.BridgeENBConfigurationTransferIEFieldFieldReplay(v), *s64.BridgeENBConfigurationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEField(v *s64.MMEConfigurationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s64.BridgeMMEConfigurationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s64.BridgeMMEConfigurationTransferIEFieldFieldReplay(v), *s64.BridgeMMEConfigurationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(v *s64.MMEConfigurationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s64.BridgeMMEConfigurationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s64.BridgeMMEConfigurationTransferIEFieldFieldReplay(v), *s64.BridgeMMEConfigurationTransferIEFieldFieldWithoutReplay(v))
}

// ENBConfigurationTransferAPERValue is the concrete APERValue[ENBConfigurationTransfer].
type ENBConfigurationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferAPERValue) WithoutReplay() ENBConfigurationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitiatingMessageAPERValue is the concrete APERValue[InitiatingMessage].
type InitiatingMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   InitiatingMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitiatingMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitiatingMessageAPERValue) WithoutReplay() InitiatingMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationTransferAPERValue is the concrete APERValue[MMEConfigurationTransfer].
type MMEConfigurationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEConfigurationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferAPERValue) WithoutReplay() MMEConfigurationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeENBConfigurationTransferIEValueCaptureS1APERABIEContainerList(v *s64.ENBConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCompareS1APERABIEContainerList(v *s64.ENBConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APERABIEContainerList(v *s64.MMEConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s64.ENBConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(v *s64.ENBConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEContainerList(v *s64.ENBConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(v *s64.MMEConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s64.ENBConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(v *s64.ENBConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s64.MMEConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}

// APERValue carries a source value and private replay state.
type APERValue[T any] struct {
	context       s00.BridgeCodecContext
	Value         T
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v APERValue[T]) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v APERValue[T]) WithoutReplay() APERValue[T] {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (T, error)
	encode  func(T, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(T, aper.DecodeState) (T, aper.Snapshot)
	compare func(T, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ValueCodec[T]) New(value T) (APERValue[T], error) {
	if c.encode == nil {
		return APERValue[T]{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return APERValue[T]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return APERValue[T]{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return APERValue[T]{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ValueCodec[T]) DecodeAPER(data []byte, options ...aper.DecodeOption) (APERValue[T], aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return APERValue[T]{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return APERValue[T]{}, report, aper.OperationError(err, c.path)
		}
		return APERValue[T]{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return APERValue[T]{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ValueCodec[T]) EncodeAPER(value APERValue[T], options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ValueCodec[T]) encodeBudgetValue(value T, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ValueCodec[T]) encodeChanged(value T, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

type IEBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   s00.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source descriptor for this binding.
func (b IEBinding[T, V]) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b IEBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates a source value and constructs its bound field.
func (b IEBinding[T, V]) New(value T) (ProtocolIEField[V], error) {
	if b.inject == nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolIEField[V]{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b IEBinding[T, V]) Get(field *ProtocolIEField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

type ExtensionBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   s00.ExtensionInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source descriptor for this binding.
func (b ExtensionBinding[T, V]) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ExtensionBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates a source value and constructs its bound field.
func (b ExtensionBinding[T, V]) New(value T) (ProtocolExtensionField[V], error) {
	if b.inject == nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolExtensionField[V]{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ExtensionBinding[T, V]) Get(field *ProtocolExtensionField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// PayloadCodec owns a typed foreign decoder and encoder. The callbacks must
// enforce the foreign schema and consume a complete value.
type PayloadCodec[T any] struct {
	decode func([]byte, s00.PayloadLimits) (T, s00.PayloadReport, error)
	encode func(T, s00.PayloadLimits) ([]byte, error)
}
type NewPayloadCodec[T any] struct{}

// Call validates the foreign decoder and encoder callbacks and returns their typed payload codec.
func (NewPayloadCodec[T]) Call(
	decode func([]byte, s00.PayloadLimits) (T, s00.PayloadReport, error),
	encode func(T, s00.PayloadLimits) ([]byte, error),
) (PayloadCodec[T], error) {
	if decode == nil || encode == nil {
		return PayloadCodec[T]{}, aper.OperationError(aper.OperationError(fmt.Errorf("%w: payload binding: nil callback", aper.ErrInvalidValue), "Payload.binding"), "PayloadCodec")
	}
	return PayloadCodec[T]{decode: decode, encode: encode}, aper.OperationError(nil, "PayloadCodec")
}

type DecodePayload[T any] struct{}

// Call decodes a foreign payload with the supplied typed codec and limits and returns its report.
func (DecodePayload[T]) Call(data []byte, codec PayloadCodec[T], limits s00.PayloadLimits) (T, s00.PayloadReport, error) {
	var zero T
	if codec.decode == nil || codec.encode == nil {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s08.BridgeEffectivePayloadLimits(limits)
	if uint64(len(data)) > limits.MaxInputBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input: %d bytes exceed limit %d", aper.ErrLimit, len(data), limits.MaxInputBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxAllocatedBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(data), limits.MaxAllocatedBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxWork {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy work", aper.ErrLimit), "Payload.input")
	}
	owned := append([]byte(nil), data...)
	value, report, err := codec.decode(owned, limits)
	if err != nil {
		return zero, report, fmt.Errorf("payload decode: %w", err)
	}
	if uint64(len(report.Deviations)) > limits.MaxReports {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload report: %d deviations exceed limit %d", aper.ErrLimit, len(report.Deviations), limits.MaxReports), "Payload.report")
	}
	return value, report, nil
}

type EncodePayload[T any] struct{}

// Call encodes a foreign value with the supplied typed payload codec and limits.
func (EncodePayload[T]) Call(value T, codec PayloadCodec[T], limits s00.PayloadLimits) ([]byte, error) {
	if codec.decode == nil || codec.encode == nil {
		return nil, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s08.BridgeEffectivePayloadLimits(limits)
	wire, err := codec.encode(value, limits)
	if err != nil {
		return nil, fmt.Errorf("payload encode: %w", err)
	}
	if uint64(len(wire)) > limits.MaxOutputBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output: %d bytes exceed limit %d", aper.ErrLimit, len(wire), limits.MaxOutputBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxAllocatedBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(wire), limits.MaxAllocatedBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxWork {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy work", aper.ErrLimit), "Payload.output")
	}
	return append([]byte(nil), wire...), nil
}

type InitiatingValue struct {
	code                                     s00.ProcedureCode
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	bodyHandoverRequired                     *s43.HandoverRequired
	bodyHandoverRequest                      *s60.HandoverRequest
	bodyHandoverNotify                       *s44.HandoverNotify
	bodyPathSwitchRequest                    *s51.PathSwitchRequest
	bodyHandoverCancel                       *s29.HandoverCancel
	bodyERABSetupRequest                     *s51.ERABSetupRequest
	bodyERABModifyRequest                    *s51.ERABModifyRequest
	bodyERABReleaseCommand                   *s49.ERABReleaseCommand
	bodyERABReleaseIndication                *s57.ERABReleaseIndication
	bodyInitialContextSetupRequest           *s60.InitialContextSetupRequest
	bodyPaging                               *s61.Paging
	bodyDownlinkNASTransport                 *s53.DownlinkNASTransport
	bodyInitialUEMessage                     *s45.InitialUEMessage
	bodyUplinkNASTransport                   *s55.UplinkNASTransport
	bodyReset                                *s45.Reset
	bodyErrorIndication                      *s36.ErrorIndication
	bodyNASNonDeliveryIndication             *s30.NASNonDeliveryIndication
	bodyS1SetupRequest                       *s54.S1SetupRequest
	bodyUEContextReleaseRequest              *s53.UEContextReleaseRequest
	bodyDownlinkS1cdma2000tunnelling         *s50.DownlinkS1cdma2000tunnelling
	bodyUplinkS1cdma2000tunnelling           *s55.UplinkS1cdma2000tunnelling
	bodyUEContextModificationRequest         *s58.UEContextModificationRequest
	bodyUECapabilityInfoIndication           *s45.UECapabilityInfoIndication
	bodyUEContextReleaseCommand              *s47.UEContextReleaseCommand
	bodyENBStatusTransfer                    *s28.ENBStatusTransfer
	bodyMMEStatusTransfer                    *s30.MMEStatusTransfer
	bodyDeactivateTrace                      *s18.DeactivateTrace
	bodyTraceStart                           *s61.TraceStart
	bodyTraceFailureIndication               *s44.TraceFailureIndication
	bodyENBConfigurationUpdate               *s54.ENBConfigurationUpdate
	bodyMMEConfigurationUpdate               *s54.MMEConfigurationUpdate
	bodyLocationReportingControl             *s31.LocationReportingControl
	bodyLocationReportingFailureIndication   *s30.LocationReportingFailureIndication
	bodyLocationReport                       *s42.LocationReport
	bodyOverloadStart                        *s52.OverloadStart
	bodyOverloadStop                         *s52.OverloadStop
	bodyWriteReplaceWarningRequest           *s64.WriteReplaceWarningRequest
	bodyENBDirectInformationTransfer         *s43.ENBDirectInformationTransfer
	bodyMMEDirectInformationTransfer         *s43.MMEDirectInformationTransfer
	bodyPrivateMessage                       *s30.PrivateMessage
	bodyENBConfigurationTransfer             *ENBConfigurationTransfer
	bodyMMEConfigurationTransfer             *MMEConfigurationTransfer
	bodyCellTrafficTrace                     *s25.CellTrafficTrace
	bodyKillRequest                          *s42.KillRequest
	bodyDownlinkUEAssociatedLPPaTransport    *s18.DownlinkUEAssociatedLPPaTransport
	bodyUplinkUEAssociatedLPPaTransport      *s55.UplinkUEAssociatedLPPaTransport
	bodyDownlinkNonUEAssociatedLPPaTransport *s18.DownlinkNonUEAssociatedLPPaTransport
	bodyUplinkNonUEAssociatedLPPaTransport   *s55.UplinkNonUEAssociatedLPPaTransport
	bodyUERadioCapabilityMatchRequest        *s46.UERadioCapabilityMatchRequest
	bodyPWSRestartIndication                 *s55.PWSRestartIndication
	bodyERABModificationIndication           *s57.ERABModificationIndication
	bodyPWSFailureIndication                 *s52.PWSFailureIndication
	bodyRerouteNASRequest                    *s31.RerouteNASRequest
	bodyUEContextModificationIndication      *s46.UEContextModificationIndication
	bodyConnectionEstablishmentIndication    *s40.ConnectionEstablishmentIndication
	bodyUEContextSuspendRequest              *s57.UEContextSuspendRequest
	bodyUEContextResumeRequest               *s48.UEContextResumeRequest
	bodyNASDeliveryIndication                *s22.NASDeliveryIndication
	bodyRetrieveUEInformation                *s36.RetrieveUEInformation
	bodyUEInformationTransfer                *s46.UEInformationTransfer
	bodyENBCPRelocationIndication            *s47.ENBCPRelocationIndication
	bodyMMECPRelocationIndication            *s22.MMECPRelocationIndication
	bodySecondaryRATDataUsageReport          *s57.SecondaryRATDataUsageReport
	bodyUERadioCapabilityIDMappingRequest    *s46.UERadioCapabilityIDMappingRequest
	bodyHandoverSuccess                      *s21.HandoverSuccess
	bodyENBEarlyStatusTransfer               *s47.ENBEarlyStatusTransfer
	bodyMMEEarlyStatusTransfer               *s48.MMEEarlyStatusTransfer
	bodyS1RemovalRequest                     *s31.S1RemovalRequest
}

// Opaque returns the retained opaque open value of InitiatingValue and reports whether the opaque alternative is selected.
func (v *InitiatingValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverRequired returns the selected HandoverRequired value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsHandoverRequired() (*s43.HandoverRequired, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverRequired == nil {
		return nil, false
	}
	return v.bodyHandoverRequired, true
}

// AsHandoverRequest returns the selected HandoverRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsHandoverRequest() (*s60.HandoverRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyHandoverRequest == nil {
		return nil, false
	}
	return v.bodyHandoverRequest, true
}

// AsHandoverNotify returns the selected HandoverNotify value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsHandoverNotify() (*s44.HandoverNotify, bool) {
	if v == nil || v.code != s00.ProcedureCode(2) || v.bodyHandoverNotify == nil {
		return nil, false
	}
	return v.bodyHandoverNotify, true
}

// AsPathSwitchRequest returns the selected PathSwitchRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsPathSwitchRequest() (*s51.PathSwitchRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyPathSwitchRequest == nil {
		return nil, false
	}
	return v.bodyPathSwitchRequest, true
}

// AsHandoverCancel returns the selected HandoverCancel value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsHandoverCancel() (*s29.HandoverCancel, bool) {
	if v == nil || v.code != s00.ProcedureCode(4) || v.bodyHandoverCancel == nil {
		return nil, false
	}
	return v.bodyHandoverCancel, true
}

// AsERABSetupRequest returns the selected ERABSetupRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsERABSetupRequest() (*s51.ERABSetupRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(5) || v.bodyERABSetupRequest == nil {
		return nil, false
	}
	return v.bodyERABSetupRequest, true
}

// AsERABModifyRequest returns the selected ERABModifyRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsERABModifyRequest() (*s51.ERABModifyRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyERABModifyRequest == nil {
		return nil, false
	}
	return v.bodyERABModifyRequest, true
}

// AsERABReleaseCommand returns the selected ERABReleaseCommand value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsERABReleaseCommand() (*s49.ERABReleaseCommand, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyERABReleaseCommand == nil {
		return nil, false
	}
	return v.bodyERABReleaseCommand, true
}

// AsERABReleaseIndication returns the selected ERABReleaseIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsERABReleaseIndication() (*s57.ERABReleaseIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(8) || v.bodyERABReleaseIndication == nil {
		return nil, false
	}
	return v.bodyERABReleaseIndication, true
}

// AsInitialContextSetupRequest returns the selected InitialContextSetupRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsInitialContextSetupRequest() (*s60.InitialContextSetupRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyInitialContextSetupRequest == nil {
		return nil, false
	}
	return v.bodyInitialContextSetupRequest, true
}

// AsPaging returns the selected Paging value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsPaging() (*s61.Paging, bool) {
	if v == nil || v.code != s00.ProcedureCode(10) || v.bodyPaging == nil {
		return nil, false
	}
	return v.bodyPaging, true
}

// AsDownlinkNASTransport returns the selected DownlinkNASTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsDownlinkNASTransport() (*s53.DownlinkNASTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(11) || v.bodyDownlinkNASTransport == nil {
		return nil, false
	}
	return v.bodyDownlinkNASTransport, true
}

// AsInitialUEMessage returns the selected InitialUEMessage value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsInitialUEMessage() (*s45.InitialUEMessage, bool) {
	if v == nil || v.code != s00.ProcedureCode(12) || v.bodyInitialUEMessage == nil {
		return nil, false
	}
	return v.bodyInitialUEMessage, true
}

// AsUplinkNASTransport returns the selected UplinkNASTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUplinkNASTransport() (*s55.UplinkNASTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(13) || v.bodyUplinkNASTransport == nil {
		return nil, false
	}
	return v.bodyUplinkNASTransport, true
}

// AsReset returns the selected Reset value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsReset() (*s45.Reset, bool) {
	if v == nil || v.code != s00.ProcedureCode(14) || v.bodyReset == nil {
		return nil, false
	}
	return v.bodyReset, true
}

// AsErrorIndication returns the selected ErrorIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsErrorIndication() (*s36.ErrorIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(15) || v.bodyErrorIndication == nil {
		return nil, false
	}
	return v.bodyErrorIndication, true
}

// AsNASNonDeliveryIndication returns the selected NASNonDeliveryIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsNASNonDeliveryIndication() (*s30.NASNonDeliveryIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(16) || v.bodyNASNonDeliveryIndication == nil {
		return nil, false
	}
	return v.bodyNASNonDeliveryIndication, true
}

// AsS1SetupRequest returns the selected S1SetupRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsS1SetupRequest() (*s54.S1SetupRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupRequest == nil {
		return nil, false
	}
	return v.bodyS1SetupRequest, true
}

// AsUEContextReleaseRequest returns the selected UEContextReleaseRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextReleaseRequest() (*s53.UEContextReleaseRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(18) || v.bodyUEContextReleaseRequest == nil {
		return nil, false
	}
	return v.bodyUEContextReleaseRequest, true
}

// AsDownlinkS1cdma2000tunnelling returns the selected DownlinkS1cdma2000tunnelling value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsDownlinkS1cdma2000tunnelling() (*s50.DownlinkS1cdma2000tunnelling, bool) {
	if v == nil || v.code != s00.ProcedureCode(19) || v.bodyDownlinkS1cdma2000tunnelling == nil {
		return nil, false
	}
	return v.bodyDownlinkS1cdma2000tunnelling, true
}

// AsUplinkS1cdma2000tunnelling returns the selected UplinkS1cdma2000tunnelling value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUplinkS1cdma2000tunnelling() (*s55.UplinkS1cdma2000tunnelling, bool) {
	if v == nil || v.code != s00.ProcedureCode(20) || v.bodyUplinkS1cdma2000tunnelling == nil {
		return nil, false
	}
	return v.bodyUplinkS1cdma2000tunnelling, true
}

// AsUEContextModificationRequest returns the selected UEContextModificationRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextModificationRequest() (*s58.UEContextModificationRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationRequest == nil {
		return nil, false
	}
	return v.bodyUEContextModificationRequest, true
}

// AsUECapabilityInfoIndication returns the selected UECapabilityInfoIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUECapabilityInfoIndication() (*s45.UECapabilityInfoIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(22) || v.bodyUECapabilityInfoIndication == nil {
		return nil, false
	}
	return v.bodyUECapabilityInfoIndication, true
}

// AsUEContextReleaseCommand returns the selected UEContextReleaseCommand value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextReleaseCommand() (*s47.UEContextReleaseCommand, bool) {
	if v == nil || v.code != s00.ProcedureCode(23) || v.bodyUEContextReleaseCommand == nil {
		return nil, false
	}
	return v.bodyUEContextReleaseCommand, true
}

// AsENBStatusTransfer returns the selected ENBStatusTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBStatusTransfer() (*s28.ENBStatusTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(24) || v.bodyENBStatusTransfer == nil {
		return nil, false
	}
	return v.bodyENBStatusTransfer, true
}

// AsMMEStatusTransfer returns the selected MMEStatusTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMEStatusTransfer() (*s30.MMEStatusTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(25) || v.bodyMMEStatusTransfer == nil {
		return nil, false
	}
	return v.bodyMMEStatusTransfer, true
}

// AsDeactivateTrace returns the selected DeactivateTrace value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsDeactivateTrace() (*s18.DeactivateTrace, bool) {
	if v == nil || v.code != s00.ProcedureCode(26) || v.bodyDeactivateTrace == nil {
		return nil, false
	}
	return v.bodyDeactivateTrace, true
}

// AsTraceStart returns the selected TraceStart value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsTraceStart() (*s61.TraceStart, bool) {
	if v == nil || v.code != s00.ProcedureCode(27) || v.bodyTraceStart == nil {
		return nil, false
	}
	return v.bodyTraceStart, true
}

// AsTraceFailureIndication returns the selected TraceFailureIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsTraceFailureIndication() (*s44.TraceFailureIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(28) || v.bodyTraceFailureIndication == nil {
		return nil, false
	}
	return v.bodyTraceFailureIndication, true
}

// AsENBConfigurationUpdate returns the selected ENBConfigurationUpdate value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBConfigurationUpdate() (*s54.ENBConfigurationUpdate, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodyENBConfigurationUpdate == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdate, true
}

// AsMMEConfigurationUpdate returns the selected MMEConfigurationUpdate value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMEConfigurationUpdate() (*s54.MMEConfigurationUpdate, bool) {
	if v == nil || v.code != s00.ProcedureCode(30) || v.bodyMMEConfigurationUpdate == nil {
		return nil, false
	}
	return v.bodyMMEConfigurationUpdate, true
}

// AsLocationReportingControl returns the selected LocationReportingControl value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsLocationReportingControl() (*s31.LocationReportingControl, bool) {
	if v == nil || v.code != s00.ProcedureCode(31) || v.bodyLocationReportingControl == nil {
		return nil, false
	}
	return v.bodyLocationReportingControl, true
}

// AsLocationReportingFailureIndication returns the selected LocationReportingFailureIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsLocationReportingFailureIndication() (*s30.LocationReportingFailureIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(32) || v.bodyLocationReportingFailureIndication == nil {
		return nil, false
	}
	return v.bodyLocationReportingFailureIndication, true
}

// AsLocationReport returns the selected LocationReport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsLocationReport() (*s42.LocationReport, bool) {
	if v == nil || v.code != s00.ProcedureCode(33) || v.bodyLocationReport == nil {
		return nil, false
	}
	return v.bodyLocationReport, true
}

// AsOverloadStart returns the selected OverloadStart value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsOverloadStart() (*s52.OverloadStart, bool) {
	if v == nil || v.code != s00.ProcedureCode(34) || v.bodyOverloadStart == nil {
		return nil, false
	}
	return v.bodyOverloadStart, true
}

// AsOverloadStop returns the selected OverloadStop value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsOverloadStop() (*s52.OverloadStop, bool) {
	if v == nil || v.code != s00.ProcedureCode(35) || v.bodyOverloadStop == nil {
		return nil, false
	}
	return v.bodyOverloadStop, true
}

// AsWriteReplaceWarningRequest returns the selected WriteReplaceWarningRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsWriteReplaceWarningRequest() (*s64.WriteReplaceWarningRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(36) || v.bodyWriteReplaceWarningRequest == nil {
		return nil, false
	}
	return v.bodyWriteReplaceWarningRequest, true
}

// AsENBDirectInformationTransfer returns the selected ENBDirectInformationTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBDirectInformationTransfer() (*s43.ENBDirectInformationTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(37) || v.bodyENBDirectInformationTransfer == nil {
		return nil, false
	}
	return v.bodyENBDirectInformationTransfer, true
}

// AsMMEDirectInformationTransfer returns the selected MMEDirectInformationTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMEDirectInformationTransfer() (*s43.MMEDirectInformationTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(38) || v.bodyMMEDirectInformationTransfer == nil {
		return nil, false
	}
	return v.bodyMMEDirectInformationTransfer, true
}

// AsPrivateMessage returns the selected PrivateMessage value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsPrivateMessage() (*s30.PrivateMessage, bool) {
	if v == nil || v.code != s00.ProcedureCode(39) || v.bodyPrivateMessage == nil {
		return nil, false
	}
	return v.bodyPrivateMessage, true
}

// AsENBConfigurationTransfer returns the selected ENBConfigurationTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBConfigurationTransfer() (*ENBConfigurationTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(40) || v.bodyENBConfigurationTransfer == nil {
		return nil, false
	}
	return v.bodyENBConfigurationTransfer, true
}

// AsMMEConfigurationTransfer returns the selected MMEConfigurationTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMEConfigurationTransfer() (*MMEConfigurationTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(41) || v.bodyMMEConfigurationTransfer == nil {
		return nil, false
	}
	return v.bodyMMEConfigurationTransfer, true
}

// AsCellTrafficTrace returns the selected CellTrafficTrace value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsCellTrafficTrace() (*s25.CellTrafficTrace, bool) {
	if v == nil || v.code != s00.ProcedureCode(42) || v.bodyCellTrafficTrace == nil {
		return nil, false
	}
	return v.bodyCellTrafficTrace, true
}

// AsKillRequest returns the selected KillRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsKillRequest() (*s42.KillRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(43) || v.bodyKillRequest == nil {
		return nil, false
	}
	return v.bodyKillRequest, true
}

// AsDownlinkUEAssociatedLPPaTransport returns the selected DownlinkUEAssociatedLPPaTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsDownlinkUEAssociatedLPPaTransport() (*s18.DownlinkUEAssociatedLPPaTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(44) || v.bodyDownlinkUEAssociatedLPPaTransport == nil {
		return nil, false
	}
	return v.bodyDownlinkUEAssociatedLPPaTransport, true
}

// AsUplinkUEAssociatedLPPaTransport returns the selected UplinkUEAssociatedLPPaTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUplinkUEAssociatedLPPaTransport() (*s55.UplinkUEAssociatedLPPaTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(45) || v.bodyUplinkUEAssociatedLPPaTransport == nil {
		return nil, false
	}
	return v.bodyUplinkUEAssociatedLPPaTransport, true
}

// AsDownlinkNonUEAssociatedLPPaTransport returns the selected DownlinkNonUEAssociatedLPPaTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsDownlinkNonUEAssociatedLPPaTransport() (*s18.DownlinkNonUEAssociatedLPPaTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(46) || v.bodyDownlinkNonUEAssociatedLPPaTransport == nil {
		return nil, false
	}
	return v.bodyDownlinkNonUEAssociatedLPPaTransport, true
}

// AsUplinkNonUEAssociatedLPPaTransport returns the selected UplinkNonUEAssociatedLPPaTransport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUplinkNonUEAssociatedLPPaTransport() (*s55.UplinkNonUEAssociatedLPPaTransport, bool) {
	if v == nil || v.code != s00.ProcedureCode(47) || v.bodyUplinkNonUEAssociatedLPPaTransport == nil {
		return nil, false
	}
	return v.bodyUplinkNonUEAssociatedLPPaTransport, true
}

// AsUERadioCapabilityMatchRequest returns the selected UERadioCapabilityMatchRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUERadioCapabilityMatchRequest() (*s46.UERadioCapabilityMatchRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(48) || v.bodyUERadioCapabilityMatchRequest == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityMatchRequest, true
}

// AsPWSRestartIndication returns the selected PWSRestartIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsPWSRestartIndication() (*s55.PWSRestartIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(49) || v.bodyPWSRestartIndication == nil {
		return nil, false
	}
	return v.bodyPWSRestartIndication, true
}

// AsERABModificationIndication returns the selected ERABModificationIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsERABModificationIndication() (*s57.ERABModificationIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(50) || v.bodyERABModificationIndication == nil {
		return nil, false
	}
	return v.bodyERABModificationIndication, true
}

// AsPWSFailureIndication returns the selected PWSFailureIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsPWSFailureIndication() (*s52.PWSFailureIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(51) || v.bodyPWSFailureIndication == nil {
		return nil, false
	}
	return v.bodyPWSFailureIndication, true
}

// AsRerouteNASRequest returns the selected RerouteNASRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsRerouteNASRequest() (*s31.RerouteNASRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(52) || v.bodyRerouteNASRequest == nil {
		return nil, false
	}
	return v.bodyRerouteNASRequest, true
}

// AsUEContextModificationIndication returns the selected UEContextModificationIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextModificationIndication() (*s46.UEContextModificationIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(53) || v.bodyUEContextModificationIndication == nil {
		return nil, false
	}
	return v.bodyUEContextModificationIndication, true
}

// AsConnectionEstablishmentIndication returns the selected ConnectionEstablishmentIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsConnectionEstablishmentIndication() (*s40.ConnectionEstablishmentIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(54) || v.bodyConnectionEstablishmentIndication == nil {
		return nil, false
	}
	return v.bodyConnectionEstablishmentIndication, true
}

// AsUEContextSuspendRequest returns the selected UEContextSuspendRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextSuspendRequest() (*s57.UEContextSuspendRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(55) || v.bodyUEContextSuspendRequest == nil {
		return nil, false
	}
	return v.bodyUEContextSuspendRequest, true
}

// AsUEContextResumeRequest returns the selected UEContextResumeRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEContextResumeRequest() (*s48.UEContextResumeRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUEContextResumeRequest == nil {
		return nil, false
	}
	return v.bodyUEContextResumeRequest, true
}

// AsNASDeliveryIndication returns the selected NASDeliveryIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsNASDeliveryIndication() (*s22.NASDeliveryIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(57) || v.bodyNASDeliveryIndication == nil {
		return nil, false
	}
	return v.bodyNASDeliveryIndication, true
}

// AsRetrieveUEInformation returns the selected RetrieveUEInformation value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsRetrieveUEInformation() (*s36.RetrieveUEInformation, bool) {
	if v == nil || v.code != s00.ProcedureCode(58) || v.bodyRetrieveUEInformation == nil {
		return nil, false
	}
	return v.bodyRetrieveUEInformation, true
}

// AsUEInformationTransfer returns the selected UEInformationTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUEInformationTransfer() (*s46.UEInformationTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(59) || v.bodyUEInformationTransfer == nil {
		return nil, false
	}
	return v.bodyUEInformationTransfer, true
}

// AsENBCPRelocationIndication returns the selected ENBCPRelocationIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBCPRelocationIndication() (*s47.ENBCPRelocationIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(60) || v.bodyENBCPRelocationIndication == nil {
		return nil, false
	}
	return v.bodyENBCPRelocationIndication, true
}

// AsMMECPRelocationIndication returns the selected MMECPRelocationIndication value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMECPRelocationIndication() (*s22.MMECPRelocationIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(61) || v.bodyMMECPRelocationIndication == nil {
		return nil, false
	}
	return v.bodyMMECPRelocationIndication, true
}

// AsSecondaryRATDataUsageReport returns the selected SecondaryRATDataUsageReport value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsSecondaryRATDataUsageReport() (*s57.SecondaryRATDataUsageReport, bool) {
	if v == nil || v.code != s00.ProcedureCode(62) || v.bodySecondaryRATDataUsageReport == nil {
		return nil, false
	}
	return v.bodySecondaryRATDataUsageReport, true
}

// AsUERadioCapabilityIDMappingRequest returns the selected UERadioCapabilityIDMappingRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsUERadioCapabilityIDMappingRequest() (*s46.UERadioCapabilityIDMappingRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(63) || v.bodyUERadioCapabilityIDMappingRequest == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityIDMappingRequest, true
}

// AsHandoverSuccess returns the selected HandoverSuccess value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsHandoverSuccess() (*s21.HandoverSuccess, bool) {
	if v == nil || v.code != s00.ProcedureCode(64) || v.bodyHandoverSuccess == nil {
		return nil, false
	}
	return v.bodyHandoverSuccess, true
}

// AsENBEarlyStatusTransfer returns the selected ENBEarlyStatusTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsENBEarlyStatusTransfer() (*s47.ENBEarlyStatusTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(65) || v.bodyENBEarlyStatusTransfer == nil {
		return nil, false
	}
	return v.bodyENBEarlyStatusTransfer, true
}

// AsMMEEarlyStatusTransfer returns the selected MMEEarlyStatusTransfer value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsMMEEarlyStatusTransfer() (*s48.MMEEarlyStatusTransfer, bool) {
	if v == nil || v.code != s00.ProcedureCode(66) || v.bodyMMEEarlyStatusTransfer == nil {
		return nil, false
	}
	return v.bodyMMEEarlyStatusTransfer, true
}

// AsS1RemovalRequest returns the selected S1RemovalRequest value of InitiatingValue and reports whether that alternative is active.
func (v *InitiatingValue) AsS1RemovalRequest() (*s31.S1RemovalRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalRequest == nil {
		return nil, false
	}
	return v.bodyS1RemovalRequest, true
}
func BridgeDecodeInitiatingValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (InitiatingValue, error) {
	v := InitiatingValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s43.HandoverRequired
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s43.BridgeHandoverRequiredMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.HandoverRequired:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRequired")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s43.BridgeHandoverRequiredFieldPerPadding(&body) = padding
		*s43.BridgeHandoverRequiredFieldReceived(&body) = true
		raw.RetainContents(s43.BridgeHandoverRequiredFieldReceivedBytes(&body))
		*s43.BridgeHandoverRequiredFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverRequired = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(1):
		var body s60.HandoverRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s60.BridgeHandoverRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.HandoverRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s60.BridgeHandoverRequestFieldPerPadding(&body) = padding
		*s60.BridgeHandoverRequestFieldReceived(&body) = true
		raw.RetainContents(s60.BridgeHandoverRequestFieldReceivedBytes(&body))
		*s60.BridgeHandoverRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(2):
		var body s44.HandoverNotify
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s44.BridgeHandoverNotifyMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.HandoverNotify:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverNotify")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s44.BridgeHandoverNotifyFieldPerPadding(&body) = padding
		*s44.BridgeHandoverNotifyFieldReceived(&body) = true
		raw.RetainContents(s44.BridgeHandoverNotifyFieldReceivedBytes(&body))
		*s44.BridgeHandoverNotifyFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverNotify = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(3):
		var body s51.PathSwitchRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s51.BridgePathSwitchRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.PathSwitchRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s51.BridgePathSwitchRequestFieldPerPadding(&body) = padding
		*s51.BridgePathSwitchRequestFieldReceived(&body) = true
		raw.RetainContents(s51.BridgePathSwitchRequestFieldReceivedBytes(&body))
		*s51.BridgePathSwitchRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPathSwitchRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(4):
		var body s29.HandoverCancel
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s29.BridgeHandoverCancelMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.HandoverCancel:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCancel")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s29.BridgeHandoverCancelFieldPerPadding(&body) = padding
		*s29.BridgeHandoverCancelFieldReceived(&body) = true
		raw.RetainContents(s29.BridgeHandoverCancelFieldReceivedBytes(&body))
		*s29.BridgeHandoverCancelFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverCancel = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(5):
		var body s51.ERABSetupRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s51.BridgeERABSetupRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ERABSetupRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s51.BridgeERABSetupRequestFieldPerPadding(&body) = padding
		*s51.BridgeERABSetupRequestFieldReceived(&body) = true
		raw.RetainContents(s51.BridgeERABSetupRequestFieldReceivedBytes(&body))
		*s51.BridgeERABSetupRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABSetupRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(6):
		var body s51.ERABModifyRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s51.BridgeERABModifyRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ERABModifyRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModifyRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s51.BridgeERABModifyRequestFieldPerPadding(&body) = padding
		*s51.BridgeERABModifyRequestFieldReceived(&body) = true
		raw.RetainContents(s51.BridgeERABModifyRequestFieldReceivedBytes(&body))
		*s51.BridgeERABModifyRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModifyRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(7):
		var body s49.ERABReleaseCommand
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s49.BridgeERABReleaseCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ERABReleaseCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABReleaseCommand")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s49.BridgeERABReleaseCommandFieldPerPadding(&body) = padding
		*s49.BridgeERABReleaseCommandFieldReceived(&body) = true
		raw.RetainContents(s49.BridgeERABReleaseCommandFieldReceivedBytes(&body))
		*s49.BridgeERABReleaseCommandFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABReleaseCommand = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(8):
		var body s57.ERABReleaseIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeERABReleaseIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ERABReleaseIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABReleaseIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s57.BridgeERABReleaseIndicationFieldPerPadding(&body) = padding
		*s57.BridgeERABReleaseIndicationFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeERABReleaseIndicationFieldReceivedBytes(&body))
		*s57.BridgeERABReleaseIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABReleaseIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body s60.InitialContextSetupRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s60.BridgeInitialContextSetupRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.InitialContextSetupRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialContextSetupRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s60.BridgeInitialContextSetupRequestFieldPerPadding(&body) = padding
		*s60.BridgeInitialContextSetupRequestFieldReceived(&body) = true
		raw.RetainContents(s60.BridgeInitialContextSetupRequestFieldReceivedBytes(&body))
		*s60.BridgeInitialContextSetupRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialContextSetupRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(10):
		var body s61.Paging
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s61.BridgePagingMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.Paging:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Paging")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s61.BridgePagingFieldPerPadding(&body) = padding
		*s61.BridgePagingFieldReceived(&body) = true
		raw.RetainContents(s61.BridgePagingFieldReceivedBytes(&body))
		*s61.BridgePagingFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPaging = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(11):
		var body s53.DownlinkNASTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s53.BridgeDownlinkNASTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.DownlinkNASTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DownlinkNASTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s53.BridgeDownlinkNASTransportFieldPerPadding(&body) = padding
		*s53.BridgeDownlinkNASTransportFieldReceived(&body) = true
		raw.RetainContents(s53.BridgeDownlinkNASTransportFieldReceivedBytes(&body))
		*s53.BridgeDownlinkNASTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyDownlinkNASTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(12):
		var body s45.InitialUEMessage
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeInitialUEMessageMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.InitialUEMessage:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialUEMessage")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s45.BridgeInitialUEMessageFieldPerPadding(&body) = padding
		*s45.BridgeInitialUEMessageFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeInitialUEMessageFieldReceivedBytes(&body))
		*s45.BridgeInitialUEMessageFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialUEMessage = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(13):
		var body s55.UplinkNASTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgeUplinkNASTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UplinkNASTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UplinkNASTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s55.BridgeUplinkNASTransportFieldPerPadding(&body) = padding
		*s55.BridgeUplinkNASTransportFieldReceived(&body) = true
		raw.RetainContents(s55.BridgeUplinkNASTransportFieldReceivedBytes(&body))
		*s55.BridgeUplinkNASTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUplinkNASTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(14):
		var body s45.Reset
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeResetMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.Reset:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Reset")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s45.BridgeResetFieldPerPadding(&body) = padding
		*s45.BridgeResetFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeResetFieldReceivedBytes(&body))
		*s45.BridgeResetFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyReset = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(15):
		var body s36.ErrorIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeErrorIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ErrorIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ErrorIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s36.BridgeErrorIndicationFieldPerPadding(&body) = padding
		*s36.BridgeErrorIndicationFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeErrorIndicationFieldReceivedBytes(&body))
		*s36.BridgeErrorIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyErrorIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(16):
		var body s30.NASNonDeliveryIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeNASNonDeliveryIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.NASNonDeliveryIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NASNonDeliveryIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s30.BridgeNASNonDeliveryIndicationFieldPerPadding(&body) = padding
		*s30.BridgeNASNonDeliveryIndicationFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeNASNonDeliveryIndicationFieldReceivedBytes(&body))
		*s30.BridgeNASNonDeliveryIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyNASNonDeliveryIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s54.S1SetupRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s54.BridgeS1SetupRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.S1SetupRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s54.BridgeS1SetupRequestFieldPerPadding(&body) = padding
		*s54.BridgeS1SetupRequestFieldReceived(&body) = true
		raw.RetainContents(s54.BridgeS1SetupRequestFieldReceivedBytes(&body))
		*s54.BridgeS1SetupRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(18):
		var body s53.UEContextReleaseRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s53.BridgeUEContextReleaseRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextReleaseRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextReleaseRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s53.BridgeUEContextReleaseRequestFieldPerPadding(&body) = padding
		*s53.BridgeUEContextReleaseRequestFieldReceived(&body) = true
		raw.RetainContents(s53.BridgeUEContextReleaseRequestFieldReceivedBytes(&body))
		*s53.BridgeUEContextReleaseRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextReleaseRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(19):
		var body s50.DownlinkS1cdma2000tunnelling
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s50.BridgeDownlinkS1cdma2000tunnellingMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.DownlinkS1cdma2000tunnelling:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DownlinkS1cdma2000tunnelling")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldPerPadding(&body) = padding
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldReceived(&body) = true
		raw.RetainContents(s50.BridgeDownlinkS1cdma2000tunnellingFieldReceivedBytes(&body))
		*s50.BridgeDownlinkS1cdma2000tunnellingFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyDownlinkS1cdma2000tunnelling = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(20):
		var body s55.UplinkS1cdma2000tunnelling
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UplinkS1cdma2000tunnelling:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UplinkS1cdma2000tunnelling")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s55.BridgeUplinkS1cdma2000tunnellingFieldPerPadding(&body) = padding
		*s55.BridgeUplinkS1cdma2000tunnellingFieldReceived(&body) = true
		raw.RetainContents(s55.BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(&body))
		*s55.BridgeUplinkS1cdma2000tunnellingFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUplinkS1cdma2000tunnelling = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s58.UEContextModificationRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s58.BridgeUEContextModificationRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextModificationRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s58.BridgeUEContextModificationRequestFieldPerPadding(&body) = padding
		*s58.BridgeUEContextModificationRequestFieldReceived(&body) = true
		raw.RetainContents(s58.BridgeUEContextModificationRequestFieldReceivedBytes(&body))
		*s58.BridgeUEContextModificationRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(22):
		var body s45.UECapabilityInfoIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeUECapabilityInfoIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UECapabilityInfoIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UECapabilityInfoIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s45.BridgeUECapabilityInfoIndicationFieldPerPadding(&body) = padding
		*s45.BridgeUECapabilityInfoIndicationFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeUECapabilityInfoIndicationFieldReceivedBytes(&body))
		*s45.BridgeUECapabilityInfoIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUECapabilityInfoIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(23):
		var body s47.UEContextReleaseCommand
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgeUEContextReleaseCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextReleaseCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextReleaseCommand")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s47.BridgeUEContextReleaseCommandFieldPerPadding(&body) = padding
		*s47.BridgeUEContextReleaseCommandFieldReceived(&body) = true
		raw.RetainContents(s47.BridgeUEContextReleaseCommandFieldReceivedBytes(&body))
		*s47.BridgeUEContextReleaseCommandFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextReleaseCommand = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(24):
		var body s28.ENBStatusTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s28.BridgeENBStatusTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBStatusTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBStatusTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s28.BridgeENBStatusTransferFieldPerPadding(&body) = padding
		*s28.BridgeENBStatusTransferFieldReceived(&body) = true
		raw.RetainContents(s28.BridgeENBStatusTransferFieldReceivedBytes(&body))
		*s28.BridgeENBStatusTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBStatusTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(25):
		var body s30.MMEStatusTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeMMEStatusTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMEStatusTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEStatusTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s30.BridgeMMEStatusTransferFieldPerPadding(&body) = padding
		*s30.BridgeMMEStatusTransferFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeMMEStatusTransferFieldReceivedBytes(&body))
		*s30.BridgeMMEStatusTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEStatusTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(26):
		var body s18.DeactivateTrace
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s18.BridgeDeactivateTraceMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.DeactivateTrace:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DeactivateTrace")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s18.BridgeDeactivateTraceFieldPerPadding(&body) = padding
		*s18.BridgeDeactivateTraceFieldReceived(&body) = true
		raw.RetainContents(s18.BridgeDeactivateTraceFieldReceivedBytes(&body))
		*s18.BridgeDeactivateTraceFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyDeactivateTrace = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(27):
		var body s61.TraceStart
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s61.BridgeTraceStartMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.TraceStart:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TraceStart")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s61.BridgeTraceStartFieldPerPadding(&body) = padding
		*s61.BridgeTraceStartFieldReceived(&body) = true
		raw.RetainContents(s61.BridgeTraceStartFieldReceivedBytes(&body))
		*s61.BridgeTraceStartFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyTraceStart = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(28):
		var body s44.TraceFailureIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s44.BridgeTraceFailureIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.TraceFailureIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TraceFailureIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s44.BridgeTraceFailureIndicationFieldPerPadding(&body) = padding
		*s44.BridgeTraceFailureIndicationFieldReceived(&body) = true
		raw.RetainContents(s44.BridgeTraceFailureIndicationFieldReceivedBytes(&body))
		*s44.BridgeTraceFailureIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyTraceFailureIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body s54.ENBConfigurationUpdate
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s54.BridgeENBConfigurationUpdateMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBConfigurationUpdate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdate")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s54.BridgeENBConfigurationUpdateFieldPerPadding(&body) = padding
		*s54.BridgeENBConfigurationUpdateFieldReceived(&body) = true
		raw.RetainContents(s54.BridgeENBConfigurationUpdateFieldReceivedBytes(&body))
		*s54.BridgeENBConfigurationUpdateFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBConfigurationUpdate = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body s54.MMEConfigurationUpdate
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s54.BridgeMMEConfigurationUpdateMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMEConfigurationUpdate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdate")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s54.BridgeMMEConfigurationUpdateFieldPerPadding(&body) = padding
		*s54.BridgeMMEConfigurationUpdateFieldReceived(&body) = true
		raw.RetainContents(s54.BridgeMMEConfigurationUpdateFieldReceivedBytes(&body))
		*s54.BridgeMMEConfigurationUpdateFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEConfigurationUpdate = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(31):
		var body s31.LocationReportingControl
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeLocationReportingControlMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.LocationReportingControl:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LocationReportingControl")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s31.BridgeLocationReportingControlFieldPerPadding(&body) = padding
		*s31.BridgeLocationReportingControlFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeLocationReportingControlFieldReceivedBytes(&body))
		*s31.BridgeLocationReportingControlFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyLocationReportingControl = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(32):
		var body s30.LocationReportingFailureIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeLocationReportingFailureIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.LocationReportingFailureIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LocationReportingFailureIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s30.BridgeLocationReportingFailureIndicationFieldPerPadding(&body) = padding
		*s30.BridgeLocationReportingFailureIndicationFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeLocationReportingFailureIndicationFieldReceivedBytes(&body))
		*s30.BridgeLocationReportingFailureIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyLocationReportingFailureIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(33):
		var body s42.LocationReport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s42.BridgeLocationReportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.LocationReport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LocationReport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s42.BridgeLocationReportFieldPerPadding(&body) = padding
		*s42.BridgeLocationReportFieldReceived(&body) = true
		raw.RetainContents(s42.BridgeLocationReportFieldReceivedBytes(&body))
		*s42.BridgeLocationReportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyLocationReport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(34):
		var body s52.OverloadStart
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s52.BridgeOverloadStartMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.OverloadStart:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OverloadStart")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s52.BridgeOverloadStartFieldPerPadding(&body) = padding
		*s52.BridgeOverloadStartFieldReceived(&body) = true
		raw.RetainContents(s52.BridgeOverloadStartFieldReceivedBytes(&body))
		*s52.BridgeOverloadStartFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyOverloadStart = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(35):
		var body s52.OverloadStop
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s52.BridgeOverloadStopMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.OverloadStop:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OverloadStop")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s52.BridgeOverloadStopFieldPerPadding(&body) = padding
		*s52.BridgeOverloadStopFieldReceived(&body) = true
		raw.RetainContents(s52.BridgeOverloadStopFieldReceivedBytes(&body))
		*s52.BridgeOverloadStopFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyOverloadStop = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(36):
		var body s64.WriteReplaceWarningRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s64.BridgeWriteReplaceWarningRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.WriteReplaceWarningRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WriteReplaceWarningRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s64.BridgeWriteReplaceWarningRequestFieldPerPadding(&body) = padding
		*s64.BridgeWriteReplaceWarningRequestFieldReceived(&body) = true
		raw.RetainContents(s64.BridgeWriteReplaceWarningRequestFieldReceivedBytes(&body))
		*s64.BridgeWriteReplaceWarningRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyWriteReplaceWarningRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(37):
		var body s43.ENBDirectInformationTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s43.BridgeENBDirectInformationTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBDirectInformationTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBDirectInformationTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s43.BridgeENBDirectInformationTransferFieldPerPadding(&body) = padding
		*s43.BridgeENBDirectInformationTransferFieldReceived(&body) = true
		raw.RetainContents(s43.BridgeENBDirectInformationTransferFieldReceivedBytes(&body))
		*s43.BridgeENBDirectInformationTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBDirectInformationTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(38):
		var body s43.MMEDirectInformationTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s43.BridgeMMEDirectInformationTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMEDirectInformationTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEDirectInformationTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s43.BridgeMMEDirectInformationTransferFieldPerPadding(&body) = padding
		*s43.BridgeMMEDirectInformationTransferFieldReceived(&body) = true
		raw.RetainContents(s43.BridgeMMEDirectInformationTransferFieldReceivedBytes(&body))
		*s43.BridgeMMEDirectInformationTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEDirectInformationTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(39):
		var body s30.PrivateMessage
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgePrivateMessageMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.PrivateMessage:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PrivateMessage")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s30.BridgePrivateMessageFieldPerPadding(&body) = padding
		*s30.BridgePrivateMessageFieldReceived(&body) = true
		raw.RetainContents(s30.BridgePrivateMessageFieldReceivedBytes(&body))
		*s30.BridgePrivateMessageFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPrivateMessage = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(40):
		var body ENBConfigurationTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBConfigurationTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.ContentLocation()
		v.bodyENBConfigurationTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(41):
		var body MMEConfigurationTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMEConfigurationTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.ContentLocation()
		v.bodyMMEConfigurationTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(42):
		var body s25.CellTrafficTrace
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeCellTrafficTraceMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.CellTrafficTrace:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CellTrafficTrace")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s25.BridgeCellTrafficTraceFieldPerPadding(&body) = padding
		*s25.BridgeCellTrafficTraceFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeCellTrafficTraceFieldReceivedBytes(&body))
		*s25.BridgeCellTrafficTraceFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyCellTrafficTrace = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(43):
		var body s42.KillRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s42.BridgeKillRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.KillRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "KillRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s42.BridgeKillRequestFieldPerPadding(&body) = padding
		*s42.BridgeKillRequestFieldReceived(&body) = true
		raw.RetainContents(s42.BridgeKillRequestFieldReceivedBytes(&body))
		*s42.BridgeKillRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyKillRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(44):
		var body s18.DownlinkUEAssociatedLPPaTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s18.BridgeDownlinkUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.DownlinkUEAssociatedLPPaTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DownlinkUEAssociatedLPPaTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldPerPadding(&body) = padding
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceived(&body) = true
		raw.RetainContents(s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedBytes(&body))
		*s18.BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyDownlinkUEAssociatedLPPaTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(45):
		var body s55.UplinkUEAssociatedLPPaTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UplinkUEAssociatedLPPaTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UplinkUEAssociatedLPPaTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldPerPadding(&body) = padding
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceived(&body) = true
		raw.RetainContents(s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(&body))
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUplinkUEAssociatedLPPaTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(46):
		var body s18.DownlinkNonUEAssociatedLPPaTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.DownlinkNonUEAssociatedLPPaTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DownlinkNonUEAssociatedLPPaTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldPerPadding(&body) = padding
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceived(&body) = true
		raw.RetainContents(s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&body))
		*s18.BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyDownlinkNonUEAssociatedLPPaTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(47):
		var body s55.UplinkNonUEAssociatedLPPaTransport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UplinkNonUEAssociatedLPPaTransport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UplinkNonUEAssociatedLPPaTransport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldPerPadding(&body) = padding
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(&body) = true
		raw.RetainContents(s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&body))
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUplinkNonUEAssociatedLPPaTransport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(48):
		var body s46.UERadioCapabilityMatchRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UERadioCapabilityMatchRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityMatchRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s46.BridgeUERadioCapabilityMatchRequestFieldPerPadding(&body) = padding
		*s46.BridgeUERadioCapabilityMatchRequestFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUERadioCapabilityMatchRequestFieldReceivedBytes(&body))
		*s46.BridgeUERadioCapabilityMatchRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityMatchRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(49):
		var body s55.PWSRestartIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgePWSRestartIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.PWSRestartIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PWSRestartIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s55.BridgePWSRestartIndicationFieldPerPadding(&body) = padding
		*s55.BridgePWSRestartIndicationFieldReceived(&body) = true
		raw.RetainContents(s55.BridgePWSRestartIndicationFieldReceivedBytes(&body))
		*s55.BridgePWSRestartIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPWSRestartIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(50):
		var body s57.ERABModificationIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeERABModificationIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ERABModificationIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModificationIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s57.BridgeERABModificationIndicationFieldPerPadding(&body) = padding
		*s57.BridgeERABModificationIndicationFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeERABModificationIndicationFieldReceivedBytes(&body))
		*s57.BridgeERABModificationIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModificationIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(51):
		var body s52.PWSFailureIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s52.BridgePWSFailureIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.PWSFailureIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PWSFailureIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s52.BridgePWSFailureIndicationFieldPerPadding(&body) = padding
		*s52.BridgePWSFailureIndicationFieldReceived(&body) = true
		raw.RetainContents(s52.BridgePWSFailureIndicationFieldReceivedBytes(&body))
		*s52.BridgePWSFailureIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPWSFailureIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(52):
		var body s31.RerouteNASRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeRerouteNASRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.RerouteNASRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RerouteNASRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s31.BridgeRerouteNASRequestFieldPerPadding(&body) = padding
		*s31.BridgeRerouteNASRequestFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeRerouteNASRequestFieldReceivedBytes(&body))
		*s31.BridgeRerouteNASRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyRerouteNASRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(53):
		var body s46.UEContextModificationIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUEContextModificationIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextModificationIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s46.BridgeUEContextModificationIndicationFieldPerPadding(&body) = padding
		*s46.BridgeUEContextModificationIndicationFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUEContextModificationIndicationFieldReceivedBytes(&body))
		*s46.BridgeUEContextModificationIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(54):
		var body s40.ConnectionEstablishmentIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s40.BridgeConnectionEstablishmentIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ConnectionEstablishmentIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ConnectionEstablishmentIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s40.BridgeConnectionEstablishmentIndicationFieldPerPadding(&body) = padding
		*s40.BridgeConnectionEstablishmentIndicationFieldReceived(&body) = true
		raw.RetainContents(s40.BridgeConnectionEstablishmentIndicationFieldReceivedBytes(&body))
		*s40.BridgeConnectionEstablishmentIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyConnectionEstablishmentIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(55):
		var body s57.UEContextSuspendRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeUEContextSuspendRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextSuspendRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextSuspendRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s57.BridgeUEContextSuspendRequestFieldPerPadding(&body) = padding
		*s57.BridgeUEContextSuspendRequestFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeUEContextSuspendRequestFieldReceivedBytes(&body))
		*s57.BridgeUEContextSuspendRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextSuspendRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body s48.UEContextResumeRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s48.BridgeUEContextResumeRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEContextResumeRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextResumeRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s48.BridgeUEContextResumeRequestFieldPerPadding(&body) = padding
		*s48.BridgeUEContextResumeRequestFieldReceived(&body) = true
		raw.RetainContents(s48.BridgeUEContextResumeRequestFieldReceivedBytes(&body))
		*s48.BridgeUEContextResumeRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextResumeRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(57):
		var body s22.NASDeliveryIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s22.BridgeNASDeliveryIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.NASDeliveryIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NASDeliveryIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s22.BridgeNASDeliveryIndicationFieldPerPadding(&body) = padding
		*s22.BridgeNASDeliveryIndicationFieldReceived(&body) = true
		raw.RetainContents(s22.BridgeNASDeliveryIndicationFieldReceivedBytes(&body))
		*s22.BridgeNASDeliveryIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyNASDeliveryIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(58):
		var body s36.RetrieveUEInformation
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeRetrieveUEInformationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.RetrieveUEInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RetrieveUEInformation")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s36.BridgeRetrieveUEInformationFieldPerPadding(&body) = padding
		*s36.BridgeRetrieveUEInformationFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeRetrieveUEInformationFieldReceivedBytes(&body))
		*s36.BridgeRetrieveUEInformationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyRetrieveUEInformation = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(59):
		var body s46.UEInformationTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUEInformationTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UEInformationTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEInformationTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s46.BridgeUEInformationTransferFieldPerPadding(&body) = padding
		*s46.BridgeUEInformationTransferFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUEInformationTransferFieldReceivedBytes(&body))
		*s46.BridgeUEInformationTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEInformationTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(60):
		var body s47.ENBCPRelocationIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgeENBCPRelocationIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBCPRelocationIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBCPRelocationIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s47.BridgeENBCPRelocationIndicationFieldPerPadding(&body) = padding
		*s47.BridgeENBCPRelocationIndicationFieldReceived(&body) = true
		raw.RetainContents(s47.BridgeENBCPRelocationIndicationFieldReceivedBytes(&body))
		*s47.BridgeENBCPRelocationIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBCPRelocationIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(61):
		var body s22.MMECPRelocationIndication
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s22.BridgeMMECPRelocationIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMECPRelocationIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMECPRelocationIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s22.BridgeMMECPRelocationIndicationFieldPerPadding(&body) = padding
		*s22.BridgeMMECPRelocationIndicationFieldReceived(&body) = true
		raw.RetainContents(s22.BridgeMMECPRelocationIndicationFieldReceivedBytes(&body))
		*s22.BridgeMMECPRelocationIndicationFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMECPRelocationIndication = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(62):
		var body s57.SecondaryRATDataUsageReport
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.SecondaryRATDataUsageReport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecondaryRATDataUsageReport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s57.BridgeSecondaryRATDataUsageReportFieldPerPadding(&body) = padding
		*s57.BridgeSecondaryRATDataUsageReportFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeSecondaryRATDataUsageReportFieldReceivedBytes(&body))
		*s57.BridgeSecondaryRATDataUsageReportFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodySecondaryRATDataUsageReport = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(63):
		var body s46.UERadioCapabilityIDMappingRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UERadioCapabilityIDMappingRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityIDMappingRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldPerPadding(&body) = padding
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUERadioCapabilityIDMappingRequestFieldReceivedBytes(&body))
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityIDMappingRequest = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(64):
		var body s21.HandoverSuccess
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s21.BridgeHandoverSuccessMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.HandoverSuccess:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverSuccess")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s21.BridgeHandoverSuccessFieldPerPadding(&body) = padding
		*s21.BridgeHandoverSuccessFieldReceived(&body) = true
		raw.RetainContents(s21.BridgeHandoverSuccessFieldReceivedBytes(&body))
		*s21.BridgeHandoverSuccessFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverSuccess = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(65):
		var body s47.ENBEarlyStatusTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgeENBEarlyStatusTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ENBEarlyStatusTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBEarlyStatusTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s47.BridgeENBEarlyStatusTransferFieldPerPadding(&body) = padding
		*s47.BridgeENBEarlyStatusTransferFieldReceived(&body) = true
		raw.RetainContents(s47.BridgeENBEarlyStatusTransferFieldReceivedBytes(&body))
		*s47.BridgeENBEarlyStatusTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBEarlyStatusTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(66):
		var body s48.MMEEarlyStatusTransfer
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s48.BridgeMMEEarlyStatusTransferMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.MMEEarlyStatusTransfer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEEarlyStatusTransfer")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s48.BridgeMMEEarlyStatusTransferFieldPerPadding(&body) = padding
		*s48.BridgeMMEEarlyStatusTransferFieldReceived(&body) = true
		raw.RetainContents(s48.BridgeMMEEarlyStatusTransferFieldReceivedBytes(&body))
		*s48.BridgeMMEEarlyStatusTransferFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEEarlyStatusTransfer = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(67):
		var body s31.S1RemovalRequest
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return InitiatingValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeS1RemovalRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.S1RemovalRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s31.BridgeS1RemovalRequestFieldPerPadding(&body) = padding
		*s31.BridgeS1RemovalRequestFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeS1RemovalRequestFieldReceivedBytes(&body))
		*s31.BridgeS1RemovalRequestFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1RemovalRequest = &body
		raw.RetainContents(&v.received)
	default:
		if err := raw.Observe(aper.UnknownProcedure); err != nil {
			return v, err
		}
		v.opaque = raw.Detached()
		v.isOpaque = true
	}
	return v, nil
}
func (v InitiatingValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v InitiatingValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.code {
	case s00.ProcedureCode(0):
		if v.bodyHandoverRequired == nil {
			return nil, fmt.Errorf("%s value: missing HandoverRequired", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s43.BridgeHandoverRequiredMethodMarshalAPERBudget(v.bodyHandoverRequired, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyHandoverRequest == nil {
			return nil, fmt.Errorf("%s value: missing HandoverRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s60.BridgeHandoverRequestMethodMarshalAPERBudget(v.bodyHandoverRequest, budget, fresh)
	case s00.ProcedureCode(2):
		if v.bodyHandoverNotify == nil {
			return nil, fmt.Errorf("%s value: missing HandoverNotify", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s44.BridgeHandoverNotifyMethodMarshalAPERBudget(v.bodyHandoverNotify, budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyPathSwitchRequest == nil {
			return nil, fmt.Errorf("%s value: missing PathSwitchRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s51.BridgePathSwitchRequestMethodMarshalAPERBudget(v.bodyPathSwitchRequest, budget, fresh)
	case s00.ProcedureCode(4):
		if v.bodyHandoverCancel == nil {
			return nil, fmt.Errorf("%s value: missing HandoverCancel", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s29.BridgeHandoverCancelMethodMarshalAPERBudget(v.bodyHandoverCancel, budget, fresh)
	case s00.ProcedureCode(5):
		if v.bodyERABSetupRequest == nil {
			return nil, fmt.Errorf("%s value: missing ERABSetupRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s51.BridgeERABSetupRequestMethodMarshalAPERBudget(v.bodyERABSetupRequest, budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyERABModifyRequest == nil {
			return nil, fmt.Errorf("%s value: missing ERABModifyRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s51.BridgeERABModifyRequestMethodMarshalAPERBudget(v.bodyERABModifyRequest, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyERABReleaseCommand == nil {
			return nil, fmt.Errorf("%s value: missing ERABReleaseCommand", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s49.BridgeERABReleaseCommandMethodMarshalAPERBudget(v.bodyERABReleaseCommand, budget, fresh)
	case s00.ProcedureCode(8):
		if v.bodyERABReleaseIndication == nil {
			return nil, fmt.Errorf("%s value: missing ERABReleaseIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeERABReleaseIndicationMethodMarshalAPERBudget(v.bodyERABReleaseIndication, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyInitialContextSetupRequest == nil {
			return nil, fmt.Errorf("%s value: missing InitialContextSetupRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s60.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v.bodyInitialContextSetupRequest, budget, fresh)
	case s00.ProcedureCode(10):
		if v.bodyPaging == nil {
			return nil, fmt.Errorf("%s value: missing Paging", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s61.BridgePagingMethodMarshalAPERBudget(v.bodyPaging, budget, fresh)
	case s00.ProcedureCode(11):
		if v.bodyDownlinkNASTransport == nil {
			return nil, fmt.Errorf("%s value: missing DownlinkNASTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s53.BridgeDownlinkNASTransportMethodMarshalAPERBudget(v.bodyDownlinkNASTransport, budget, fresh)
	case s00.ProcedureCode(12):
		if v.bodyInitialUEMessage == nil {
			return nil, fmt.Errorf("%s value: missing InitialUEMessage", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s45.BridgeInitialUEMessageMethodMarshalAPERBudget(v.bodyInitialUEMessage, budget, fresh)
	case s00.ProcedureCode(13):
		if v.bodyUplinkNASTransport == nil {
			return nil, fmt.Errorf("%s value: missing UplinkNASTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgeUplinkNASTransportMethodMarshalAPERBudget(v.bodyUplinkNASTransport, budget, fresh)
	case s00.ProcedureCode(14):
		if v.bodyReset == nil {
			return nil, fmt.Errorf("%s value: missing Reset", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s45.BridgeResetMethodMarshalAPERBudget(v.bodyReset, budget, fresh)
	case s00.ProcedureCode(15):
		if v.bodyErrorIndication == nil {
			return nil, fmt.Errorf("%s value: missing ErrorIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeErrorIndicationMethodMarshalAPERBudget(v.bodyErrorIndication, budget, fresh)
	case s00.ProcedureCode(16):
		if v.bodyNASNonDeliveryIndication == nil {
			return nil, fmt.Errorf("%s value: missing NASNonDeliveryIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v.bodyNASNonDeliveryIndication, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupRequest == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s54.BridgeS1SetupRequestMethodMarshalAPERBudget(v.bodyS1SetupRequest, budget, fresh)
	case s00.ProcedureCode(18):
		if v.bodyUEContextReleaseRequest == nil {
			return nil, fmt.Errorf("%s value: missing UEContextReleaseRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s53.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v.bodyUEContextReleaseRequest, budget, fresh)
	case s00.ProcedureCode(19):
		if v.bodyDownlinkS1cdma2000tunnelling == nil {
			return nil, fmt.Errorf("%s value: missing DownlinkS1cdma2000tunnelling", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s50.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(v.bodyDownlinkS1cdma2000tunnelling, budget, fresh)
	case s00.ProcedureCode(20):
		if v.bodyUplinkS1cdma2000tunnelling == nil {
			return nil, fmt.Errorf("%s value: missing UplinkS1cdma2000tunnelling", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v.bodyUplinkS1cdma2000tunnelling, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationRequest == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s58.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v.bodyUEContextModificationRequest, budget, fresh)
	case s00.ProcedureCode(22):
		if v.bodyUECapabilityInfoIndication == nil {
			return nil, fmt.Errorf("%s value: missing UECapabilityInfoIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s45.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v.bodyUECapabilityInfoIndication, budget, fresh)
	case s00.ProcedureCode(23):
		if v.bodyUEContextReleaseCommand == nil {
			return nil, fmt.Errorf("%s value: missing UEContextReleaseCommand", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s47.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v.bodyUEContextReleaseCommand, budget, fresh)
	case s00.ProcedureCode(24):
		if v.bodyENBStatusTransfer == nil {
			return nil, fmt.Errorf("%s value: missing ENBStatusTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s28.BridgeENBStatusTransferMethodMarshalAPERBudget(v.bodyENBStatusTransfer, budget, fresh)
	case s00.ProcedureCode(25):
		if v.bodyMMEStatusTransfer == nil {
			return nil, fmt.Errorf("%s value: missing MMEStatusTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeMMEStatusTransferMethodMarshalAPERBudget(v.bodyMMEStatusTransfer, budget, fresh)
	case s00.ProcedureCode(26):
		if v.bodyDeactivateTrace == nil {
			return nil, fmt.Errorf("%s value: missing DeactivateTrace", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s18.BridgeDeactivateTraceMethodMarshalAPERBudget(v.bodyDeactivateTrace, budget, fresh)
	case s00.ProcedureCode(27):
		if v.bodyTraceStart == nil {
			return nil, fmt.Errorf("%s value: missing TraceStart", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s61.BridgeTraceStartMethodMarshalAPERBudget(v.bodyTraceStart, budget, fresh)
	case s00.ProcedureCode(28):
		if v.bodyTraceFailureIndication == nil {
			return nil, fmt.Errorf("%s value: missing TraceFailureIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s44.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v.bodyTraceFailureIndication, budget, fresh)
	case s00.ProcedureCode(29):
		if v.bodyENBConfigurationUpdate == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationUpdate", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s54.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v.bodyENBConfigurationUpdate, budget, fresh)
	case s00.ProcedureCode(30):
		if v.bodyMMEConfigurationUpdate == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationUpdate", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s54.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdate, budget, fresh)
	case s00.ProcedureCode(31):
		if v.bodyLocationReportingControl == nil {
			return nil, fmt.Errorf("%s value: missing LocationReportingControl", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s31.BridgeLocationReportingControlMethodMarshalAPERBudget(v.bodyLocationReportingControl, budget, fresh)
	case s00.ProcedureCode(32):
		if v.bodyLocationReportingFailureIndication == nil {
			return nil, fmt.Errorf("%s value: missing LocationReportingFailureIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v.bodyLocationReportingFailureIndication, budget, fresh)
	case s00.ProcedureCode(33):
		if v.bodyLocationReport == nil {
			return nil, fmt.Errorf("%s value: missing LocationReport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s42.BridgeLocationReportMethodMarshalAPERBudget(v.bodyLocationReport, budget, fresh)
	case s00.ProcedureCode(34):
		if v.bodyOverloadStart == nil {
			return nil, fmt.Errorf("%s value: missing OverloadStart", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s52.BridgeOverloadStartMethodMarshalAPERBudget(v.bodyOverloadStart, budget, fresh)
	case s00.ProcedureCode(35):
		if v.bodyOverloadStop == nil {
			return nil, fmt.Errorf("%s value: missing OverloadStop", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s52.BridgeOverloadStopMethodMarshalAPERBudget(v.bodyOverloadStop, budget, fresh)
	case s00.ProcedureCode(36):
		if v.bodyWriteReplaceWarningRequest == nil {
			return nil, fmt.Errorf("%s value: missing WriteReplaceWarningRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s64.BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v.bodyWriteReplaceWarningRequest, budget, fresh)
	case s00.ProcedureCode(37):
		if v.bodyENBDirectInformationTransfer == nil {
			return nil, fmt.Errorf("%s value: missing ENBDirectInformationTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s43.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v.bodyENBDirectInformationTransfer, budget, fresh)
	case s00.ProcedureCode(38):
		if v.bodyMMEDirectInformationTransfer == nil {
			return nil, fmt.Errorf("%s value: missing MMEDirectInformationTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s43.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v.bodyMMEDirectInformationTransfer, budget, fresh)
	case s00.ProcedureCode(39):
		if v.bodyPrivateMessage == nil {
			return nil, fmt.Errorf("%s value: missing PrivateMessage", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgePrivateMessageMethodMarshalAPERBudget(v.bodyPrivateMessage, budget, fresh)
	case s00.ProcedureCode(40):
		if v.bodyENBConfigurationTransfer == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return v.bodyENBConfigurationTransfer.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(41):
		if v.bodyMMEConfigurationTransfer == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return v.bodyMMEConfigurationTransfer.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(42):
		if v.bodyCellTrafficTrace == nil {
			return nil, fmt.Errorf("%s value: missing CellTrafficTrace", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeCellTrafficTraceMethodMarshalAPERBudget(v.bodyCellTrafficTrace, budget, fresh)
	case s00.ProcedureCode(43):
		if v.bodyKillRequest == nil {
			return nil, fmt.Errorf("%s value: missing KillRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s42.BridgeKillRequestMethodMarshalAPERBudget(v.bodyKillRequest, budget, fresh)
	case s00.ProcedureCode(44):
		if v.bodyDownlinkUEAssociatedLPPaTransport == nil {
			return nil, fmt.Errorf("%s value: missing DownlinkUEAssociatedLPPaTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s18.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v.bodyDownlinkUEAssociatedLPPaTransport, budget, fresh)
	case s00.ProcedureCode(45):
		if v.bodyUplinkUEAssociatedLPPaTransport == nil {
			return nil, fmt.Errorf("%s value: missing UplinkUEAssociatedLPPaTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v.bodyUplinkUEAssociatedLPPaTransport, budget, fresh)
	case s00.ProcedureCode(46):
		if v.bodyDownlinkNonUEAssociatedLPPaTransport == nil {
			return nil, fmt.Errorf("%s value: missing DownlinkNonUEAssociatedLPPaTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v.bodyDownlinkNonUEAssociatedLPPaTransport, budget, fresh)
	case s00.ProcedureCode(47):
		if v.bodyUplinkNonUEAssociatedLPPaTransport == nil {
			return nil, fmt.Errorf("%s value: missing UplinkNonUEAssociatedLPPaTransport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v.bodyUplinkNonUEAssociatedLPPaTransport, budget, fresh)
	case s00.ProcedureCode(48):
		if v.bodyUERadioCapabilityMatchRequest == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityMatchRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v.bodyUERadioCapabilityMatchRequest, budget, fresh)
	case s00.ProcedureCode(49):
		if v.bodyPWSRestartIndication == nil {
			return nil, fmt.Errorf("%s value: missing PWSRestartIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgePWSRestartIndicationMethodMarshalAPERBudget(v.bodyPWSRestartIndication, budget, fresh)
	case s00.ProcedureCode(50):
		if v.bodyERABModificationIndication == nil {
			return nil, fmt.Errorf("%s value: missing ERABModificationIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeERABModificationIndicationMethodMarshalAPERBudget(v.bodyERABModificationIndication, budget, fresh)
	case s00.ProcedureCode(51):
		if v.bodyPWSFailureIndication == nil {
			return nil, fmt.Errorf("%s value: missing PWSFailureIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s52.BridgePWSFailureIndicationMethodMarshalAPERBudget(v.bodyPWSFailureIndication, budget, fresh)
	case s00.ProcedureCode(52):
		if v.bodyRerouteNASRequest == nil {
			return nil, fmt.Errorf("%s value: missing RerouteNASRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s31.BridgeRerouteNASRequestMethodMarshalAPERBudget(v.bodyRerouteNASRequest, budget, fresh)
	case s00.ProcedureCode(53):
		if v.bodyUEContextModificationIndication == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v.bodyUEContextModificationIndication, budget, fresh)
	case s00.ProcedureCode(54):
		if v.bodyConnectionEstablishmentIndication == nil {
			return nil, fmt.Errorf("%s value: missing ConnectionEstablishmentIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s40.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v.bodyConnectionEstablishmentIndication, budget, fresh)
	case s00.ProcedureCode(55):
		if v.bodyUEContextSuspendRequest == nil {
			return nil, fmt.Errorf("%s value: missing UEContextSuspendRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v.bodyUEContextSuspendRequest, budget, fresh)
	case s00.ProcedureCode(56):
		if v.bodyUEContextResumeRequest == nil {
			return nil, fmt.Errorf("%s value: missing UEContextResumeRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s48.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v.bodyUEContextResumeRequest, budget, fresh)
	case s00.ProcedureCode(57):
		if v.bodyNASDeliveryIndication == nil {
			return nil, fmt.Errorf("%s value: missing NASDeliveryIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s22.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v.bodyNASDeliveryIndication, budget, fresh)
	case s00.ProcedureCode(58):
		if v.bodyRetrieveUEInformation == nil {
			return nil, fmt.Errorf("%s value: missing RetrieveUEInformation", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeRetrieveUEInformationMethodMarshalAPERBudget(v.bodyRetrieveUEInformation, budget, fresh)
	case s00.ProcedureCode(59):
		if v.bodyUEInformationTransfer == nil {
			return nil, fmt.Errorf("%s value: missing UEInformationTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUEInformationTransferMethodMarshalAPERBudget(v.bodyUEInformationTransfer, budget, fresh)
	case s00.ProcedureCode(60):
		if v.bodyENBCPRelocationIndication == nil {
			return nil, fmt.Errorf("%s value: missing ENBCPRelocationIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s47.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v.bodyENBCPRelocationIndication, budget, fresh)
	case s00.ProcedureCode(61):
		if v.bodyMMECPRelocationIndication == nil {
			return nil, fmt.Errorf("%s value: missing MMECPRelocationIndication", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s22.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v.bodyMMECPRelocationIndication, budget, fresh)
	case s00.ProcedureCode(62):
		if v.bodySecondaryRATDataUsageReport == nil {
			return nil, fmt.Errorf("%s value: missing SecondaryRATDataUsageReport", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v.bodySecondaryRATDataUsageReport, budget, fresh)
	case s00.ProcedureCode(63):
		if v.bodyUERadioCapabilityIDMappingRequest == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityIDMappingRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v.bodyUERadioCapabilityIDMappingRequest, budget, fresh)
	case s00.ProcedureCode(64):
		if v.bodyHandoverSuccess == nil {
			return nil, fmt.Errorf("%s value: missing HandoverSuccess", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s21.BridgeHandoverSuccessMethodMarshalAPERBudget(v.bodyHandoverSuccess, budget, fresh)
	case s00.ProcedureCode(65):
		if v.bodyENBEarlyStatusTransfer == nil {
			return nil, fmt.Errorf("%s value: missing ENBEarlyStatusTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s47.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v.bodyENBEarlyStatusTransfer, budget, fresh)
	case s00.ProcedureCode(66):
		if v.bodyMMEEarlyStatusTransfer == nil {
			return nil, fmt.Errorf("%s value: missing MMEEarlyStatusTransfer", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s48.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v.bodyMMEEarlyStatusTransfer, budget, fresh)
	case s00.ProcedureCode(67):
		if v.bodyS1RemovalRequest == nil {
			return nil, fmt.Errorf("%s value: missing S1RemovalRequest", "Initiating")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s31.BridgeS1RemovalRequestMethodMarshalAPERBudget(v.bodyS1RemovalRequest, budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Initiating", v.code)
	}
}
func BridgeCaptureS1APENBConfigurationTransfer(v *ENBConfigurationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationTransfer(v *ENBConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABIEContainerList[V ProtocolOpenValueConstraint[V]](v *ERABIEContainerList[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABIEContainerList[V ProtocolOpenValueConstraint[V]](v *ERABIEContainerList[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APInitiatingMessage(v *InitiatingMessage, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	BridgeCaptureS1APInitiatingValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInitiatingMessage(v *InitiatingMessage, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	BridgeCompareS1APInitiatingValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInitiatingValue(v *InitiatingValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequired == nil)
				if v.bodyHandoverRequired != nil {
					s43.BridgeCaptureS1APHandoverRequired(v.bodyHandoverRequired, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequest == nil)
				if v.bodyHandoverRequest != nil {
					s60.BridgeCaptureS1APHandoverRequest(v.bodyHandoverRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverNotify == nil)
				if v.bodyHandoverNotify != nil {
					s44.BridgeCaptureS1APHandoverNotify(v.bodyHandoverNotify, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequest == nil)
				if v.bodyPathSwitchRequest != nil {
					s51.BridgeCaptureS1APPathSwitchRequest(v.bodyPathSwitchRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancel == nil)
				if v.bodyHandoverCancel != nil {
					s29.BridgeCaptureS1APHandoverCancel(v.bodyHandoverCancel, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupRequest == nil)
				if v.bodyERABSetupRequest != nil {
					s51.BridgeCaptureS1APERABSetupRequest(v.bodyERABSetupRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyRequest == nil)
				if v.bodyERABModifyRequest != nil {
					s51.BridgeCaptureS1APERABModifyRequest(v.bodyERABModifyRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseCommand == nil)
				if v.bodyERABReleaseCommand != nil {
					s49.BridgeCaptureS1APERABReleaseCommand(v.bodyERABReleaseCommand, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseIndication == nil)
				if v.bodyERABReleaseIndication != nil {
					s57.BridgeCaptureS1APERABReleaseIndication(v.bodyERABReleaseIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupRequest == nil)
				if v.bodyInitialContextSetupRequest != nil {
					s60.BridgeCaptureS1APInitialContextSetupRequest(v.bodyInitialContextSetupRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyPaging == nil)
				if v.bodyPaging != nil {
					s61.BridgeCaptureS1APPaging(v.bodyPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(11):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkNASTransport == nil)
				if v.bodyDownlinkNASTransport != nil {
					s53.BridgeCaptureS1APDownlinkNASTransport(v.bodyDownlinkNASTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(12):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialUEMessage == nil)
				if v.bodyInitialUEMessage != nil {
					s45.BridgeCaptureS1APInitialUEMessage(v.bodyInitialUEMessage, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(13):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkNASTransport == nil)
				if v.bodyUplinkNASTransport != nil {
					s55.BridgeCaptureS1APUplinkNASTransport(v.bodyUplinkNASTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyReset == nil)
				if v.bodyReset != nil {
					s45.BridgeCaptureS1APReset(v.bodyReset, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(15):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					s36.BridgeCaptureS1APErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(16):
			{
				f := s.Begin()
				s.Bool(v.bodyNASNonDeliveryIndication == nil)
				if v.bodyNASNonDeliveryIndication != nil {
					s30.BridgeCaptureS1APNASNonDeliveryIndication(v.bodyNASNonDeliveryIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupRequest == nil)
				if v.bodyS1SetupRequest != nil {
					s54.BridgeCaptureS1APS1SetupRequest(v.bodyS1SetupRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(18):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseRequest == nil)
				if v.bodyUEContextReleaseRequest != nil {
					s53.BridgeCaptureS1APUEContextReleaseRequest(v.bodyUEContextReleaseRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(19):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkS1cdma2000tunnelling == nil)
				if v.bodyDownlinkS1cdma2000tunnelling != nil {
					s50.BridgeCaptureS1APDownlinkS1cdma2000tunnelling(v.bodyDownlinkS1cdma2000tunnelling, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(20):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkS1cdma2000tunnelling == nil)
				if v.bodyUplinkS1cdma2000tunnelling != nil {
					s55.BridgeCaptureS1APUplinkS1cdma2000tunnelling(v.bodyUplinkS1cdma2000tunnelling, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationRequest == nil)
				if v.bodyUEContextModificationRequest != nil {
					s58.BridgeCaptureS1APUEContextModificationRequest(v.bodyUEContextModificationRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(22):
			{
				f := s.Begin()
				s.Bool(v.bodyUECapabilityInfoIndication == nil)
				if v.bodyUECapabilityInfoIndication != nil {
					s45.BridgeCaptureS1APUECapabilityInfoIndication(v.bodyUECapabilityInfoIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseCommand == nil)
				if v.bodyUEContextReleaseCommand != nil {
					s47.BridgeCaptureS1APUEContextReleaseCommand(v.bodyUEContextReleaseCommand, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(24):
			{
				f := s.Begin()
				s.Bool(v.bodyENBStatusTransfer == nil)
				if v.bodyENBStatusTransfer != nil {
					s28.BridgeCaptureS1APENBStatusTransfer(v.bodyENBStatusTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(25):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEStatusTransfer == nil)
				if v.bodyMMEStatusTransfer != nil {
					s30.BridgeCaptureS1APMMEStatusTransfer(v.bodyMMEStatusTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(26):
			{
				f := s.Begin()
				s.Bool(v.bodyDeactivateTrace == nil)
				if v.bodyDeactivateTrace != nil {
					s18.BridgeCaptureS1APDeactivateTrace(v.bodyDeactivateTrace, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(27):
			{
				f := s.Begin()
				s.Bool(v.bodyTraceStart == nil)
				if v.bodyTraceStart != nil {
					s61.BridgeCaptureS1APTraceStart(v.bodyTraceStart, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(28):
			{
				f := s.Begin()
				s.Bool(v.bodyTraceFailureIndication == nil)
				if v.bodyTraceFailureIndication != nil {
					s44.BridgeCaptureS1APTraceFailureIndication(v.bodyTraceFailureIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdate == nil)
				if v.bodyENBConfigurationUpdate != nil {
					s54.BridgeCaptureS1APENBConfigurationUpdate(v.bodyENBConfigurationUpdate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdate == nil)
				if v.bodyMMEConfigurationUpdate != nil {
					s54.BridgeCaptureS1APMMEConfigurationUpdate(v.bodyMMEConfigurationUpdate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(31):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReportingControl == nil)
				if v.bodyLocationReportingControl != nil {
					s31.BridgeCaptureS1APLocationReportingControl(v.bodyLocationReportingControl, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(32):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReportingFailureIndication == nil)
				if v.bodyLocationReportingFailureIndication != nil {
					s30.BridgeCaptureS1APLocationReportingFailureIndication(v.bodyLocationReportingFailureIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(33):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReport == nil)
				if v.bodyLocationReport != nil {
					s42.BridgeCaptureS1APLocationReport(v.bodyLocationReport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(34):
			{
				f := s.Begin()
				s.Bool(v.bodyOverloadStart == nil)
				if v.bodyOverloadStart != nil {
					s52.BridgeCaptureS1APOverloadStart(v.bodyOverloadStart, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(35):
			{
				f := s.Begin()
				s.Bool(v.bodyOverloadStop == nil)
				if v.bodyOverloadStop != nil {
					s52.BridgeCaptureS1APOverloadStop(v.bodyOverloadStop, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyWriteReplaceWarningRequest == nil)
				if v.bodyWriteReplaceWarningRequest != nil {
					s64.BridgeCaptureS1APWriteReplaceWarningRequest(v.bodyWriteReplaceWarningRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(37):
			{
				f := s.Begin()
				s.Bool(v.bodyENBDirectInformationTransfer == nil)
				if v.bodyENBDirectInformationTransfer != nil {
					s43.BridgeCaptureS1APENBDirectInformationTransfer(v.bodyENBDirectInformationTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(38):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEDirectInformationTransfer == nil)
				if v.bodyMMEDirectInformationTransfer != nil {
					s43.BridgeCaptureS1APMMEDirectInformationTransfer(v.bodyMMEDirectInformationTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(39):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					s30.BridgeCaptureS1APPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(40):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationTransfer == nil)
				if v.bodyENBConfigurationTransfer != nil {
					BridgeCaptureS1APENBConfigurationTransfer(v.bodyENBConfigurationTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(41):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationTransfer == nil)
				if v.bodyMMEConfigurationTransfer != nil {
					BridgeCaptureS1APMMEConfigurationTransfer(v.bodyMMEConfigurationTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(42):
			{
				f := s.Begin()
				s.Bool(v.bodyCellTrafficTrace == nil)
				if v.bodyCellTrafficTrace != nil {
					s25.BridgeCaptureS1APCellTrafficTrace(v.bodyCellTrafficTrace, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyKillRequest == nil)
				if v.bodyKillRequest != nil {
					s42.BridgeCaptureS1APKillRequest(v.bodyKillRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(44):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkUEAssociatedLPPaTransport == nil)
				if v.bodyDownlinkUEAssociatedLPPaTransport != nil {
					s18.BridgeCaptureS1APDownlinkUEAssociatedLPPaTransport(v.bodyDownlinkUEAssociatedLPPaTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(45):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkUEAssociatedLPPaTransport == nil)
				if v.bodyUplinkUEAssociatedLPPaTransport != nil {
					s55.BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(v.bodyUplinkUEAssociatedLPPaTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(46):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkNonUEAssociatedLPPaTransport == nil)
				if v.bodyDownlinkNonUEAssociatedLPPaTransport != nil {
					s18.BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransport(v.bodyDownlinkNonUEAssociatedLPPaTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(47):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkNonUEAssociatedLPPaTransport == nil)
				if v.bodyUplinkNonUEAssociatedLPPaTransport != nil {
					s55.BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(v.bodyUplinkNonUEAssociatedLPPaTransport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchRequest == nil)
				if v.bodyUERadioCapabilityMatchRequest != nil {
					s46.BridgeCaptureS1APUERadioCapabilityMatchRequest(v.bodyUERadioCapabilityMatchRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(49):
			{
				f := s.Begin()
				s.Bool(v.bodyPWSRestartIndication == nil)
				if v.bodyPWSRestartIndication != nil {
					s55.BridgeCaptureS1APPWSRestartIndication(v.bodyPWSRestartIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationIndication == nil)
				if v.bodyERABModificationIndication != nil {
					s57.BridgeCaptureS1APERABModificationIndication(v.bodyERABModificationIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(51):
			{
				f := s.Begin()
				s.Bool(v.bodyPWSFailureIndication == nil)
				if v.bodyPWSFailureIndication != nil {
					s52.BridgeCaptureS1APPWSFailureIndication(v.bodyPWSFailureIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(52):
			{
				f := s.Begin()
				s.Bool(v.bodyRerouteNASRequest == nil)
				if v.bodyRerouteNASRequest != nil {
					s31.BridgeCaptureS1APRerouteNASRequest(v.bodyRerouteNASRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationIndication == nil)
				if v.bodyUEContextModificationIndication != nil {
					s46.BridgeCaptureS1APUEContextModificationIndication(v.bodyUEContextModificationIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(54):
			{
				f := s.Begin()
				s.Bool(v.bodyConnectionEstablishmentIndication == nil)
				if v.bodyConnectionEstablishmentIndication != nil {
					s40.BridgeCaptureS1APConnectionEstablishmentIndication(v.bodyConnectionEstablishmentIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendRequest == nil)
				if v.bodyUEContextSuspendRequest != nil {
					s57.BridgeCaptureS1APUEContextSuspendRequest(v.bodyUEContextSuspendRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeRequest == nil)
				if v.bodyUEContextResumeRequest != nil {
					s48.BridgeCaptureS1APUEContextResumeRequest(v.bodyUEContextResumeRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(57):
			{
				f := s.Begin()
				s.Bool(v.bodyNASDeliveryIndication == nil)
				if v.bodyNASDeliveryIndication != nil {
					s22.BridgeCaptureS1APNASDeliveryIndication(v.bodyNASDeliveryIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(58):
			{
				f := s.Begin()
				s.Bool(v.bodyRetrieveUEInformation == nil)
				if v.bodyRetrieveUEInformation != nil {
					s36.BridgeCaptureS1APRetrieveUEInformation(v.bodyRetrieveUEInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(59):
			{
				f := s.Begin()
				s.Bool(v.bodyUEInformationTransfer == nil)
				if v.bodyUEInformationTransfer != nil {
					s46.BridgeCaptureS1APUEInformationTransfer(v.bodyUEInformationTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(60):
			{
				f := s.Begin()
				s.Bool(v.bodyENBCPRelocationIndication == nil)
				if v.bodyENBCPRelocationIndication != nil {
					s47.BridgeCaptureS1APENBCPRelocationIndication(v.bodyENBCPRelocationIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(61):
			{
				f := s.Begin()
				s.Bool(v.bodyMMECPRelocationIndication == nil)
				if v.bodyMMECPRelocationIndication != nil {
					s22.BridgeCaptureS1APMMECPRelocationIndication(v.bodyMMECPRelocationIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(62):
			{
				f := s.Begin()
				s.Bool(v.bodySecondaryRATDataUsageReport == nil)
				if v.bodySecondaryRATDataUsageReport != nil {
					s57.BridgeCaptureS1APSecondaryRATDataUsageReport(v.bodySecondaryRATDataUsageReport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingRequest == nil)
				if v.bodyUERadioCapabilityIDMappingRequest != nil {
					s46.BridgeCaptureS1APUERadioCapabilityIDMappingRequest(v.bodyUERadioCapabilityIDMappingRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(64):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverSuccess == nil)
				if v.bodyHandoverSuccess != nil {
					s21.BridgeCaptureS1APHandoverSuccess(v.bodyHandoverSuccess, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(65):
			{
				f := s.Begin()
				s.Bool(v.bodyENBEarlyStatusTransfer == nil)
				if v.bodyENBEarlyStatusTransfer != nil {
					s47.BridgeCaptureS1APENBEarlyStatusTransfer(v.bodyENBEarlyStatusTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(66):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEEarlyStatusTransfer == nil)
				if v.bodyMMEEarlyStatusTransfer != nil {
					s48.BridgeCaptureS1APMMEEarlyStatusTransfer(v.bodyMMEEarlyStatusTransfer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalRequest == nil)
				if v.bodyS1RemovalRequest != nil {
					s31.BridgeCaptureS1APS1RemovalRequest(v.bodyS1RemovalRequest, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitiatingValue) captureSemantics(s aper.SemanticCapture) InitiatingValue {
	BridgeCaptureS1APInitiatingValue(&v, &s)
	return v
}
func BridgeCompareS1APInitiatingValue(v *InitiatingValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequired == nil)
				if v.bodyHandoverRequired != nil {
					s43.BridgeCompareS1APHandoverRequired(v.bodyHandoverRequired, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequest == nil)
				if v.bodyHandoverRequest != nil {
					s60.BridgeCompareS1APHandoverRequest(v.bodyHandoverRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverNotify == nil)
				if v.bodyHandoverNotify != nil {
					s44.BridgeCompareS1APHandoverNotify(v.bodyHandoverNotify, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequest == nil)
				if v.bodyPathSwitchRequest != nil {
					s51.BridgeCompareS1APPathSwitchRequest(v.bodyPathSwitchRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancel == nil)
				if v.bodyHandoverCancel != nil {
					s29.BridgeCompareS1APHandoverCancel(v.bodyHandoverCancel, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupRequest == nil)
				if v.bodyERABSetupRequest != nil {
					s51.BridgeCompareS1APERABSetupRequest(v.bodyERABSetupRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyRequest == nil)
				if v.bodyERABModifyRequest != nil {
					s51.BridgeCompareS1APERABModifyRequest(v.bodyERABModifyRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseCommand == nil)
				if v.bodyERABReleaseCommand != nil {
					s49.BridgeCompareS1APERABReleaseCommand(v.bodyERABReleaseCommand, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseIndication == nil)
				if v.bodyERABReleaseIndication != nil {
					s57.BridgeCompareS1APERABReleaseIndication(v.bodyERABReleaseIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupRequest == nil)
				if v.bodyInitialContextSetupRequest != nil {
					s60.BridgeCompareS1APInitialContextSetupRequest(v.bodyInitialContextSetupRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyPaging == nil)
				if v.bodyPaging != nil {
					s61.BridgeCompareS1APPaging(v.bodyPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(11):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkNASTransport == nil)
				if v.bodyDownlinkNASTransport != nil {
					s53.BridgeCompareS1APDownlinkNASTransport(v.bodyDownlinkNASTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(12):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialUEMessage == nil)
				if v.bodyInitialUEMessage != nil {
					s45.BridgeCompareS1APInitialUEMessage(v.bodyInitialUEMessage, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(13):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkNASTransport == nil)
				if v.bodyUplinkNASTransport != nil {
					s55.BridgeCompareS1APUplinkNASTransport(v.bodyUplinkNASTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyReset == nil)
				if v.bodyReset != nil {
					s45.BridgeCompareS1APReset(v.bodyReset, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(15):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					s36.BridgeCompareS1APErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(16):
			{
				f := s.Begin()
				s.Bool(v.bodyNASNonDeliveryIndication == nil)
				if v.bodyNASNonDeliveryIndication != nil {
					s30.BridgeCompareS1APNASNonDeliveryIndication(v.bodyNASNonDeliveryIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupRequest == nil)
				if v.bodyS1SetupRequest != nil {
					s54.BridgeCompareS1APS1SetupRequest(v.bodyS1SetupRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(18):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseRequest == nil)
				if v.bodyUEContextReleaseRequest != nil {
					s53.BridgeCompareS1APUEContextReleaseRequest(v.bodyUEContextReleaseRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(19):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkS1cdma2000tunnelling == nil)
				if v.bodyDownlinkS1cdma2000tunnelling != nil {
					s50.BridgeCompareS1APDownlinkS1cdma2000tunnelling(v.bodyDownlinkS1cdma2000tunnelling, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(20):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkS1cdma2000tunnelling == nil)
				if v.bodyUplinkS1cdma2000tunnelling != nil {
					s55.BridgeCompareS1APUplinkS1cdma2000tunnelling(v.bodyUplinkS1cdma2000tunnelling, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationRequest == nil)
				if v.bodyUEContextModificationRequest != nil {
					s58.BridgeCompareS1APUEContextModificationRequest(v.bodyUEContextModificationRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(22):
			{
				f := s.Begin()
				s.Bool(v.bodyUECapabilityInfoIndication == nil)
				if v.bodyUECapabilityInfoIndication != nil {
					s45.BridgeCompareS1APUECapabilityInfoIndication(v.bodyUECapabilityInfoIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseCommand == nil)
				if v.bodyUEContextReleaseCommand != nil {
					s47.BridgeCompareS1APUEContextReleaseCommand(v.bodyUEContextReleaseCommand, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(24):
			{
				f := s.Begin()
				s.Bool(v.bodyENBStatusTransfer == nil)
				if v.bodyENBStatusTransfer != nil {
					s28.BridgeCompareS1APENBStatusTransfer(v.bodyENBStatusTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(25):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEStatusTransfer == nil)
				if v.bodyMMEStatusTransfer != nil {
					s30.BridgeCompareS1APMMEStatusTransfer(v.bodyMMEStatusTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(26):
			{
				f := s.Begin()
				s.Bool(v.bodyDeactivateTrace == nil)
				if v.bodyDeactivateTrace != nil {
					s18.BridgeCompareS1APDeactivateTrace(v.bodyDeactivateTrace, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(27):
			{
				f := s.Begin()
				s.Bool(v.bodyTraceStart == nil)
				if v.bodyTraceStart != nil {
					s61.BridgeCompareS1APTraceStart(v.bodyTraceStart, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(28):
			{
				f := s.Begin()
				s.Bool(v.bodyTraceFailureIndication == nil)
				if v.bodyTraceFailureIndication != nil {
					s44.BridgeCompareS1APTraceFailureIndication(v.bodyTraceFailureIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdate == nil)
				if v.bodyENBConfigurationUpdate != nil {
					s54.BridgeCompareS1APENBConfigurationUpdate(v.bodyENBConfigurationUpdate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdate == nil)
				if v.bodyMMEConfigurationUpdate != nil {
					s54.BridgeCompareS1APMMEConfigurationUpdate(v.bodyMMEConfigurationUpdate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(31):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReportingControl == nil)
				if v.bodyLocationReportingControl != nil {
					s31.BridgeCompareS1APLocationReportingControl(v.bodyLocationReportingControl, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(32):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReportingFailureIndication == nil)
				if v.bodyLocationReportingFailureIndication != nil {
					s30.BridgeCompareS1APLocationReportingFailureIndication(v.bodyLocationReportingFailureIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(33):
			{
				f := s.Begin()
				s.Bool(v.bodyLocationReport == nil)
				if v.bodyLocationReport != nil {
					s42.BridgeCompareS1APLocationReport(v.bodyLocationReport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(34):
			{
				f := s.Begin()
				s.Bool(v.bodyOverloadStart == nil)
				if v.bodyOverloadStart != nil {
					s52.BridgeCompareS1APOverloadStart(v.bodyOverloadStart, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(35):
			{
				f := s.Begin()
				s.Bool(v.bodyOverloadStop == nil)
				if v.bodyOverloadStop != nil {
					s52.BridgeCompareS1APOverloadStop(v.bodyOverloadStop, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyWriteReplaceWarningRequest == nil)
				if v.bodyWriteReplaceWarningRequest != nil {
					s64.BridgeCompareS1APWriteReplaceWarningRequest(v.bodyWriteReplaceWarningRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(37):
			{
				f := s.Begin()
				s.Bool(v.bodyENBDirectInformationTransfer == nil)
				if v.bodyENBDirectInformationTransfer != nil {
					s43.BridgeCompareS1APENBDirectInformationTransfer(v.bodyENBDirectInformationTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(38):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEDirectInformationTransfer == nil)
				if v.bodyMMEDirectInformationTransfer != nil {
					s43.BridgeCompareS1APMMEDirectInformationTransfer(v.bodyMMEDirectInformationTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(39):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					s30.BridgeCompareS1APPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(40):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationTransfer == nil)
				if v.bodyENBConfigurationTransfer != nil {
					BridgeCompareS1APENBConfigurationTransfer(v.bodyENBConfigurationTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(41):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationTransfer == nil)
				if v.bodyMMEConfigurationTransfer != nil {
					BridgeCompareS1APMMEConfigurationTransfer(v.bodyMMEConfigurationTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(42):
			{
				f := s.Begin()
				s.Bool(v.bodyCellTrafficTrace == nil)
				if v.bodyCellTrafficTrace != nil {
					s25.BridgeCompareS1APCellTrafficTrace(v.bodyCellTrafficTrace, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyKillRequest == nil)
				if v.bodyKillRequest != nil {
					s42.BridgeCompareS1APKillRequest(v.bodyKillRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(44):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkUEAssociatedLPPaTransport == nil)
				if v.bodyDownlinkUEAssociatedLPPaTransport != nil {
					s18.BridgeCompareS1APDownlinkUEAssociatedLPPaTransport(v.bodyDownlinkUEAssociatedLPPaTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(45):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkUEAssociatedLPPaTransport == nil)
				if v.bodyUplinkUEAssociatedLPPaTransport != nil {
					s55.BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v.bodyUplinkUEAssociatedLPPaTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(46):
			{
				f := s.Begin()
				s.Bool(v.bodyDownlinkNonUEAssociatedLPPaTransport == nil)
				if v.bodyDownlinkNonUEAssociatedLPPaTransport != nil {
					s18.BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransport(v.bodyDownlinkNonUEAssociatedLPPaTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(47):
			{
				f := s.Begin()
				s.Bool(v.bodyUplinkNonUEAssociatedLPPaTransport == nil)
				if v.bodyUplinkNonUEAssociatedLPPaTransport != nil {
					s55.BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v.bodyUplinkNonUEAssociatedLPPaTransport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchRequest == nil)
				if v.bodyUERadioCapabilityMatchRequest != nil {
					s46.BridgeCompareS1APUERadioCapabilityMatchRequest(v.bodyUERadioCapabilityMatchRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(49):
			{
				f := s.Begin()
				s.Bool(v.bodyPWSRestartIndication == nil)
				if v.bodyPWSRestartIndication != nil {
					s55.BridgeCompareS1APPWSRestartIndication(v.bodyPWSRestartIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationIndication == nil)
				if v.bodyERABModificationIndication != nil {
					s57.BridgeCompareS1APERABModificationIndication(v.bodyERABModificationIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(51):
			{
				f := s.Begin()
				s.Bool(v.bodyPWSFailureIndication == nil)
				if v.bodyPWSFailureIndication != nil {
					s52.BridgeCompareS1APPWSFailureIndication(v.bodyPWSFailureIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(52):
			{
				f := s.Begin()
				s.Bool(v.bodyRerouteNASRequest == nil)
				if v.bodyRerouteNASRequest != nil {
					s31.BridgeCompareS1APRerouteNASRequest(v.bodyRerouteNASRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationIndication == nil)
				if v.bodyUEContextModificationIndication != nil {
					s46.BridgeCompareS1APUEContextModificationIndication(v.bodyUEContextModificationIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(54):
			{
				f := s.Begin()
				s.Bool(v.bodyConnectionEstablishmentIndication == nil)
				if v.bodyConnectionEstablishmentIndication != nil {
					s40.BridgeCompareS1APConnectionEstablishmentIndication(v.bodyConnectionEstablishmentIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendRequest == nil)
				if v.bodyUEContextSuspendRequest != nil {
					s57.BridgeCompareS1APUEContextSuspendRequest(v.bodyUEContextSuspendRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeRequest == nil)
				if v.bodyUEContextResumeRequest != nil {
					s48.BridgeCompareS1APUEContextResumeRequest(v.bodyUEContextResumeRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(57):
			{
				f := s.Begin()
				s.Bool(v.bodyNASDeliveryIndication == nil)
				if v.bodyNASDeliveryIndication != nil {
					s22.BridgeCompareS1APNASDeliveryIndication(v.bodyNASDeliveryIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(58):
			{
				f := s.Begin()
				s.Bool(v.bodyRetrieveUEInformation == nil)
				if v.bodyRetrieveUEInformation != nil {
					s36.BridgeCompareS1APRetrieveUEInformation(v.bodyRetrieveUEInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(59):
			{
				f := s.Begin()
				s.Bool(v.bodyUEInformationTransfer == nil)
				if v.bodyUEInformationTransfer != nil {
					s46.BridgeCompareS1APUEInformationTransfer(v.bodyUEInformationTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(60):
			{
				f := s.Begin()
				s.Bool(v.bodyENBCPRelocationIndication == nil)
				if v.bodyENBCPRelocationIndication != nil {
					s47.BridgeCompareS1APENBCPRelocationIndication(v.bodyENBCPRelocationIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(61):
			{
				f := s.Begin()
				s.Bool(v.bodyMMECPRelocationIndication == nil)
				if v.bodyMMECPRelocationIndication != nil {
					s22.BridgeCompareS1APMMECPRelocationIndication(v.bodyMMECPRelocationIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(62):
			{
				f := s.Begin()
				s.Bool(v.bodySecondaryRATDataUsageReport == nil)
				if v.bodySecondaryRATDataUsageReport != nil {
					s57.BridgeCompareS1APSecondaryRATDataUsageReport(v.bodySecondaryRATDataUsageReport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingRequest == nil)
				if v.bodyUERadioCapabilityIDMappingRequest != nil {
					s46.BridgeCompareS1APUERadioCapabilityIDMappingRequest(v.bodyUERadioCapabilityIDMappingRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(64):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverSuccess == nil)
				if v.bodyHandoverSuccess != nil {
					s21.BridgeCompareS1APHandoverSuccess(v.bodyHandoverSuccess, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(65):
			{
				f := s.Begin()
				s.Bool(v.bodyENBEarlyStatusTransfer == nil)
				if v.bodyENBEarlyStatusTransfer != nil {
					s47.BridgeCompareS1APENBEarlyStatusTransfer(v.bodyENBEarlyStatusTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(66):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEEarlyStatusTransfer == nil)
				if v.bodyMMEEarlyStatusTransfer != nil {
					s48.BridgeCompareS1APMMEEarlyStatusTransfer(v.bodyMMEEarlyStatusTransfer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalRequest == nil)
				if v.bodyS1RemovalRequest != nil {
					s31.BridgeCompareS1APS1RemovalRequest(v.bodyS1RemovalRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitiatingValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APInitiatingValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEConfigurationTransfer(v *MMEConfigurationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEConfigurationTransfer(v *MMEConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s23.BridgeCaptureS1APPrivateIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s23.BridgeCompareS1APPrivateIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APProtocolErrorIEContainerList[V ProtocolOpenValueConstraint[V]](v *ProtocolErrorIEContainerList[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APProtocolErrorIEContainerList[V ProtocolOpenValueConstraint[V]](v *ProtocolErrorIEContainerList[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APProtocolIEContainerList[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainerList[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCaptureS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APProtocolIEContainerList[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainerList[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APProtocolIESingleContainer[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APProtocolIEField[V](v, s)
	s.End(f, nil, false)
}
func BridgeCompareS1APProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEField[V](v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBConfigurationTransfer represents the ASN.1 type ENBConfigurationTransfer (SEQUENCE).
type ENBConfigurationTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s64.ENBConfigurationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEConfigurationTransfer represents the ASN.1 type MMEConfigurationTransfer (SEQUENCE).
type MMEConfigurationTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s64.MMEConfigurationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ENBConfigurationTransfer to APER format.
func (v *ENBConfigurationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
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
			if err := s64.BridgeENBConfigurationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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

// UnmarshalAPER decodes ENBConfigurationTransfer from APER format.
func (v *ENBConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBConfigurationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationTransfer")
	}
	bb.EnterComponent("ENBConfigurationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationTransfer")
	}
	v.perPadding = padding
	return nil
}
func (v *ENBConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s64.ENBConfigurationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s64.ENBConfigurationTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s64.BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MMEConfigurationTransfer to APER format.
func (v *MMEConfigurationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEConfigurationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
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
			if err := s64.BridgeMMEConfigurationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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

// UnmarshalAPER decodes MMEConfigurationTransfer from APER format.
func (v *MMEConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MMEConfigurationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationTransfer")
	}
	bb.EnterComponent("MMEConfigurationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEConfigurationTransfer")
	}
	v.perPadding = padding
	return nil
}
func (v *MMEConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s64.MMEConfigurationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s64.MMEConfigurationTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s64.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBConfigurationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationTransfer) WithoutReplay() ENBConfigurationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEConfigurationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEConfigurationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEConfigurationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEConfigurationTransfer) WithoutReplay() MMEConfigurationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEConfigurationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEConfigurationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEConfigurationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEConfigurationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBConfigurationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationTransfer")
}
func (v *ENBConfigurationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationTransfer")
}
func (v *ENBConfigurationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationTransfer(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *ENBConfigurationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MMEConfigurationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEConfigurationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEConfigurationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEConfigurationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEConfigurationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEConfigurationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEConfigurationTransfer")
}
func (v *MMEConfigurationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEConfigurationTransfer")
}
func (v *MMEConfigurationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEConfigurationTransfer(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *MMEConfigurationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEConfigurationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBConfigurationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationTransfer{}
		return report, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEConfigurationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEConfigurationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEConfigurationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEConfigurationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEConfigurationTransfer{}
		return report, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEConfigurationTransfer")
}

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProcedureCode    s00.ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            InitiatingValue      `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// MarshalAPER encodes InitiatingMessage to APER format.
func (v *InitiatingMessage) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InitiatingMessage) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Value.code != v.ProcedureCode {
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "InitiatingMessage.ProcedureCode")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
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

// UnmarshalAPER decodes InitiatingMessage from APER format.
func (v *InitiatingMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *InitiatingMessage) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	bb.EnterComponent("InitiatingMessage")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	padding, err := aper.CaptureFinalBits(bb, "InitiatingMessage")
	if err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InitiatingMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitiatingMessage{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = s00.ProcedureCode(val_procedurecode)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	toleranceMark_value := bb.EnterComponent("Value")
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.InitiatingReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "Initiating"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("InitiatingMessage.Value")
	decoded_value, err := BridgeDecodeInitiatingValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitiatingMessage) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitiatingMessage", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InitiatingMessage", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitiatingMessage) WithoutReplay() InitiatingMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InitiatingMessage
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InitiatingMessage) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InitiatingMessage")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InitiatingMessage) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InitiatingMessage")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInitiatingMessage(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InitiatingMessage")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InitiatingMessage")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InitiatingMessage) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InitiatingMessage")
}
func (v *InitiatingMessage) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InitiatingMessage")
}
func (v *InitiatingMessage) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInitiatingMessage(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *InitiatingMessage) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InitiatingMessage) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InitiatingMessage) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InitiatingMessage")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InitiatingMessage
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInitiatingMessage(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InitiatingMessage{}
		return report, aper.OperationError(err, "InitiatingMessage")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InitiatingMessage")
}

type IETable[V ProtocolOpenValueConstraint[V]] struct{ bound bool }

// IETableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueIETableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec]
//   - [BearersSubjectToStatusTransferItemIEValueIETableCodec]
//   - [CellTrafficTraceIEValueIETableCodec]
//   - [ConnectionEstablishmentIndicationIEValueIETableCodec]
//   - [DAPSResponseInfoListIEValueIETableCodec]
//   - [DeactivateTraceIEValueIETableCodec]
//   - [DownlinkNASTransportIEValueIETableCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueIETableCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [ENBCPRelocationIndicationIEValueIETableCodec]
//   - [ENBConfigurationTransferIEValueIETableCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueIETableCodec]
//   - [ENBConfigurationUpdateFailureIEValueIETableCodec]
//   - [ENBConfigurationUpdateIEValueIETableCodec]
//   - [ENBDirectInformationTransferIEValueIETableCodec]
//   - [ENBEarlyStatusTransferIEValueIETableCodec]
//   - [ENBStatusTransferIEValueIETableCodec]
//   - [ERABAdmittedItemIEValueIETableCodec]
//   - [ERABDataForwardingItemIEValueIETableCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueIETableCodec]
//   - [ERABFailedToResumeItemResumeResIEValueIETableCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueIETableCodec]
//   - [ERABInformationListIEValueIETableCodec]
//   - [ERABItemIEValueIETableCodec]
//   - [ERABModificationConfirmIEValueIETableCodec]
//   - [ERABModificationIndicationIEValueIETableCodec]
//   - [ERABModifyItemBearerModConfIEValueIETableCodec]
//   - [ERABModifyItemBearerModResIEValueIETableCodec]
//   - [ERABModifyRequestIEValueIETableCodec]
//   - [ERABModifyResponseIEValueIETableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec]
//   - [ERABReleaseCommandIEValueIETableCodec]
//   - [ERABReleaseIndicationIEValueIETableCodec]
//   - [ERABReleaseItemBearerRelCompIEValueIETableCodec]
//   - [ERABReleaseResponseIEValueIETableCodec]
//   - [ERABSecurityResultListIEValueIETableCodec]
//   - [ERABSetupItemBearerSUResIEValueIETableCodec]
//   - [ERABSetupItemCtxtSUResIEValueIETableCodec]
//   - [ERABSetupRequestIEValueIETableCodec]
//   - [ERABSetupResponseIEValueIETableCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueIETableCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueIETableCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueIETableCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueIETableCodec]
//   - [ERABToBeSetupItemHOReqIEValueIETableCodec]
//   - [ERABToBeSwitchedDLItemIEValueIETableCodec]
//   - [ERABToBeSwitchedULItemIEValueIETableCodec]
//   - [ERABToBeUpdatedItemIEValueIETableCodec]
//   - [ERABUsageReportItemIEValueIETableCodec]
//   - [ErrorIndicationIEValueIETableCodec]
//   - [EventTriggerExtIEValueIETableCodec]
//   - [HandoverCancelAcknowledgeIEValueIETableCodec]
//   - [HandoverCancelIEValueIETableCodec]
//   - [HandoverCommandIEValueIETableCodec]
//   - [HandoverFailureIEValueIETableCodec]
//   - [HandoverNotifyIEValueIETableCodec]
//   - [HandoverPreparationFailureIEValueIETableCodec]
//   - [HandoverRequestAcknowledgeIEValueIETableCodec]
//   - [HandoverRequestIEValueIETableCodec]
//   - [HandoverRequiredIEValueIETableCodec]
//   - [HandoverSuccessIEValueIETableCodec]
//   - [InitialContextSetupFailureIEValueIETableCodec]
//   - [InitialContextSetupRequestIEValueIETableCodec]
//   - [InitialContextSetupResponseIEValueIETableCodec]
//   - [InitialUEMessageIEValueIETableCodec]
//   - [KillRequestIEValueIETableCodec]
//   - [KillResponseIEValueIETableCodec]
//   - [LocationReportIEValueIETableCodec]
//   - [LocationReportingControlIEValueIETableCodec]
//   - [LocationReportingFailureIndicationIEValueIETableCodec]
//   - [MDTModeExtensionIEIEValueIETableCodec]
//   - [MMECPRelocationIndicationIEValueIETableCodec]
//   - [MMEConfigurationTransferIEValueIETableCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueIETableCodec]
//   - [MMEConfigurationUpdateFailureIEValueIETableCodec]
//   - [MMEConfigurationUpdateIEValueIETableCodec]
//   - [MMEDirectInformationTransferIEValueIETableCodec]
//   - [MMEEarlyStatusTransferIEValueIETableCodec]
//   - [MMEStatusTransferIEValueIETableCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec]
//   - [NASDeliveryIndicationIEValueIETableCodec]
//   - [NASNonDeliveryIndicationIEValueIETableCodec]
//   - [OverloadStartIEValueIETableCodec]
//   - [OverloadStopIEValueIETableCodec]
//   - [PWSFailureIndicationIEValueIETableCodec]
//   - [PWSRestartIndicationIEValueIETableCodec]
//   - [PagingIEValueIETableCodec]
//   - [PathSwitchRequestAcknowledgeIEValueIETableCodec]
//   - [PathSwitchRequestFailureIEValueIETableCodec]
//   - [PathSwitchRequestIEValueIETableCodec]
//   - [RecommendedCellItemIEValueIETableCodec]
//   - [RecommendedENBItemIEValueIETableCodec]
//   - [RerouteNASRequestIEValueIETableCodec]
//   - [ResetAcknowledgeIEValueIETableCodec]
//   - [ResetIEValueIETableCodec]
//   - [RetrieveUEInformationIEValueIETableCodec]
//   - [S1RemovalFailureIEValueIETableCodec]
//   - [S1RemovalRequestIEValueIETableCodec]
//   - [S1RemovalResponseIEValueIETableCodec]
//   - [S1SetupFailureIEValueIETableCodec]
//   - [S1SetupRequestIEValueIETableCodec]
//   - [S1SetupResponseIEValueIETableCodec]
//   - [SONInformationExtensionIEIEValueIETableCodec]
//   - [SecondaryRATDataUsageReportIEValueIETableCodec]
//   - [SecondaryRATDataUsageReportItemIEValueIETableCodec]
//   - [SensorNameConfigExtIEValueIETableCodec]
//   - [SourceNodeIDExtensionIEIEValueIETableCodec]
//   - [TAIItemIEValueIETableCodec]
//   - [TraceFailureIndicationIEValueIETableCodec]
//   - [TraceStartIEValueIETableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec]
//   - [UECapabilityInfoIndicationIEValueIETableCodec]
//   - [UEContextModificationConfirmIEValueIETableCodec]
//   - [UEContextModificationFailureIEValueIETableCodec]
//   - [UEContextModificationIndicationIEValueIETableCodec]
//   - [UEContextModificationRequestIEValueIETableCodec]
//   - [UEContextModificationResponseIEValueIETableCodec]
//   - [UEContextReleaseCommandIEValueIETableCodec]
//   - [UEContextReleaseCompleteIEValueIETableCodec]
//   - [UEContextReleaseRequestIEValueIETableCodec]
//   - [UEContextResumeFailureIEValueIETableCodec]
//   - [UEContextResumeRequestIEValueIETableCodec]
//   - [UEContextResumeResponseIEValueIETableCodec]
//   - [UEContextSuspendRequestIEValueIETableCodec]
//   - [UEContextSuspendResponseIEValueIETableCodec]
//   - [UEInformationTransferIEValueIETableCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueIETableCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueIETableCodec]
//   - [UERadioCapabilityMatchRequestIEValueIETableCodec]
//   - [UERadioCapabilityMatchResponseIEValueIETableCodec]
//   - [UplinkNASTransportIEValueIETableCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [UplinkS1cdma2000tunnellingIEValueIETableCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [WriteReplaceWarningRequestIEValueIETableCodec]
//   - [WriteReplaceWarningResponseIEValueIETableCodec]
type IETableCodec[V ProtocolOpenValueConstraint[V]] struct{}

// IETableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueIETableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec]
//   - [BearersSubjectToStatusTransferItemIEValueIETableCodec]
//   - [CellTrafficTraceIEValueIETableCodec]
//   - [ConnectionEstablishmentIndicationIEValueIETableCodec]
//   - [DAPSResponseInfoListIEValueIETableCodec]
//   - [DeactivateTraceIEValueIETableCodec]
//   - [DownlinkNASTransportIEValueIETableCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueIETableCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [ENBCPRelocationIndicationIEValueIETableCodec]
//   - [ENBConfigurationTransferIEValueIETableCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueIETableCodec]
//   - [ENBConfigurationUpdateFailureIEValueIETableCodec]
//   - [ENBConfigurationUpdateIEValueIETableCodec]
//   - [ENBDirectInformationTransferIEValueIETableCodec]
//   - [ENBEarlyStatusTransferIEValueIETableCodec]
//   - [ENBStatusTransferIEValueIETableCodec]
//   - [ERABAdmittedItemIEValueIETableCodec]
//   - [ERABDataForwardingItemIEValueIETableCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueIETableCodec]
//   - [ERABFailedToResumeItemResumeResIEValueIETableCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueIETableCodec]
//   - [ERABInformationListIEValueIETableCodec]
//   - [ERABItemIEValueIETableCodec]
//   - [ERABModificationConfirmIEValueIETableCodec]
//   - [ERABModificationIndicationIEValueIETableCodec]
//   - [ERABModifyItemBearerModConfIEValueIETableCodec]
//   - [ERABModifyItemBearerModResIEValueIETableCodec]
//   - [ERABModifyRequestIEValueIETableCodec]
//   - [ERABModifyResponseIEValueIETableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueIETableCodec]
//   - [ERABReleaseCommandIEValueIETableCodec]
//   - [ERABReleaseIndicationIEValueIETableCodec]
//   - [ERABReleaseItemBearerRelCompIEValueIETableCodec]
//   - [ERABReleaseResponseIEValueIETableCodec]
//   - [ERABSecurityResultListIEValueIETableCodec]
//   - [ERABSetupItemBearerSUResIEValueIETableCodec]
//   - [ERABSetupItemCtxtSUResIEValueIETableCodec]
//   - [ERABSetupRequestIEValueIETableCodec]
//   - [ERABSetupResponseIEValueIETableCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueIETableCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueIETableCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueIETableCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueIETableCodec]
//   - [ERABToBeSetupItemHOReqIEValueIETableCodec]
//   - [ERABToBeSwitchedDLItemIEValueIETableCodec]
//   - [ERABToBeSwitchedULItemIEValueIETableCodec]
//   - [ERABToBeUpdatedItemIEValueIETableCodec]
//   - [ERABUsageReportItemIEValueIETableCodec]
//   - [ErrorIndicationIEValueIETableCodec]
//   - [EventTriggerExtIEValueIETableCodec]
//   - [HandoverCancelAcknowledgeIEValueIETableCodec]
//   - [HandoverCancelIEValueIETableCodec]
//   - [HandoverCommandIEValueIETableCodec]
//   - [HandoverFailureIEValueIETableCodec]
//   - [HandoverNotifyIEValueIETableCodec]
//   - [HandoverPreparationFailureIEValueIETableCodec]
//   - [HandoverRequestAcknowledgeIEValueIETableCodec]
//   - [HandoverRequestIEValueIETableCodec]
//   - [HandoverRequiredIEValueIETableCodec]
//   - [HandoverSuccessIEValueIETableCodec]
//   - [InitialContextSetupFailureIEValueIETableCodec]
//   - [InitialContextSetupRequestIEValueIETableCodec]
//   - [InitialContextSetupResponseIEValueIETableCodec]
//   - [InitialUEMessageIEValueIETableCodec]
//   - [KillRequestIEValueIETableCodec]
//   - [KillResponseIEValueIETableCodec]
//   - [LocationReportIEValueIETableCodec]
//   - [LocationReportingControlIEValueIETableCodec]
//   - [LocationReportingFailureIndicationIEValueIETableCodec]
//   - [MDTModeExtensionIEIEValueIETableCodec]
//   - [MMECPRelocationIndicationIEValueIETableCodec]
//   - [MMEConfigurationTransferIEValueIETableCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueIETableCodec]
//   - [MMEConfigurationUpdateFailureIEValueIETableCodec]
//   - [MMEConfigurationUpdateIEValueIETableCodec]
//   - [MMEDirectInformationTransferIEValueIETableCodec]
//   - [MMEEarlyStatusTransferIEValueIETableCodec]
//   - [MMEStatusTransferIEValueIETableCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec]
//   - [NASDeliveryIndicationIEValueIETableCodec]
//   - [NASNonDeliveryIndicationIEValueIETableCodec]
//   - [OverloadStartIEValueIETableCodec]
//   - [OverloadStopIEValueIETableCodec]
//   - [PWSFailureIndicationIEValueIETableCodec]
//   - [PWSRestartIndicationIEValueIETableCodec]
//   - [PagingIEValueIETableCodec]
//   - [PathSwitchRequestAcknowledgeIEValueIETableCodec]
//   - [PathSwitchRequestFailureIEValueIETableCodec]
//   - [PathSwitchRequestIEValueIETableCodec]
//   - [RecommendedCellItemIEValueIETableCodec]
//   - [RecommendedENBItemIEValueIETableCodec]
//   - [RerouteNASRequestIEValueIETableCodec]
//   - [ResetAcknowledgeIEValueIETableCodec]
//   - [ResetIEValueIETableCodec]
//   - [RetrieveUEInformationIEValueIETableCodec]
//   - [S1RemovalFailureIEValueIETableCodec]
//   - [S1RemovalRequestIEValueIETableCodec]
//   - [S1RemovalResponseIEValueIETableCodec]
//   - [S1SetupFailureIEValueIETableCodec]
//   - [S1SetupRequestIEValueIETableCodec]
//   - [S1SetupResponseIEValueIETableCodec]
//   - [SONInformationExtensionIEIEValueIETableCodec]
//   - [SecondaryRATDataUsageReportIEValueIETableCodec]
//   - [SecondaryRATDataUsageReportItemIEValueIETableCodec]
//   - [SensorNameConfigExtIEValueIETableCodec]
//   - [SourceNodeIDExtensionIEIEValueIETableCodec]
//   - [TAIItemIEValueIETableCodec]
//   - [TraceFailureIndicationIEValueIETableCodec]
//   - [TraceStartIEValueIETableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec]
//   - [UECapabilityInfoIndicationIEValueIETableCodec]
//   - [UEContextModificationConfirmIEValueIETableCodec]
//   - [UEContextModificationFailureIEValueIETableCodec]
//   - [UEContextModificationIndicationIEValueIETableCodec]
//   - [UEContextModificationRequestIEValueIETableCodec]
//   - [UEContextModificationResponseIEValueIETableCodec]
//   - [UEContextReleaseCommandIEValueIETableCodec]
//   - [UEContextReleaseCompleteIEValueIETableCodec]
//   - [UEContextReleaseRequestIEValueIETableCodec]
//   - [UEContextResumeFailureIEValueIETableCodec]
//   - [UEContextResumeRequestIEValueIETableCodec]
//   - [UEContextResumeResponseIEValueIETableCodec]
//   - [UEContextSuspendRequestIEValueIETableCodec]
//   - [UEContextSuspendResponseIEValueIETableCodec]
//   - [UEInformationTransferIEValueIETableCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueIETableCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueIETableCodec]
//   - [UERadioCapabilityMatchRequestIEValueIETableCodec]
//   - [UERadioCapabilityMatchResponseIEValueIETableCodec]
//   - [UplinkNASTransportIEValueIETableCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [UplinkS1cdma2000tunnellingIEValueIETableCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueIETableCodec]
//   - [WriteReplaceWarningRequestIEValueIETableCodec]
//   - [WriteReplaceWarningResponseIEValueIETableCodec]
func (IETableCodec[V]) Call(table IETable[V], bounds aper.ListBounds) ValueCodec[ProtocolIEContainer[V]] {
	if !table.bound {
		return ValueCodec[ProtocolIEContainer[V]]{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ValueCodec[ProtocolIEContainer[V]]{path: "ProtocolIEContainer", decode: func(data []byte, options aper.DecodeState) (ProtocolIEContainer[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ProtocolIEContainer[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ProtocolIEField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ProtocolIEContainer[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v ProtocolIEContainer[V], options aper.DecodeState) (ProtocolIEContainer[V], aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APProtocolIEContainer[V](&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ProtocolIEContainer[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APProtocolIEContainer[V](&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// IEFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueIEFieldTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueIEFieldTableCodec]
//   - [BearersSubjectToStatusTransferItemIEValueIEFieldTableCodec]
//   - [CellTrafficTraceIEValueIEFieldTableCodec]
//   - [ConnectionEstablishmentIndicationIEValueIEFieldTableCodec]
//   - [DAPSResponseInfoListIEValueIEFieldTableCodec]
//   - [DeactivateTraceIEValueIEFieldTableCodec]
//   - [DownlinkNASTransportIEValueIEFieldTableCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueIEFieldTableCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [ENBCPRelocationIndicationIEValueIEFieldTableCodec]
//   - [ENBConfigurationTransferIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateFailureIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateIEValueIEFieldTableCodec]
//   - [ENBDirectInformationTransferIEValueIEFieldTableCodec]
//   - [ENBEarlyStatusTransferIEValueIEFieldTableCodec]
//   - [ENBStatusTransferIEValueIEFieldTableCodec]
//   - [ERABAdmittedItemIEValueIEFieldTableCodec]
//   - [ERABDataForwardingItemIEValueIEFieldTableCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueIEFieldTableCodec]
//   - [ERABFailedToResumeItemResumeResIEValueIEFieldTableCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueIEFieldTableCodec]
//   - [ERABInformationListIEValueIEFieldTableCodec]
//   - [ERABItemIEValueIEFieldTableCodec]
//   - [ERABModificationConfirmIEValueIEFieldTableCodec]
//   - [ERABModificationIndicationIEValueIEFieldTableCodec]
//   - [ERABModifyItemBearerModConfIEValueIEFieldTableCodec]
//   - [ERABModifyItemBearerModResIEValueIEFieldTableCodec]
//   - [ERABModifyRequestIEValueIEFieldTableCodec]
//   - [ERABModifyResponseIEValueIEFieldTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueIEFieldTableCodec]
//   - [ERABReleaseCommandIEValueIEFieldTableCodec]
//   - [ERABReleaseIndicationIEValueIEFieldTableCodec]
//   - [ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec]
//   - [ERABReleaseResponseIEValueIEFieldTableCodec]
//   - [ERABSecurityResultListIEValueIEFieldTableCodec]
//   - [ERABSetupItemBearerSUResIEValueIEFieldTableCodec]
//   - [ERABSetupItemCtxtSUResIEValueIEFieldTableCodec]
//   - [ERABSetupRequestIEValueIEFieldTableCodec]
//   - [ERABSetupResponseIEValueIEFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemHOReqIEValueIEFieldTableCodec]
//   - [ERABToBeSwitchedDLItemIEValueIEFieldTableCodec]
//   - [ERABToBeSwitchedULItemIEValueIEFieldTableCodec]
//   - [ERABToBeUpdatedItemIEValueIEFieldTableCodec]
//   - [ERABUsageReportItemIEValueIEFieldTableCodec]
//   - [ErrorIndicationIEValueIEFieldTableCodec]
//   - [EventTriggerExtIEValueIEFieldTableCodec]
//   - [HandoverCancelAcknowledgeIEValueIEFieldTableCodec]
//   - [HandoverCancelIEValueIEFieldTableCodec]
//   - [HandoverCommandIEValueIEFieldTableCodec]
//   - [HandoverFailureIEValueIEFieldTableCodec]
//   - [HandoverNotifyIEValueIEFieldTableCodec]
//   - [HandoverPreparationFailureIEValueIEFieldTableCodec]
//   - [HandoverRequestAcknowledgeIEValueIEFieldTableCodec]
//   - [HandoverRequestIEValueIEFieldTableCodec]
//   - [HandoverRequiredIEValueIEFieldTableCodec]
//   - [HandoverSuccessIEValueIEFieldTableCodec]
//   - [InitialContextSetupFailureIEValueIEFieldTableCodec]
//   - [InitialContextSetupRequestIEValueIEFieldTableCodec]
//   - [InitialContextSetupResponseIEValueIEFieldTableCodec]
//   - [InitialUEMessageIEValueIEFieldTableCodec]
//   - [KillRequestIEValueIEFieldTableCodec]
//   - [KillResponseIEValueIEFieldTableCodec]
//   - [LocationReportIEValueIEFieldTableCodec]
//   - [LocationReportingControlIEValueIEFieldTableCodec]
//   - [LocationReportingFailureIndicationIEValueIEFieldTableCodec]
//   - [MDTModeExtensionIEIEValueIEFieldTableCodec]
//   - [MMECPRelocationIndicationIEValueIEFieldTableCodec]
//   - [MMEConfigurationTransferIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateFailureIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateIEValueIEFieldTableCodec]
//   - [MMEDirectInformationTransferIEValueIEFieldTableCodec]
//   - [MMEEarlyStatusTransferIEValueIEFieldTableCodec]
//   - [MMEStatusTransferIEValueIEFieldTableCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueIEFieldTableCodec]
//   - [NASDeliveryIndicationIEValueIEFieldTableCodec]
//   - [NASNonDeliveryIndicationIEValueIEFieldTableCodec]
//   - [OverloadStartIEValueIEFieldTableCodec]
//   - [OverloadStopIEValueIEFieldTableCodec]
//   - [PWSFailureIndicationIEValueIEFieldTableCodec]
//   - [PWSRestartIndicationIEValueIEFieldTableCodec]
//   - [PagingIEValueIEFieldTableCodec]
//   - [PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec]
//   - [PathSwitchRequestFailureIEValueIEFieldTableCodec]
//   - [PathSwitchRequestIEValueIEFieldTableCodec]
//   - [RecommendedCellItemIEValueIEFieldTableCodec]
//   - [RecommendedENBItemIEValueIEFieldTableCodec]
//   - [RerouteNASRequestIEValueIEFieldTableCodec]
//   - [ResetAcknowledgeIEValueIEFieldTableCodec]
//   - [ResetIEValueIEFieldTableCodec]
//   - [RetrieveUEInformationIEValueIEFieldTableCodec]
//   - [S1RemovalFailureIEValueIEFieldTableCodec]
//   - [S1RemovalRequestIEValueIEFieldTableCodec]
//   - [S1RemovalResponseIEValueIEFieldTableCodec]
//   - [S1SetupFailureIEValueIEFieldTableCodec]
//   - [S1SetupRequestIEValueIEFieldTableCodec]
//   - [S1SetupResponseIEValueIEFieldTableCodec]
//   - [SONInformationExtensionIEIEValueIEFieldTableCodec]
//   - [SecondaryRATDataUsageReportIEValueIEFieldTableCodec]
//   - [SecondaryRATDataUsageReportItemIEValueIEFieldTableCodec]
//   - [SensorNameConfigExtIEValueIEFieldTableCodec]
//   - [SourceNodeIDExtensionIEIEValueIEFieldTableCodec]
//   - [TAIItemIEValueIEFieldTableCodec]
//   - [TraceFailureIndicationIEValueIEFieldTableCodec]
//   - [TraceStartIEValueIEFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueIEFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueIEFieldTableCodec]
//   - [UECapabilityInfoIndicationIEValueIEFieldTableCodec]
//   - [UEContextModificationConfirmIEValueIEFieldTableCodec]
//   - [UEContextModificationFailureIEValueIEFieldTableCodec]
//   - [UEContextModificationIndicationIEValueIEFieldTableCodec]
//   - [UEContextModificationRequestIEValueIEFieldTableCodec]
//   - [UEContextModificationResponseIEValueIEFieldTableCodec]
//   - [UEContextReleaseCommandIEValueIEFieldTableCodec]
//   - [UEContextReleaseCompleteIEValueIEFieldTableCodec]
//   - [UEContextReleaseRequestIEValueIEFieldTableCodec]
//   - [UEContextResumeFailureIEValueIEFieldTableCodec]
//   - [UEContextResumeRequestIEValueIEFieldTableCodec]
//   - [UEContextResumeResponseIEValueIEFieldTableCodec]
//   - [UEContextSuspendRequestIEValueIEFieldTableCodec]
//   - [UEContextSuspendResponseIEValueIEFieldTableCodec]
//   - [UEInformationTransferIEValueIEFieldTableCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec]
//   - [UERadioCapabilityMatchRequestIEValueIEFieldTableCodec]
//   - [UERadioCapabilityMatchResponseIEValueIEFieldTableCodec]
//   - [UplinkNASTransportIEValueIEFieldTableCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [WriteReplaceWarningRequestIEValueIEFieldTableCodec]
//   - [WriteReplaceWarningResponseIEValueIEFieldTableCodec]
type IEFieldTableCodec[V ProtocolOpenValueConstraint[V]] struct{}

// IEFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueIEFieldTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueIEFieldTableCodec]
//   - [BearersSubjectToStatusTransferItemIEValueIEFieldTableCodec]
//   - [CellTrafficTraceIEValueIEFieldTableCodec]
//   - [ConnectionEstablishmentIndicationIEValueIEFieldTableCodec]
//   - [DAPSResponseInfoListIEValueIEFieldTableCodec]
//   - [DeactivateTraceIEValueIEFieldTableCodec]
//   - [DownlinkNASTransportIEValueIEFieldTableCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueIEFieldTableCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [ENBCPRelocationIndicationIEValueIEFieldTableCodec]
//   - [ENBConfigurationTransferIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateFailureIEValueIEFieldTableCodec]
//   - [ENBConfigurationUpdateIEValueIEFieldTableCodec]
//   - [ENBDirectInformationTransferIEValueIEFieldTableCodec]
//   - [ENBEarlyStatusTransferIEValueIEFieldTableCodec]
//   - [ENBStatusTransferIEValueIEFieldTableCodec]
//   - [ERABAdmittedItemIEValueIEFieldTableCodec]
//   - [ERABDataForwardingItemIEValueIEFieldTableCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueIEFieldTableCodec]
//   - [ERABFailedToResumeItemResumeResIEValueIEFieldTableCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueIEFieldTableCodec]
//   - [ERABInformationListIEValueIEFieldTableCodec]
//   - [ERABItemIEValueIEFieldTableCodec]
//   - [ERABModificationConfirmIEValueIEFieldTableCodec]
//   - [ERABModificationIndicationIEValueIEFieldTableCodec]
//   - [ERABModifyItemBearerModConfIEValueIEFieldTableCodec]
//   - [ERABModifyItemBearerModResIEValueIEFieldTableCodec]
//   - [ERABModifyRequestIEValueIEFieldTableCodec]
//   - [ERABModifyResponseIEValueIEFieldTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueIEFieldTableCodec]
//   - [ERABReleaseCommandIEValueIEFieldTableCodec]
//   - [ERABReleaseIndicationIEValueIEFieldTableCodec]
//   - [ERABReleaseItemBearerRelCompIEValueIEFieldTableCodec]
//   - [ERABReleaseResponseIEValueIEFieldTableCodec]
//   - [ERABSecurityResultListIEValueIEFieldTableCodec]
//   - [ERABSetupItemBearerSUResIEValueIEFieldTableCodec]
//   - [ERABSetupItemCtxtSUResIEValueIEFieldTableCodec]
//   - [ERABSetupRequestIEValueIEFieldTableCodec]
//   - [ERABSetupResponseIEValueIEFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueIEFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueIEFieldTableCodec]
//   - [ERABToBeSetupItemHOReqIEValueIEFieldTableCodec]
//   - [ERABToBeSwitchedDLItemIEValueIEFieldTableCodec]
//   - [ERABToBeSwitchedULItemIEValueIEFieldTableCodec]
//   - [ERABToBeUpdatedItemIEValueIEFieldTableCodec]
//   - [ERABUsageReportItemIEValueIEFieldTableCodec]
//   - [ErrorIndicationIEValueIEFieldTableCodec]
//   - [EventTriggerExtIEValueIEFieldTableCodec]
//   - [HandoverCancelAcknowledgeIEValueIEFieldTableCodec]
//   - [HandoverCancelIEValueIEFieldTableCodec]
//   - [HandoverCommandIEValueIEFieldTableCodec]
//   - [HandoverFailureIEValueIEFieldTableCodec]
//   - [HandoverNotifyIEValueIEFieldTableCodec]
//   - [HandoverPreparationFailureIEValueIEFieldTableCodec]
//   - [HandoverRequestAcknowledgeIEValueIEFieldTableCodec]
//   - [HandoverRequestIEValueIEFieldTableCodec]
//   - [HandoverRequiredIEValueIEFieldTableCodec]
//   - [HandoverSuccessIEValueIEFieldTableCodec]
//   - [InitialContextSetupFailureIEValueIEFieldTableCodec]
//   - [InitialContextSetupRequestIEValueIEFieldTableCodec]
//   - [InitialContextSetupResponseIEValueIEFieldTableCodec]
//   - [InitialUEMessageIEValueIEFieldTableCodec]
//   - [KillRequestIEValueIEFieldTableCodec]
//   - [KillResponseIEValueIEFieldTableCodec]
//   - [LocationReportIEValueIEFieldTableCodec]
//   - [LocationReportingControlIEValueIEFieldTableCodec]
//   - [LocationReportingFailureIndicationIEValueIEFieldTableCodec]
//   - [MDTModeExtensionIEIEValueIEFieldTableCodec]
//   - [MMECPRelocationIndicationIEValueIEFieldTableCodec]
//   - [MMEConfigurationTransferIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateFailureIEValueIEFieldTableCodec]
//   - [MMEConfigurationUpdateIEValueIEFieldTableCodec]
//   - [MMEDirectInformationTransferIEValueIEFieldTableCodec]
//   - [MMEEarlyStatusTransferIEValueIEFieldTableCodec]
//   - [MMEStatusTransferIEValueIEFieldTableCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueIEFieldTableCodec]
//   - [NASDeliveryIndicationIEValueIEFieldTableCodec]
//   - [NASNonDeliveryIndicationIEValueIEFieldTableCodec]
//   - [OverloadStartIEValueIEFieldTableCodec]
//   - [OverloadStopIEValueIEFieldTableCodec]
//   - [PWSFailureIndicationIEValueIEFieldTableCodec]
//   - [PWSRestartIndicationIEValueIEFieldTableCodec]
//   - [PagingIEValueIEFieldTableCodec]
//   - [PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec]
//   - [PathSwitchRequestFailureIEValueIEFieldTableCodec]
//   - [PathSwitchRequestIEValueIEFieldTableCodec]
//   - [RecommendedCellItemIEValueIEFieldTableCodec]
//   - [RecommendedENBItemIEValueIEFieldTableCodec]
//   - [RerouteNASRequestIEValueIEFieldTableCodec]
//   - [ResetAcknowledgeIEValueIEFieldTableCodec]
//   - [ResetIEValueIEFieldTableCodec]
//   - [RetrieveUEInformationIEValueIEFieldTableCodec]
//   - [S1RemovalFailureIEValueIEFieldTableCodec]
//   - [S1RemovalRequestIEValueIEFieldTableCodec]
//   - [S1RemovalResponseIEValueIEFieldTableCodec]
//   - [S1SetupFailureIEValueIEFieldTableCodec]
//   - [S1SetupRequestIEValueIEFieldTableCodec]
//   - [S1SetupResponseIEValueIEFieldTableCodec]
//   - [SONInformationExtensionIEIEValueIEFieldTableCodec]
//   - [SecondaryRATDataUsageReportIEValueIEFieldTableCodec]
//   - [SecondaryRATDataUsageReportItemIEValueIEFieldTableCodec]
//   - [SensorNameConfigExtIEValueIEFieldTableCodec]
//   - [SourceNodeIDExtensionIEIEValueIEFieldTableCodec]
//   - [TAIItemIEValueIEFieldTableCodec]
//   - [TraceFailureIndicationIEValueIEFieldTableCodec]
//   - [TraceStartIEValueIEFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueIEFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueIEFieldTableCodec]
//   - [UECapabilityInfoIndicationIEValueIEFieldTableCodec]
//   - [UEContextModificationConfirmIEValueIEFieldTableCodec]
//   - [UEContextModificationFailureIEValueIEFieldTableCodec]
//   - [UEContextModificationIndicationIEValueIEFieldTableCodec]
//   - [UEContextModificationRequestIEValueIEFieldTableCodec]
//   - [UEContextModificationResponseIEValueIEFieldTableCodec]
//   - [UEContextReleaseCommandIEValueIEFieldTableCodec]
//   - [UEContextReleaseCompleteIEValueIEFieldTableCodec]
//   - [UEContextReleaseRequestIEValueIEFieldTableCodec]
//   - [UEContextResumeFailureIEValueIEFieldTableCodec]
//   - [UEContextResumeRequestIEValueIEFieldTableCodec]
//   - [UEContextResumeResponseIEValueIEFieldTableCodec]
//   - [UEContextSuspendRequestIEValueIEFieldTableCodec]
//   - [UEContextSuspendResponseIEValueIEFieldTableCodec]
//   - [UEInformationTransferIEValueIEFieldTableCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec]
//   - [UERadioCapabilityMatchRequestIEValueIEFieldTableCodec]
//   - [UERadioCapabilityMatchResponseIEValueIEFieldTableCodec]
//   - [UplinkNASTransportIEValueIEFieldTableCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec]
//   - [WriteReplaceWarningRequestIEValueIEFieldTableCodec]
//   - [WriteReplaceWarningResponseIEValueIEFieldTableCodec]
func (IEFieldTableCodec[V]) Call(table IETable[V]) ValueCodec[ProtocolIEField[V]] {
	if !table.bound {
		return ValueCodec[ProtocolIEField[V]]{}
	}
	return ValueCodec[ProtocolIEField[V]]{path: "ProtocolIEField", decode: func(data []byte, options aper.DecodeState) (ProtocolIEField[V], error) {
		var field ProtocolIEField[V]
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ProtocolIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ProtocolIEField")
		}
		return field, nil
	}, encode: func(field ProtocolIEField[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ProtocolIEField[V], options aper.DecodeState) (ProtocolIEField[V], aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APProtocolIEField[V](&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ProtocolIEField[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APProtocolIEField[V](&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

type ExtensionTable[V ProtocolOpenValueConstraint[V]] struct{ bound bool }

// ExtensionTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [AdditionalGUTIExtIEsValueExtensionTableCodec]
//   - [AllocationAndRetentionPriorityExtIEsValueExtensionTableCodec]
//   - [AssistanceDataForPagingExtIEsValueExtensionTableCodec]
//   - [AssistanceDataForRecommendedCellsExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToDLDiscardingItemExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToStatusTransferItemExtIEsValueExtensionTableCodec]
//   - [BluetoothMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [CGIExtIEsValueExtensionTableCodec]
//   - [CNTypeRestrictionsItemExtIEsValueExtensionTableCodec]
//   - [COUNTValueExtendedExtIEsValueExtensionTableCodec]
//   - [COUNTvalueExtIEsValueExtensionTableCodec]
//   - [COUNTvaluePDCPSNlength18ExtIEsValueExtensionTableCodec]
//   - [CSGIdListItemExtIEsValueExtensionTableCodec]
//   - [CSGMembershipInfoExtIEsValueExtensionTableCodec]
//   - [CancelledCellinEAIItemExtIEsValueExtensionTableCodec]
//   - [CancelledCellinTAIItemExtIEsValueExtensionTableCodec]
//   - [Cdma2000OneXSRVCCInfoExtIEsValueExtensionTableCodec]
//   - [CellBasedMDTExtIEsValueExtensionTableCodec]
//   - [CellBasedQMCExtIEsValueExtensionTableCodec]
//   - [CellIDBroadcastItemExtIEsValueExtensionTableCodec]
//   - [CellIDCancelledItemExtIEsValueExtensionTableCodec]
//   - [CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableCodec]
//   - [CellTypeExtIEsValueExtensionTableCodec]
//   - [CompletedCellinEAIItemExtIEsValueExtensionTableCodec]
//   - [CompletedCellinTAIItemExtIEsValueExtensionTableCodec]
//   - [ConnectedengNBItemExtIEsValueExtensionTableCodec]
//   - [ContextatSourceExtIEsValueExtensionTableCodec]
//   - [CriticalityDiagnosticsExtIEsValueExtensionTableCodec]
//   - [CriticalityDiagnosticsIEItemExtIEsValueExtensionTableCodec]
//   - [DAPSRequestInfoExtIEsValueExtensionTableCodec]
//   - [DAPSResponseInfoExtIEsValueExtensionTableCodec]
//   - [DAPSResponseInfoItemExtIEsValueExtensionTableCodec]
//   - [DLCPSecurityInformationExtIEsValueExtensionTableCodec]
//   - [ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec]
//   - [ENBStatusTransferTransparentContainerExtIEsValueExtensionTableCodec]
//   - [ENBX2ExtTLAExtIEsValueExtensionTableCodec]
//   - [ENDCSONConfigurationTransferExtIEsValueExtensionTableCodec]
//   - [ENDCSONeNBIdentificationExtIEsValueExtensionTableCodec]
//   - [ENDCSONengNBIdentificationExtIEsValueExtensionTableCodec]
//   - [ENDCTransferTypeReplyExtIEsValueExtensionTableCodec]
//   - [ENDCTransferTypeRequestExtIEsValueExtensionTableCodec]
//   - [ERABAdmittedItemExtIEsValueExtensionTableCodec]
//   - [ERABDataForwardingItemExtIEsValueExtensionTableCodec]
//   - [ERABFailedToResumeItemResumeReqExtIEsValueExtensionTableCodec]
//   - [ERABFailedToResumeItemResumeResExtIEsValueExtensionTableCodec]
//   - [ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableCodec]
//   - [ERABInformationListItemExtIEsValueExtensionTableCodec]
//   - [ERABItemExtIEsValueExtensionTableCodec]
//   - [ERABModifyItemBearerModConfExtIEsValueExtensionTableCodec]
//   - [ERABModifyItemBearerModResExtIEsValueExtensionTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec]
//   - [ERABQoSParametersExtIEsValueExtensionTableCodec]
//   - [ERABReleaseItemBearerRelCompExtIEsValueExtensionTableCodec]
//   - [ERABSecurityResultItemExtIEsValueExtensionTableCodec]
//   - [ERABSetupItemBearerSUResExtIEsValueExtensionTableCodec]
//   - [ERABSetupItemCtxtSUResExtIEsValueExtensionTableCodec]
//   - [ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec]
//   - [ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemHOReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSwitchedDLItemExtIEsValueExtensionTableCodec]
//   - [ERABToBeSwitchedULItemExtIEsValueExtensionTableCodec]
//   - [ERABToBeUpdatedItemExtIEsValueExtensionTableCodec]
//   - [ERABUsageReportItemExtIEsValueExtensionTableCodec]
//   - [EUTRANCGIExtIEsValueExtensionTableCodec]
//   - [EmergencyAreaIDBroadcastItemExtIEsValueExtensionTableCodec]
//   - [EmergencyAreaIDCancelledItemExtIEsValueExtensionTableCodec]
//   - [EventL1LoggedMDTConfigExtIEsValueExtensionTableCodec]
//   - [ExpectedUEActivityBehaviourExtIEsValueExtensionTableCodec]
//   - [ExpectedUEBehaviourExtIEsValueExtensionTableCodec]
//   - [FiveGSTAIExtIEsValueExtensionTableCodec]
//   - [ForbiddenLAsItemExtIEsValueExtensionTableCodec]
//   - [ForbiddenTAsItemExtIEsValueExtensionTableCodec]
//   - [GBRQosInformationExtIEsValueExtensionTableCodec]
//   - [GERANCellIDExtIEsValueExtensionTableCodec]
//   - [GNBExtIEsValueExtensionTableCodec]
//   - [GUMMEIExtIEsValueExtensionTableCodec]
//   - [GlobalENBIDExtIEsValueExtensionTableCodec]
//   - [GlobalEnGNBIDExtIEsValueExtensionTableCodec]
//   - [GlobalGNBIDExtIEsValueExtensionTableCodec]
//   - [HandoverRestrictionListExtIEsValueExtensionTableCodec]
//   - [ImmediateMDTExtIEsValueExtensionTableCodec]
//   - [InformationForCECapableUEsExtIEsValueExtensionTableCodec]
//   - [InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableCodec]
//   - [InterSystemMeasurementItemExtIEsValueExtensionTableCodec]
//   - [InterSystemMeasurementParametersExtIEsValueExtensionTableCodec]
//   - [IntersystemMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [LAIExtIEsValueExtensionTableCodec]
//   - [LTENTNTAIInformationExtIEsValueExtensionTableCodec]
//   - [LastVisitedEUTRANCellInformationExtIEsValueExtensionTableCodec]
//   - [LastVisitedPSCellInformationExtIEsValueExtensionTableCodec]
//   - [ListeningSubframePatternExtIEsValueExtensionTableCodec]
//   - [LoggedMBSFNMDTExtIEsValueExtensionTableCodec]
//   - [LoggedMDTExtIEsValueExtensionTableCodec]
//   - [M1PeriodicReportingExtIEsValueExtensionTableCodec]
//   - [M1ThresholdEventA2ExtIEsValueExtensionTableCodec]
//   - [M3ConfigurationExtIEsValueExtensionTableCodec]
//   - [M4ConfigurationExtIEsValueExtensionTableCodec]
//   - [M5ConfigurationExtIEsValueExtensionTableCodec]
//   - [M6ConfigurationExtIEsValueExtensionTableCodec]
//   - [M7ConfigurationExtIEsValueExtensionTableCodec]
//   - [MBSFNResultToLogInfoExtIEsValueExtensionTableCodec]
//   - [MDTConfigurationExtIEsValueExtensionTableCodec]
//   - [MutingPatternInformationExtIEsValueExtensionTableCodec]
//   - [NBIoTPagingEDRXInformationExtIEsValueExtensionTableCodec]
//   - [NGENBExtIEsValueExtensionTableCodec]
//   - [NRCGIExtIEsValueExtensionTableCodec]
//   - [NRUESecurityCapabilitiesExtIEsValueExtensionTableCodec]
//   - [NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableCodec]
//   - [NRV2XServicesAuthorizedExtIEsValueExtensionTableCodec]
//   - [PC5FlowBitRatesExtIEsValueExtensionTableCodec]
//   - [PC5QoSFlowItemExtIEsValueExtensionTableCodec]
//   - [PC5QoSParametersExtIEsValueExtensionTableCodec]
//   - [PLMNAreaBasedQMCExtIEsValueExtensionTableCodec]
//   - [PSCellInformationExtIEsValueExtensionTableCodec]
//   - [PagingAttemptInformationExtIEsValueExtensionTableCodec]
//   - [PagingEDRXInformationExtIEsValueExtensionTableCodec]
//   - [ProSeAuthorizedExtIEsValueExtensionTableCodec]
//   - [RATRestrictionsItemExtIEsValueExtensionTableCodec]
//   - [RIMTransferExtIEsValueExtensionTableCodec]
//   - [RLFReportInformationExtIEsValueExtensionTableCodec]
//   - [RecommendedCellsForPagingExtIEsValueExtensionTableCodec]
//   - [RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec]
//   - [RecommendedENBItemExtIEsValueExtensionTableCodec]
//   - [RecommendedENBsForPagingExtIEsValueExtensionTableCodec]
//   - [RequestTypeExtIEsValueExtensionTableCodec]
//   - [RequestedTNLInfoExtIEsValueExtensionTableCodec]
//   - [SONConfigurationTransferExtIEsValueExtensionTableCodec]
//   - [SONInformationReplyExtIEsValueExtensionTableCodec]
//   - [STMSIExtIEsValueExtensionTableCodec]
//   - [ScheduledCommunicationTimeExtIEsValueExtensionTableCodec]
//   - [SecondaryRATDataUsageReportItemExtIEsValueExtensionTableCodec]
//   - [SecurityContextExtIEsValueExtensionTableCodec]
//   - [SecurityIndicationExtIEsValueExtensionTableCodec]
//   - [SecurityResultExtIEsValueExtensionTableCodec]
//   - [SensorMeasConfigNameItemExtIEsValueExtensionTableCodec]
//   - [SensorMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [ServedDCNsItemExtIEsValueExtensionTableCodec]
//   - [ServedGUMMEIsItemExtIEsValueExtensionTableCodec]
//   - [SourceNgRanNodeIDExtIEsValueExtensionTableCodec]
//   - [SourceeNBIDExtIEsValueExtensionTableCodec]
//   - [SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableCodec]
//   - [SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec]
//   - [SupportedTAsItemExtIEsValueExtensionTableCodec]
//   - [SynchronisationInformationExtIEsValueExtensionTableCodec]
//   - [TABasedMDTExtIEsValueExtensionTableCodec]
//   - [TABasedQMCExtIEsValueExtensionTableCodec]
//   - [TAIBasedMDTExtIEsValueExtensionTableCodec]
//   - [TAIBasedQMCExtIEsValueExtensionTableCodec]
//   - [TAIBroadcastItemExtIEsValueExtensionTableCodec]
//   - [TAICancelledItemExtIEsValueExtensionTableCodec]
//   - [TAIExtIEsValueExtensionTableCodec]
//   - [TAIItemExtIEsValueExtensionTableCodec]
//   - [TargetNgRanNodeIDExtIEsValueExtensionTableCodec]
//   - [TargetRNCIDExtIEsValueExtensionTableCodec]
//   - [TargeteNBIDExtIEsValueExtensionTableCodec]
//   - [TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableCodec]
//   - [TimeBasedHandoverInformationExtIEsValueExtensionTableCodec]
//   - [TimeSynchronisationInfoExtIEsValueExtensionTableCodec]
//   - [TraceActivationExtIEsValueExtensionTableCodec]
//   - [TunnelInformationExtIEsValueExtensionTableCodec]
//   - [UEAggregateMaximumBitratesExtIEsValueExtensionTableCodec]
//   - [UEAppLayerMeasConfigExtIEsValueExtensionTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableCodec]
//   - [UES1APIDPairExtIEsValueExtensionTableCodec]
//   - [UESecurityCapabilitiesExtIEsValueExtensionTableCodec]
//   - [UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec]
//   - [ULCPSecurityInformationExtIEsValueExtensionTableCodec]
//   - [UserLocationInformationExtIEsValueExtensionTableCodec]
//   - [V2XServicesAuthorizedExtIEsValueExtensionTableCodec]
//   - [WLANMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [WUSAssistanceInformationExtIEsValueExtensionTableCodec]
//   - [X2TNLConfigurationInfoExtIEsValueExtensionTableCodec]
type ExtensionTableCodec[V ProtocolOpenValueConstraint[V]] struct{}

// ExtensionTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [AdditionalGUTIExtIEsValueExtensionTableCodec]
//   - [AllocationAndRetentionPriorityExtIEsValueExtensionTableCodec]
//   - [AssistanceDataForPagingExtIEsValueExtensionTableCodec]
//   - [AssistanceDataForRecommendedCellsExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToDLDiscardingItemExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableCodec]
//   - [BearersSubjectToStatusTransferItemExtIEsValueExtensionTableCodec]
//   - [BluetoothMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [CGIExtIEsValueExtensionTableCodec]
//   - [CNTypeRestrictionsItemExtIEsValueExtensionTableCodec]
//   - [COUNTValueExtendedExtIEsValueExtensionTableCodec]
//   - [COUNTvalueExtIEsValueExtensionTableCodec]
//   - [COUNTvaluePDCPSNlength18ExtIEsValueExtensionTableCodec]
//   - [CSGIdListItemExtIEsValueExtensionTableCodec]
//   - [CSGMembershipInfoExtIEsValueExtensionTableCodec]
//   - [CancelledCellinEAIItemExtIEsValueExtensionTableCodec]
//   - [CancelledCellinTAIItemExtIEsValueExtensionTableCodec]
//   - [Cdma2000OneXSRVCCInfoExtIEsValueExtensionTableCodec]
//   - [CellBasedMDTExtIEsValueExtensionTableCodec]
//   - [CellBasedQMCExtIEsValueExtensionTableCodec]
//   - [CellIDBroadcastItemExtIEsValueExtensionTableCodec]
//   - [CellIDCancelledItemExtIEsValueExtensionTableCodec]
//   - [CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableCodec]
//   - [CellTypeExtIEsValueExtensionTableCodec]
//   - [CompletedCellinEAIItemExtIEsValueExtensionTableCodec]
//   - [CompletedCellinTAIItemExtIEsValueExtensionTableCodec]
//   - [ConnectedengNBItemExtIEsValueExtensionTableCodec]
//   - [ContextatSourceExtIEsValueExtensionTableCodec]
//   - [CriticalityDiagnosticsExtIEsValueExtensionTableCodec]
//   - [CriticalityDiagnosticsIEItemExtIEsValueExtensionTableCodec]
//   - [DAPSRequestInfoExtIEsValueExtensionTableCodec]
//   - [DAPSResponseInfoExtIEsValueExtensionTableCodec]
//   - [DAPSResponseInfoItemExtIEsValueExtensionTableCodec]
//   - [DLCPSecurityInformationExtIEsValueExtensionTableCodec]
//   - [ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec]
//   - [ENBStatusTransferTransparentContainerExtIEsValueExtensionTableCodec]
//   - [ENBX2ExtTLAExtIEsValueExtensionTableCodec]
//   - [ENDCSONConfigurationTransferExtIEsValueExtensionTableCodec]
//   - [ENDCSONeNBIdentificationExtIEsValueExtensionTableCodec]
//   - [ENDCSONengNBIdentificationExtIEsValueExtensionTableCodec]
//   - [ENDCTransferTypeReplyExtIEsValueExtensionTableCodec]
//   - [ENDCTransferTypeRequestExtIEsValueExtensionTableCodec]
//   - [ERABAdmittedItemExtIEsValueExtensionTableCodec]
//   - [ERABDataForwardingItemExtIEsValueExtensionTableCodec]
//   - [ERABFailedToResumeItemResumeReqExtIEsValueExtensionTableCodec]
//   - [ERABFailedToResumeItemResumeResExtIEsValueExtensionTableCodec]
//   - [ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableCodec]
//   - [ERABInformationListItemExtIEsValueExtensionTableCodec]
//   - [ERABItemExtIEsValueExtensionTableCodec]
//   - [ERABModifyItemBearerModConfExtIEsValueExtensionTableCodec]
//   - [ERABModifyItemBearerModResExtIEsValueExtensionTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec]
//   - [ERABQoSParametersExtIEsValueExtensionTableCodec]
//   - [ERABReleaseItemBearerRelCompExtIEsValueExtensionTableCodec]
//   - [ERABSecurityResultItemExtIEsValueExtensionTableCodec]
//   - [ERABSetupItemBearerSUResExtIEsValueExtensionTableCodec]
//   - [ERABSetupItemCtxtSUResExtIEsValueExtensionTableCodec]
//   - [ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec]
//   - [ERABToBeModifyItemBearerModReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemBearerSUReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSetupItemHOReqExtIEsValueExtensionTableCodec]
//   - [ERABToBeSwitchedDLItemExtIEsValueExtensionTableCodec]
//   - [ERABToBeSwitchedULItemExtIEsValueExtensionTableCodec]
//   - [ERABToBeUpdatedItemExtIEsValueExtensionTableCodec]
//   - [ERABUsageReportItemExtIEsValueExtensionTableCodec]
//   - [EUTRANCGIExtIEsValueExtensionTableCodec]
//   - [EmergencyAreaIDBroadcastItemExtIEsValueExtensionTableCodec]
//   - [EmergencyAreaIDCancelledItemExtIEsValueExtensionTableCodec]
//   - [EventL1LoggedMDTConfigExtIEsValueExtensionTableCodec]
//   - [ExpectedUEActivityBehaviourExtIEsValueExtensionTableCodec]
//   - [ExpectedUEBehaviourExtIEsValueExtensionTableCodec]
//   - [FiveGSTAIExtIEsValueExtensionTableCodec]
//   - [ForbiddenLAsItemExtIEsValueExtensionTableCodec]
//   - [ForbiddenTAsItemExtIEsValueExtensionTableCodec]
//   - [GBRQosInformationExtIEsValueExtensionTableCodec]
//   - [GERANCellIDExtIEsValueExtensionTableCodec]
//   - [GNBExtIEsValueExtensionTableCodec]
//   - [GUMMEIExtIEsValueExtensionTableCodec]
//   - [GlobalENBIDExtIEsValueExtensionTableCodec]
//   - [GlobalEnGNBIDExtIEsValueExtensionTableCodec]
//   - [GlobalGNBIDExtIEsValueExtensionTableCodec]
//   - [HandoverRestrictionListExtIEsValueExtensionTableCodec]
//   - [ImmediateMDTExtIEsValueExtensionTableCodec]
//   - [InformationForCECapableUEsExtIEsValueExtensionTableCodec]
//   - [InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableCodec]
//   - [InterSystemMeasurementItemExtIEsValueExtensionTableCodec]
//   - [InterSystemMeasurementParametersExtIEsValueExtensionTableCodec]
//   - [IntersystemMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [LAIExtIEsValueExtensionTableCodec]
//   - [LTENTNTAIInformationExtIEsValueExtensionTableCodec]
//   - [LastVisitedEUTRANCellInformationExtIEsValueExtensionTableCodec]
//   - [LastVisitedPSCellInformationExtIEsValueExtensionTableCodec]
//   - [ListeningSubframePatternExtIEsValueExtensionTableCodec]
//   - [LoggedMBSFNMDTExtIEsValueExtensionTableCodec]
//   - [LoggedMDTExtIEsValueExtensionTableCodec]
//   - [M1PeriodicReportingExtIEsValueExtensionTableCodec]
//   - [M1ThresholdEventA2ExtIEsValueExtensionTableCodec]
//   - [M3ConfigurationExtIEsValueExtensionTableCodec]
//   - [M4ConfigurationExtIEsValueExtensionTableCodec]
//   - [M5ConfigurationExtIEsValueExtensionTableCodec]
//   - [M6ConfigurationExtIEsValueExtensionTableCodec]
//   - [M7ConfigurationExtIEsValueExtensionTableCodec]
//   - [MBSFNResultToLogInfoExtIEsValueExtensionTableCodec]
//   - [MDTConfigurationExtIEsValueExtensionTableCodec]
//   - [MutingPatternInformationExtIEsValueExtensionTableCodec]
//   - [NBIoTPagingEDRXInformationExtIEsValueExtensionTableCodec]
//   - [NGENBExtIEsValueExtensionTableCodec]
//   - [NRCGIExtIEsValueExtensionTableCodec]
//   - [NRUESecurityCapabilitiesExtIEsValueExtensionTableCodec]
//   - [NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableCodec]
//   - [NRV2XServicesAuthorizedExtIEsValueExtensionTableCodec]
//   - [PC5FlowBitRatesExtIEsValueExtensionTableCodec]
//   - [PC5QoSFlowItemExtIEsValueExtensionTableCodec]
//   - [PC5QoSParametersExtIEsValueExtensionTableCodec]
//   - [PLMNAreaBasedQMCExtIEsValueExtensionTableCodec]
//   - [PSCellInformationExtIEsValueExtensionTableCodec]
//   - [PagingAttemptInformationExtIEsValueExtensionTableCodec]
//   - [PagingEDRXInformationExtIEsValueExtensionTableCodec]
//   - [ProSeAuthorizedExtIEsValueExtensionTableCodec]
//   - [RATRestrictionsItemExtIEsValueExtensionTableCodec]
//   - [RIMTransferExtIEsValueExtensionTableCodec]
//   - [RLFReportInformationExtIEsValueExtensionTableCodec]
//   - [RecommendedCellsForPagingExtIEsValueExtensionTableCodec]
//   - [RecommendedCellsForPagingItemExtIEsValueExtensionTableCodec]
//   - [RecommendedENBItemExtIEsValueExtensionTableCodec]
//   - [RecommendedENBsForPagingExtIEsValueExtensionTableCodec]
//   - [RequestTypeExtIEsValueExtensionTableCodec]
//   - [RequestedTNLInfoExtIEsValueExtensionTableCodec]
//   - [SONConfigurationTransferExtIEsValueExtensionTableCodec]
//   - [SONInformationReplyExtIEsValueExtensionTableCodec]
//   - [STMSIExtIEsValueExtensionTableCodec]
//   - [ScheduledCommunicationTimeExtIEsValueExtensionTableCodec]
//   - [SecondaryRATDataUsageReportItemExtIEsValueExtensionTableCodec]
//   - [SecurityContextExtIEsValueExtensionTableCodec]
//   - [SecurityIndicationExtIEsValueExtensionTableCodec]
//   - [SecurityResultExtIEsValueExtensionTableCodec]
//   - [SensorMeasConfigNameItemExtIEsValueExtensionTableCodec]
//   - [SensorMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [ServedDCNsItemExtIEsValueExtensionTableCodec]
//   - [ServedGUMMEIsItemExtIEsValueExtensionTableCodec]
//   - [SourceNgRanNodeIDExtIEsValueExtensionTableCodec]
//   - [SourceeNBIDExtIEsValueExtensionTableCodec]
//   - [SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableCodec]
//   - [SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionTableCodec]
//   - [SupportedTAsItemExtIEsValueExtensionTableCodec]
//   - [SynchronisationInformationExtIEsValueExtensionTableCodec]
//   - [TABasedMDTExtIEsValueExtensionTableCodec]
//   - [TABasedQMCExtIEsValueExtensionTableCodec]
//   - [TAIBasedMDTExtIEsValueExtensionTableCodec]
//   - [TAIBasedQMCExtIEsValueExtensionTableCodec]
//   - [TAIBroadcastItemExtIEsValueExtensionTableCodec]
//   - [TAICancelledItemExtIEsValueExtensionTableCodec]
//   - [TAIExtIEsValueExtensionTableCodec]
//   - [TAIItemExtIEsValueExtensionTableCodec]
//   - [TargetNgRanNodeIDExtIEsValueExtensionTableCodec]
//   - [TargetRNCIDExtIEsValueExtensionTableCodec]
//   - [TargeteNBIDExtIEsValueExtensionTableCodec]
//   - [TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionTableCodec]
//   - [TimeBasedHandoverInformationExtIEsValueExtensionTableCodec]
//   - [TimeSynchronisationInfoExtIEsValueExtensionTableCodec]
//   - [TraceActivationExtIEsValueExtensionTableCodec]
//   - [TunnelInformationExtIEsValueExtensionTableCodec]
//   - [UEAggregateMaximumBitratesExtIEsValueExtensionTableCodec]
//   - [UEAppLayerMeasConfigExtIEsValueExtensionTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableCodec]
//   - [UES1APIDPairExtIEsValueExtensionTableCodec]
//   - [UESecurityCapabilitiesExtIEsValueExtensionTableCodec]
//   - [UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec]
//   - [ULCPSecurityInformationExtIEsValueExtensionTableCodec]
//   - [UserLocationInformationExtIEsValueExtensionTableCodec]
//   - [V2XServicesAuthorizedExtIEsValueExtensionTableCodec]
//   - [WLANMeasurementConfigurationExtIEsValueExtensionTableCodec]
//   - [WUSAssistanceInformationExtIEsValueExtensionTableCodec]
//   - [X2TNLConfigurationInfoExtIEsValueExtensionTableCodec]
func (ExtensionTableCodec[V]) Call(table ExtensionTable[V], bounds aper.ListBounds) ValueCodec[ProtocolExtensionContainer[V]] {
	if !table.bound {
		return ValueCodec[ProtocolExtensionContainer[V]]{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ValueCodec[ProtocolExtensionContainer[V]]{path: "ProtocolExtensionContainer", decode: func(data []byte, options aper.DecodeState) (ProtocolExtensionContainer[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ProtocolExtensionContainer[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ProtocolExtensionField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
		}
		return fields, nil
	},
		encode: func(fields ProtocolExtensionContainer[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v ProtocolExtensionContainer[V], options aper.DecodeState) (ProtocolExtensionContainer[V], aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APProtocolExtensionContainer[V](&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ProtocolExtensionContainer[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APProtocolExtensionContainer[V](&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// ExtensionFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [AdditionalGUTIExtIEsValueExtensionFieldTableCodec]
//   - [AllocationAndRetentionPriorityExtIEsValueExtensionFieldTableCodec]
//   - [AssistanceDataForPagingExtIEsValueExtensionFieldTableCodec]
//   - [AssistanceDataForRecommendedCellsExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToDLDiscardingItemExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToStatusTransferItemExtIEsValueExtensionFieldTableCodec]
//   - [BluetoothMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [CGIExtIEsValueExtensionFieldTableCodec]
//   - [CNTypeRestrictionsItemExtIEsValueExtensionFieldTableCodec]
//   - [COUNTValueExtendedExtIEsValueExtensionFieldTableCodec]
//   - [COUNTvalueExtIEsValueExtensionFieldTableCodec]
//   - [COUNTvaluePDCPSNlength18ExtIEsValueExtensionFieldTableCodec]
//   - [CSGIdListItemExtIEsValueExtensionFieldTableCodec]
//   - [CSGMembershipInfoExtIEsValueExtensionFieldTableCodec]
//   - [CancelledCellinEAIItemExtIEsValueExtensionFieldTableCodec]
//   - [CancelledCellinTAIItemExtIEsValueExtensionFieldTableCodec]
//   - [Cdma2000OneXSRVCCInfoExtIEsValueExtensionFieldTableCodec]
//   - [CellBasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [CellBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [CellIDBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [CellIDCancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionFieldTableCodec]
//   - [CellTypeExtIEsValueExtensionFieldTableCodec]
//   - [CompletedCellinEAIItemExtIEsValueExtensionFieldTableCodec]
//   - [CompletedCellinTAIItemExtIEsValueExtensionFieldTableCodec]
//   - [ConnectedengNBItemExtIEsValueExtensionFieldTableCodec]
//   - [ContextatSourceExtIEsValueExtensionFieldTableCodec]
//   - [CriticalityDiagnosticsExtIEsValueExtensionFieldTableCodec]
//   - [CriticalityDiagnosticsIEItemExtIEsValueExtensionFieldTableCodec]
//   - [DAPSRequestInfoExtIEsValueExtensionFieldTableCodec]
//   - [DAPSResponseInfoExtIEsValueExtensionFieldTableCodec]
//   - [DAPSResponseInfoItemExtIEsValueExtensionFieldTableCodec]
//   - [DLCPSecurityInformationExtIEsValueExtensionFieldTableCodec]
//   - [ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [ENBStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [ENBX2ExtTLAExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONConfigurationTransferExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONeNBIdentificationExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONengNBIdentificationExtIEsValueExtensionFieldTableCodec]
//   - [ENDCTransferTypeReplyExtIEsValueExtensionFieldTableCodec]
//   - [ENDCTransferTypeRequestExtIEsValueExtensionFieldTableCodec]
//   - [ERABAdmittedItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABDataForwardingItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToResumeItemResumeReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToResumeItemResumeResExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToSetupItemHOReqAckExtIEsValueExtensionFieldTableCodec]
//   - [ERABInformationListItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABModifyItemBearerModConfExtIEsValueExtensionFieldTableCodec]
//   - [ERABModifyItemBearerModResExtIEsValueExtensionFieldTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec]
//   - [ERABQoSParametersExtIEsValueExtensionFieldTableCodec]
//   - [ERABReleaseItemBearerRelCompExtIEsValueExtensionFieldTableCodec]
//   - [ERABSecurityResultItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABSetupItemBearerSUResExtIEsValueExtensionFieldTableCodec]
//   - [ERABSetupItemCtxtSUResExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemBearerSUReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemHOReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSwitchedDLItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSwitchedULItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeUpdatedItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABUsageReportItemExtIEsValueExtensionFieldTableCodec]
//   - [EUTRANCGIExtIEsValueExtensionFieldTableCodec]
//   - [EmergencyAreaIDBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [EmergencyAreaIDCancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [EventL1LoggedMDTConfigExtIEsValueExtensionFieldTableCodec]
//   - [ExpectedUEActivityBehaviourExtIEsValueExtensionFieldTableCodec]
//   - [ExpectedUEBehaviourExtIEsValueExtensionFieldTableCodec]
//   - [FiveGSTAIExtIEsValueExtensionFieldTableCodec]
//   - [ForbiddenLAsItemExtIEsValueExtensionFieldTableCodec]
//   - [ForbiddenTAsItemExtIEsValueExtensionFieldTableCodec]
//   - [GBRQosInformationExtIEsValueExtensionFieldTableCodec]
//   - [GERANCellIDExtIEsValueExtensionFieldTableCodec]
//   - [GNBExtIEsValueExtensionFieldTableCodec]
//   - [GUMMEIExtIEsValueExtensionFieldTableCodec]
//   - [GlobalENBIDExtIEsValueExtensionFieldTableCodec]
//   - [GlobalEnGNBIDExtIEsValueExtensionFieldTableCodec]
//   - [GlobalGNBIDExtIEsValueExtensionFieldTableCodec]
//   - [HandoverRestrictionListExtIEsValueExtensionFieldTableCodec]
//   - [ImmediateMDTExtIEsValueExtensionFieldTableCodec]
//   - [InformationForCECapableUEsExtIEsValueExtensionFieldTableCodec]
//   - [InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [InterSystemMeasurementItemExtIEsValueExtensionFieldTableCodec]
//   - [InterSystemMeasurementParametersExtIEsValueExtensionFieldTableCodec]
//   - [IntersystemMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [LAIExtIEsValueExtensionFieldTableCodec]
//   - [LTENTNTAIInformationExtIEsValueExtensionFieldTableCodec]
//   - [LastVisitedEUTRANCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [LastVisitedPSCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [ListeningSubframePatternExtIEsValueExtensionFieldTableCodec]
//   - [LoggedMBSFNMDTExtIEsValueExtensionFieldTableCodec]
//   - [LoggedMDTExtIEsValueExtensionFieldTableCodec]
//   - [M1PeriodicReportingExtIEsValueExtensionFieldTableCodec]
//   - [M1ThresholdEventA2ExtIEsValueExtensionFieldTableCodec]
//   - [M3ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M4ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M5ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M6ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M7ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [MBSFNResultToLogInfoExtIEsValueExtensionFieldTableCodec]
//   - [MDTConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [MutingPatternInformationExtIEsValueExtensionFieldTableCodec]
//   - [NBIoTPagingEDRXInformationExtIEsValueExtensionFieldTableCodec]
//   - [NGENBExtIEsValueExtensionFieldTableCodec]
//   - [NRCGIExtIEsValueExtensionFieldTableCodec]
//   - [NRUESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec]
//   - [NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionFieldTableCodec]
//   - [NRV2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [PC5FlowBitRatesExtIEsValueExtensionFieldTableCodec]
//   - [PC5QoSFlowItemExtIEsValueExtensionFieldTableCodec]
//   - [PC5QoSParametersExtIEsValueExtensionFieldTableCodec]
//   - [PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [PSCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [PagingAttemptInformationExtIEsValueExtensionFieldTableCodec]
//   - [PagingEDRXInformationExtIEsValueExtensionFieldTableCodec]
//   - [ProSeAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [RATRestrictionsItemExtIEsValueExtensionFieldTableCodec]
//   - [RIMTransferExtIEsValueExtensionFieldTableCodec]
//   - [RLFReportInformationExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedENBItemExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedENBsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [RequestTypeExtIEsValueExtensionFieldTableCodec]
//   - [RequestedTNLInfoExtIEsValueExtensionFieldTableCodec]
//   - [SONConfigurationTransferExtIEsValueExtensionFieldTableCodec]
//   - [SONInformationReplyExtIEsValueExtensionFieldTableCodec]
//   - [STMSIExtIEsValueExtensionFieldTableCodec]
//   - [ScheduledCommunicationTimeExtIEsValueExtensionFieldTableCodec]
//   - [SecondaryRATDataUsageReportItemExtIEsValueExtensionFieldTableCodec]
//   - [SecurityContextExtIEsValueExtensionFieldTableCodec]
//   - [SecurityIndicationExtIEsValueExtensionFieldTableCodec]
//   - [SecurityResultExtIEsValueExtensionFieldTableCodec]
//   - [SensorMeasConfigNameItemExtIEsValueExtensionFieldTableCodec]
//   - [SensorMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [ServedDCNsItemExtIEsValueExtensionFieldTableCodec]
//   - [ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec]
//   - [SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec]
//   - [SourceeNBIDExtIEsValueExtensionFieldTableCodec]
//   - [SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec]
//   - [SupportedTAsItemExtIEsValueExtensionFieldTableCodec]
//   - [SynchronisationInformationExtIEsValueExtensionFieldTableCodec]
//   - [TABasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [TABasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [TAIBasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [TAIBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [TAIBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [TAICancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [TAIExtIEsValueExtensionFieldTableCodec]
//   - [TAIItemExtIEsValueExtensionFieldTableCodec]
//   - [TargetNgRanNodeIDExtIEsValueExtensionFieldTableCodec]
//   - [TargetRNCIDExtIEsValueExtensionFieldTableCodec]
//   - [TargeteNBIDExtIEsValueExtensionFieldTableCodec]
//   - [TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec]
//   - [TimeSynchronisationInfoExtIEsValueExtensionFieldTableCodec]
//   - [TraceActivationExtIEsValueExtensionFieldTableCodec]
//   - [TunnelInformationExtIEsValueExtensionFieldTableCodec]
//   - [UEAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec]
//   - [UEAppLayerMeasConfigExtIEsValueExtensionFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionFieldTableCodec]
//   - [UES1APIDPairExtIEsValueExtensionFieldTableCodec]
//   - [UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec]
//   - [UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec]
//   - [ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec]
//   - [UserLocationInformationExtIEsValueExtensionFieldTableCodec]
//   - [V2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec]
//   - [X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec]
type ExtensionFieldTableCodec[V ProtocolOpenValueConstraint[V]] struct{}

// ExtensionFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [AdditionalGUTIExtIEsValueExtensionFieldTableCodec]
//   - [AllocationAndRetentionPriorityExtIEsValueExtensionFieldTableCodec]
//   - [AssistanceDataForPagingExtIEsValueExtensionFieldTableCodec]
//   - [AssistanceDataForRecommendedCellsExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToDLDiscardingItemExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionFieldTableCodec]
//   - [BearersSubjectToStatusTransferItemExtIEsValueExtensionFieldTableCodec]
//   - [BluetoothMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [CGIExtIEsValueExtensionFieldTableCodec]
//   - [CNTypeRestrictionsItemExtIEsValueExtensionFieldTableCodec]
//   - [COUNTValueExtendedExtIEsValueExtensionFieldTableCodec]
//   - [COUNTvalueExtIEsValueExtensionFieldTableCodec]
//   - [COUNTvaluePDCPSNlength18ExtIEsValueExtensionFieldTableCodec]
//   - [CSGIdListItemExtIEsValueExtensionFieldTableCodec]
//   - [CSGMembershipInfoExtIEsValueExtensionFieldTableCodec]
//   - [CancelledCellinEAIItemExtIEsValueExtensionFieldTableCodec]
//   - [CancelledCellinTAIItemExtIEsValueExtensionFieldTableCodec]
//   - [Cdma2000OneXSRVCCInfoExtIEsValueExtensionFieldTableCodec]
//   - [CellBasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [CellBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [CellIDBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [CellIDCancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionFieldTableCodec]
//   - [CellTypeExtIEsValueExtensionFieldTableCodec]
//   - [CompletedCellinEAIItemExtIEsValueExtensionFieldTableCodec]
//   - [CompletedCellinTAIItemExtIEsValueExtensionFieldTableCodec]
//   - [ConnectedengNBItemExtIEsValueExtensionFieldTableCodec]
//   - [ContextatSourceExtIEsValueExtensionFieldTableCodec]
//   - [CriticalityDiagnosticsExtIEsValueExtensionFieldTableCodec]
//   - [CriticalityDiagnosticsIEItemExtIEsValueExtensionFieldTableCodec]
//   - [DAPSRequestInfoExtIEsValueExtensionFieldTableCodec]
//   - [DAPSResponseInfoExtIEsValueExtensionFieldTableCodec]
//   - [DAPSResponseInfoItemExtIEsValueExtensionFieldTableCodec]
//   - [DLCPSecurityInformationExtIEsValueExtensionFieldTableCodec]
//   - [ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [ENBStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [ENBX2ExtTLAExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONConfigurationTransferExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONeNBIdentificationExtIEsValueExtensionFieldTableCodec]
//   - [ENDCSONengNBIdentificationExtIEsValueExtensionFieldTableCodec]
//   - [ENDCTransferTypeReplyExtIEsValueExtensionFieldTableCodec]
//   - [ENDCTransferTypeRequestExtIEsValueExtensionFieldTableCodec]
//   - [ERABAdmittedItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABDataForwardingItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToResumeItemResumeReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToResumeItemResumeResExtIEsValueExtensionFieldTableCodec]
//   - [ERABFailedToSetupItemHOReqAckExtIEsValueExtensionFieldTableCodec]
//   - [ERABInformationListItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABModifyItemBearerModConfExtIEsValueExtensionFieldTableCodec]
//   - [ERABModifyItemBearerModResExtIEsValueExtensionFieldTableCodec]
//   - [ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec]
//   - [ERABQoSParametersExtIEsValueExtensionFieldTableCodec]
//   - [ERABReleaseItemBearerRelCompExtIEsValueExtensionFieldTableCodec]
//   - [ERABSecurityResultItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABSetupItemBearerSUResExtIEsValueExtensionFieldTableCodec]
//   - [ERABSetupItemCtxtSUResExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeModifyItemBearerModReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemBearerSUReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemCtxtSUReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSetupItemHOReqExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSwitchedDLItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeSwitchedULItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABToBeUpdatedItemExtIEsValueExtensionFieldTableCodec]
//   - [ERABUsageReportItemExtIEsValueExtensionFieldTableCodec]
//   - [EUTRANCGIExtIEsValueExtensionFieldTableCodec]
//   - [EmergencyAreaIDBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [EmergencyAreaIDCancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [EventL1LoggedMDTConfigExtIEsValueExtensionFieldTableCodec]
//   - [ExpectedUEActivityBehaviourExtIEsValueExtensionFieldTableCodec]
//   - [ExpectedUEBehaviourExtIEsValueExtensionFieldTableCodec]
//   - [FiveGSTAIExtIEsValueExtensionFieldTableCodec]
//   - [ForbiddenLAsItemExtIEsValueExtensionFieldTableCodec]
//   - [ForbiddenTAsItemExtIEsValueExtensionFieldTableCodec]
//   - [GBRQosInformationExtIEsValueExtensionFieldTableCodec]
//   - [GERANCellIDExtIEsValueExtensionFieldTableCodec]
//   - [GNBExtIEsValueExtensionFieldTableCodec]
//   - [GUMMEIExtIEsValueExtensionFieldTableCodec]
//   - [GlobalENBIDExtIEsValueExtensionFieldTableCodec]
//   - [GlobalEnGNBIDExtIEsValueExtensionFieldTableCodec]
//   - [GlobalGNBIDExtIEsValueExtensionFieldTableCodec]
//   - [HandoverRestrictionListExtIEsValueExtensionFieldTableCodec]
//   - [ImmediateMDTExtIEsValueExtensionFieldTableCodec]
//   - [InformationForCECapableUEsExtIEsValueExtensionFieldTableCodec]
//   - [InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [InterSystemMeasurementItemExtIEsValueExtensionFieldTableCodec]
//   - [InterSystemMeasurementParametersExtIEsValueExtensionFieldTableCodec]
//   - [IntersystemMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [LAIExtIEsValueExtensionFieldTableCodec]
//   - [LTENTNTAIInformationExtIEsValueExtensionFieldTableCodec]
//   - [LastVisitedEUTRANCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [LastVisitedPSCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [ListeningSubframePatternExtIEsValueExtensionFieldTableCodec]
//   - [LoggedMBSFNMDTExtIEsValueExtensionFieldTableCodec]
//   - [LoggedMDTExtIEsValueExtensionFieldTableCodec]
//   - [M1PeriodicReportingExtIEsValueExtensionFieldTableCodec]
//   - [M1ThresholdEventA2ExtIEsValueExtensionFieldTableCodec]
//   - [M3ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M4ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M5ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M6ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [M7ConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [MBSFNResultToLogInfoExtIEsValueExtensionFieldTableCodec]
//   - [MDTConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [MutingPatternInformationExtIEsValueExtensionFieldTableCodec]
//   - [NBIoTPagingEDRXInformationExtIEsValueExtensionFieldTableCodec]
//   - [NGENBExtIEsValueExtensionFieldTableCodec]
//   - [NRCGIExtIEsValueExtensionFieldTableCodec]
//   - [NRUESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec]
//   - [NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionFieldTableCodec]
//   - [NRV2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [PC5FlowBitRatesExtIEsValueExtensionFieldTableCodec]
//   - [PC5QoSFlowItemExtIEsValueExtensionFieldTableCodec]
//   - [PC5QoSParametersExtIEsValueExtensionFieldTableCodec]
//   - [PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [PSCellInformationExtIEsValueExtensionFieldTableCodec]
//   - [PagingAttemptInformationExtIEsValueExtensionFieldTableCodec]
//   - [PagingEDRXInformationExtIEsValueExtensionFieldTableCodec]
//   - [ProSeAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [RATRestrictionsItemExtIEsValueExtensionFieldTableCodec]
//   - [RIMTransferExtIEsValueExtensionFieldTableCodec]
//   - [RLFReportInformationExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedCellsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedCellsForPagingItemExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedENBItemExtIEsValueExtensionFieldTableCodec]
//   - [RecommendedENBsForPagingExtIEsValueExtensionFieldTableCodec]
//   - [RequestTypeExtIEsValueExtensionFieldTableCodec]
//   - [RequestedTNLInfoExtIEsValueExtensionFieldTableCodec]
//   - [SONConfigurationTransferExtIEsValueExtensionFieldTableCodec]
//   - [SONInformationReplyExtIEsValueExtensionFieldTableCodec]
//   - [STMSIExtIEsValueExtensionFieldTableCodec]
//   - [ScheduledCommunicationTimeExtIEsValueExtensionFieldTableCodec]
//   - [SecondaryRATDataUsageReportItemExtIEsValueExtensionFieldTableCodec]
//   - [SecurityContextExtIEsValueExtensionFieldTableCodec]
//   - [SecurityIndicationExtIEsValueExtensionFieldTableCodec]
//   - [SecurityResultExtIEsValueExtensionFieldTableCodec]
//   - [SensorMeasConfigNameItemExtIEsValueExtensionFieldTableCodec]
//   - [SensorMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [ServedDCNsItemExtIEsValueExtensionFieldTableCodec]
//   - [ServedGUMMEIsItemExtIEsValueExtensionFieldTableCodec]
//   - [SourceNgRanNodeIDExtIEsValueExtensionFieldTableCodec]
//   - [SourceeNBIDExtIEsValueExtensionFieldTableCodec]
//   - [SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [SubscriptionBasedUEDifferentiationInfoExtIEsValueExtensionFieldTableCodec]
//   - [SupportedTAsItemExtIEsValueExtensionFieldTableCodec]
//   - [SynchronisationInformationExtIEsValueExtensionFieldTableCodec]
//   - [TABasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [TABasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [TAIBasedMDTExtIEsValueExtensionFieldTableCodec]
//   - [TAIBasedQMCExtIEsValueExtensionFieldTableCodec]
//   - [TAIBroadcastItemExtIEsValueExtensionFieldTableCodec]
//   - [TAICancelledItemExtIEsValueExtensionFieldTableCodec]
//   - [TAIExtIEsValueExtensionFieldTableCodec]
//   - [TAIItemExtIEsValueExtensionFieldTableCodec]
//   - [TargetNgRanNodeIDExtIEsValueExtensionFieldTableCodec]
//   - [TargetRNCIDExtIEsValueExtensionFieldTableCodec]
//   - [TargeteNBIDExtIEsValueExtensionFieldTableCodec]
//   - [TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec]
//   - [TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec]
//   - [TimeSynchronisationInfoExtIEsValueExtensionFieldTableCodec]
//   - [TraceActivationExtIEsValueExtensionFieldTableCodec]
//   - [TunnelInformationExtIEsValueExtensionFieldTableCodec]
//   - [UEAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec]
//   - [UEAppLayerMeasConfigExtIEsValueExtensionFieldTableCodec]
//   - [UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionFieldTableCodec]
//   - [UES1APIDPairExtIEsValueExtensionFieldTableCodec]
//   - [UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec]
//   - [UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec]
//   - [ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec]
//   - [UserLocationInformationExtIEsValueExtensionFieldTableCodec]
//   - [V2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec]
//   - [WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec]
//   - [WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec]
//   - [X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec]
func (ExtensionFieldTableCodec[V]) Call(table ExtensionTable[V]) ValueCodec[ProtocolExtensionField[V]] {
	if !table.bound {
		return ValueCodec[ProtocolExtensionField[V]]{}
	}
	return ValueCodec[ProtocolExtensionField[V]]{path: "ProtocolExtensionField", decode: func(data []byte, options aper.DecodeState) (ProtocolExtensionField[V], error) {
		var field ProtocolExtensionField[V]
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ProtocolExtensionField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ProtocolExtensionField")
		}
		return field, nil
	}, encode: func(field ProtocolExtensionField[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ProtocolExtensionField[V], options aper.DecodeState) (ProtocolExtensionField[V], aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APProtocolExtensionField[V](&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ProtocolExtensionField[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APProtocolExtensionField[V](&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

type PrivateTable[V ProtocolPrivateValueConstraint[V]] struct{ bound bool }

// PrivateTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [PrivateMessageIEsValuePrivateTableCodec]
type PrivateTableCodec[V ProtocolPrivateValueConstraint[V]] struct{}

// PrivateTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [PrivateMessageIEsValuePrivateTableCodec]
func (PrivateTableCodec[V]) Call(table PrivateTable[V], bounds aper.ListBounds) ValueCodec[PrivateIEContainer[V]] {
	if !table.bound {
		return ValueCodec[PrivateIEContainer[V]]{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ValueCodec[PrivateIEContainer[V]]{path: "PrivateIEContainer", decode: func(data []byte, options aper.DecodeState) (PrivateIEContainer[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PrivateIEContainer[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PrivateIEField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "PrivateIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "PrivateIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PrivateIEContainer")
		}
		return fields, nil
	},
		encode: func(fields PrivateIEContainer[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v PrivateIEContainer[V], options aper.DecodeState) (PrivateIEContainer[V], aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APPrivateIEContainer[V](&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false,
			)
			return v, root
		}, compare: func(v PrivateIEContainer[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPrivateIEContainer[V](&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// PrivateFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [PrivateMessageIEsValuePrivateFieldTableCodec]
type PrivateFieldTableCodec[V ProtocolPrivateValueConstraint[V]] struct{}

// PrivateFieldTableCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [PrivateMessageIEsValuePrivateFieldTableCodec]
func (PrivateFieldTableCodec[V]) Call(table PrivateTable[V]) ValueCodec[PrivateIEField[V]] {
	if !table.bound {
		return ValueCodec[PrivateIEField[V]]{}
	}
	return ValueCodec[PrivateIEField[V]]{path: "PrivateIEField", decode: func(data []byte, options aper.DecodeState) (PrivateIEField[V], error) {
		var field PrivateIEField[V]
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "PrivateIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "PrivateIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "PrivateIEField")
		}
		return field, nil
	}, encode: func(field PrivateIEField[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PrivateIEField[V], options aper.DecodeState) (PrivateIEField[V], aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APPrivateIEField[V](&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PrivateIEField[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPrivateIEField[V](&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ProtocolIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListCodec]
//   - [CellTrafficTraceIEValueProtocolIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueProtocolIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueProtocolIEContainerListCodec]
//   - [DeactivateTraceIEValueProtocolIEContainerListCodec]
//   - [DownlinkNASTransportIEValueProtocolIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueProtocolIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueProtocolIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueProtocolIEContainerListCodec]
//   - [ENBStatusTransferIEValueProtocolIEContainerListCodec]
//   - [ERABAdmittedItemIEValueProtocolIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueProtocolIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListCodec]
//   - [ERABInformationListIEValueProtocolIEContainerListCodec]
//   - [ERABItemIEValueProtocolIEContainerListCodec]
//   - [ERABModificationConfirmIEValueProtocolIEContainerListCodec]
//   - [ERABModificationIndicationIEValueProtocolIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueProtocolIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueProtocolIEContainerListCodec]
//   - [ERABModifyRequestIEValueProtocolIEContainerListCodec]
//   - [ERABModifyResponseIEValueProtocolIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseCommandIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseResponseIEValueProtocolIEContainerListCodec]
//   - [ERABSecurityResultListIEValueProtocolIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec]
//   - [ERABSetupRequestIEValueProtocolIEContainerListCodec]
//   - [ERABSetupResponseIEValueProtocolIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueProtocolIEContainerListCodec]
//   - [ERABUsageReportItemIEValueProtocolIEContainerListCodec]
//   - [ErrorIndicationIEValueProtocolIEContainerListCodec]
//   - [EventTriggerExtIEValueProtocolIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [HandoverCancelIEValueProtocolIEContainerListCodec]
//   - [HandoverCommandIEValueProtocolIEContainerListCodec]
//   - [HandoverFailureIEValueProtocolIEContainerListCodec]
//   - [HandoverNotifyIEValueProtocolIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueProtocolIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [HandoverRequestIEValueProtocolIEContainerListCodec]
//   - [HandoverRequiredIEValueProtocolIEContainerListCodec]
//   - [HandoverSuccessIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueProtocolIEContainerListCodec]
//   - [InitialUEMessageIEValueProtocolIEContainerListCodec]
//   - [KillRequestIEValueProtocolIEContainerListCodec]
//   - [KillResponseIEValueProtocolIEContainerListCodec]
//   - [LocationReportIEValueProtocolIEContainerListCodec]
//   - [LocationReportingControlIEValueProtocolIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueProtocolIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueProtocolIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueProtocolIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec]
//   - [MMEStatusTransferIEValueProtocolIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueProtocolIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec]
//   - [OverloadStartIEValueProtocolIEContainerListCodec]
//   - [OverloadStopIEValueProtocolIEContainerListCodec]
//   - [PWSFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [PWSRestartIndicationIEValueProtocolIEContainerListCodec]
//   - [PagingIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestIEValueProtocolIEContainerListCodec]
//   - [RecommendedCellItemIEValueProtocolIEContainerListCodec]
//   - [RecommendedENBItemIEValueProtocolIEContainerListCodec]
//   - [RerouteNASRequestIEValueProtocolIEContainerListCodec]
//   - [ResetAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [ResetIEValueProtocolIEContainerListCodec]
//   - [RetrieveUEInformationIEValueProtocolIEContainerListCodec]
//   - [S1RemovalFailureIEValueProtocolIEContainerListCodec]
//   - [S1RemovalRequestIEValueProtocolIEContainerListCodec]
//   - [S1RemovalResponseIEValueProtocolIEContainerListCodec]
//   - [S1SetupFailureIEValueProtocolIEContainerListCodec]
//   - [S1SetupRequestIEValueProtocolIEContainerListCodec]
//   - [S1SetupResponseIEValueProtocolIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueProtocolIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueProtocolIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListCodec]
//   - [SensorNameConfigExtIEValueProtocolIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec]
//   - [TAIItemIEValueProtocolIEContainerListCodec]
//   - [TraceFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [TraceStartIEValueProtocolIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationFailureIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationResponseIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeFailureIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeResponseIEValueProtocolIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueProtocolIEContainerListCodec]
//   - [UEInformationTransferIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec]
//   - [UplinkNASTransportIEValueProtocolIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec]
type ProtocolIEContainerListCodec[V ProtocolOpenValueConstraint[V]] struct{}

// ProtocolIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListCodec]
//   - [CellTrafficTraceIEValueProtocolIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueProtocolIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueProtocolIEContainerListCodec]
//   - [DeactivateTraceIEValueProtocolIEContainerListCodec]
//   - [DownlinkNASTransportIEValueProtocolIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueProtocolIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueProtocolIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueProtocolIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueProtocolIEContainerListCodec]
//   - [ENBStatusTransferIEValueProtocolIEContainerListCodec]
//   - [ERABAdmittedItemIEValueProtocolIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueProtocolIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueProtocolIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListCodec]
//   - [ERABInformationListIEValueProtocolIEContainerListCodec]
//   - [ERABItemIEValueProtocolIEContainerListCodec]
//   - [ERABModificationConfirmIEValueProtocolIEContainerListCodec]
//   - [ERABModificationIndicationIEValueProtocolIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueProtocolIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueProtocolIEContainerListCodec]
//   - [ERABModifyRequestIEValueProtocolIEContainerListCodec]
//   - [ERABModifyResponseIEValueProtocolIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseCommandIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListCodec]
//   - [ERABReleaseResponseIEValueProtocolIEContainerListCodec]
//   - [ERABSecurityResultListIEValueProtocolIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueProtocolIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueProtocolIEContainerListCodec]
//   - [ERABSetupRequestIEValueProtocolIEContainerListCodec]
//   - [ERABSetupResponseIEValueProtocolIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueProtocolIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueProtocolIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueProtocolIEContainerListCodec]
//   - [ERABUsageReportItemIEValueProtocolIEContainerListCodec]
//   - [ErrorIndicationIEValueProtocolIEContainerListCodec]
//   - [EventTriggerExtIEValueProtocolIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [HandoverCancelIEValueProtocolIEContainerListCodec]
//   - [HandoverCommandIEValueProtocolIEContainerListCodec]
//   - [HandoverFailureIEValueProtocolIEContainerListCodec]
//   - [HandoverNotifyIEValueProtocolIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueProtocolIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [HandoverRequestIEValueProtocolIEContainerListCodec]
//   - [HandoverRequiredIEValueProtocolIEContainerListCodec]
//   - [HandoverSuccessIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueProtocolIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueProtocolIEContainerListCodec]
//   - [InitialUEMessageIEValueProtocolIEContainerListCodec]
//   - [KillRequestIEValueProtocolIEContainerListCodec]
//   - [KillResponseIEValueProtocolIEContainerListCodec]
//   - [LocationReportIEValueProtocolIEContainerListCodec]
//   - [LocationReportingControlIEValueProtocolIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueProtocolIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueProtocolIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueProtocolIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueProtocolIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec]
//   - [MMEStatusTransferIEValueProtocolIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueProtocolIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueProtocolIEContainerListCodec]
//   - [OverloadStartIEValueProtocolIEContainerListCodec]
//   - [OverloadStopIEValueProtocolIEContainerListCodec]
//   - [PWSFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [PWSRestartIndicationIEValueProtocolIEContainerListCodec]
//   - [PagingIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueProtocolIEContainerListCodec]
//   - [PathSwitchRequestIEValueProtocolIEContainerListCodec]
//   - [RecommendedCellItemIEValueProtocolIEContainerListCodec]
//   - [RecommendedENBItemIEValueProtocolIEContainerListCodec]
//   - [RerouteNASRequestIEValueProtocolIEContainerListCodec]
//   - [ResetAcknowledgeIEValueProtocolIEContainerListCodec]
//   - [ResetIEValueProtocolIEContainerListCodec]
//   - [RetrieveUEInformationIEValueProtocolIEContainerListCodec]
//   - [S1RemovalFailureIEValueProtocolIEContainerListCodec]
//   - [S1RemovalRequestIEValueProtocolIEContainerListCodec]
//   - [S1RemovalResponseIEValueProtocolIEContainerListCodec]
//   - [S1SetupFailureIEValueProtocolIEContainerListCodec]
//   - [S1SetupRequestIEValueProtocolIEContainerListCodec]
//   - [S1SetupResponseIEValueProtocolIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueProtocolIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueProtocolIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueProtocolIEContainerListCodec]
//   - [SensorNameConfigExtIEValueProtocolIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueProtocolIEContainerListCodec]
//   - [TAIItemIEValueProtocolIEContainerListCodec]
//   - [TraceFailureIndicationIEValueProtocolIEContainerListCodec]
//   - [TraceStartIEValueProtocolIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationFailureIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextModificationResponseIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueProtocolIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeFailureIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextResumeResponseIEValueProtocolIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueProtocolIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueProtocolIEContainerListCodec]
//   - [UEInformationTransferIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec]
//   - [UplinkNASTransportIEValueProtocolIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec]
func (ProtocolIEContainerListCodec[V]) Call(table IETable[V], bounds aper.ListBounds) ValueCodec[ProtocolIEContainerList[V]] {
	codec := (IETableCodec[V]{}).Call(table, bounds)
	if codec.decode == nil {
		return ValueCodec[ProtocolIEContainerList[V]]{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ValueCodec[ProtocolIEContainerList[V]]{path: "ProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ProtocolIEContainerList[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ProtocolIEContainerList[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ProtocolIEField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ProtocolIEContainerList[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ProtocolIEContainer[V](value), fresh, budget)
	}, capture: func(v ProtocolIEContainerList[V], options aper.DecodeState) (ProtocolIEContainerList[V], aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APProtocolIEContainerList[V](&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ProtocolIEContainerList[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APProtocolIEContainerList[V](&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// ERABIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueERABIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueERABIEContainerListCodec]
//   - [CellTrafficTraceIEValueERABIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueERABIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueERABIEContainerListCodec]
//   - [DeactivateTraceIEValueERABIEContainerListCodec]
//   - [DownlinkNASTransportIEValueERABIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueERABIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueERABIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueERABIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueERABIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueERABIEContainerListCodec]
//   - [ENBStatusTransferIEValueERABIEContainerListCodec]
//   - [ERABAdmittedItemIEValueERABIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueERABIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueERABIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueERABIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListCodec]
//   - [ERABInformationListIEValueERABIEContainerListCodec]
//   - [ERABItemIEValueERABIEContainerListCodec]
//   - [ERABModificationConfirmIEValueERABIEContainerListCodec]
//   - [ERABModificationIndicationIEValueERABIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueERABIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueERABIEContainerListCodec]
//   - [ERABModifyRequestIEValueERABIEContainerListCodec]
//   - [ERABModifyResponseIEValueERABIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec]
//   - [ERABReleaseCommandIEValueERABIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueERABIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec]
//   - [ERABReleaseResponseIEValueERABIEContainerListCodec]
//   - [ERABSecurityResultListIEValueERABIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueERABIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec]
//   - [ERABSetupRequestIEValueERABIEContainerListCodec]
//   - [ERABSetupResponseIEValueERABIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueERABIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueERABIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueERABIEContainerListCodec]
//   - [ERABUsageReportItemIEValueERABIEContainerListCodec]
//   - [ErrorIndicationIEValueERABIEContainerListCodec]
//   - [EventTriggerExtIEValueERABIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueERABIEContainerListCodec]
//   - [HandoverCancelIEValueERABIEContainerListCodec]
//   - [HandoverCommandIEValueERABIEContainerListCodec]
//   - [HandoverFailureIEValueERABIEContainerListCodec]
//   - [HandoverNotifyIEValueERABIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueERABIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueERABIEContainerListCodec]
//   - [HandoverRequestIEValueERABIEContainerListCodec]
//   - [HandoverRequiredIEValueERABIEContainerListCodec]
//   - [HandoverSuccessIEValueERABIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueERABIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueERABIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueERABIEContainerListCodec]
//   - [InitialUEMessageIEValueERABIEContainerListCodec]
//   - [KillRequestIEValueERABIEContainerListCodec]
//   - [KillResponseIEValueERABIEContainerListCodec]
//   - [LocationReportIEValueERABIEContainerListCodec]
//   - [LocationReportingControlIEValueERABIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueERABIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueERABIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueERABIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueERABIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueERABIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueERABIEContainerListCodec]
//   - [MMEStatusTransferIEValueERABIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueERABIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueERABIEContainerListCodec]
//   - [OverloadStartIEValueERABIEContainerListCodec]
//   - [OverloadStopIEValueERABIEContainerListCodec]
//   - [PWSFailureIndicationIEValueERABIEContainerListCodec]
//   - [PWSRestartIndicationIEValueERABIEContainerListCodec]
//   - [PagingIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestIEValueERABIEContainerListCodec]
//   - [RecommendedCellItemIEValueERABIEContainerListCodec]
//   - [RecommendedENBItemIEValueERABIEContainerListCodec]
//   - [RerouteNASRequestIEValueERABIEContainerListCodec]
//   - [ResetAcknowledgeIEValueERABIEContainerListCodec]
//   - [ResetIEValueERABIEContainerListCodec]
//   - [RetrieveUEInformationIEValueERABIEContainerListCodec]
//   - [S1RemovalFailureIEValueERABIEContainerListCodec]
//   - [S1RemovalRequestIEValueERABIEContainerListCodec]
//   - [S1RemovalResponseIEValueERABIEContainerListCodec]
//   - [S1SetupFailureIEValueERABIEContainerListCodec]
//   - [S1SetupRequestIEValueERABIEContainerListCodec]
//   - [S1SetupResponseIEValueERABIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueERABIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueERABIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueERABIEContainerListCodec]
//   - [SensorNameConfigExtIEValueERABIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueERABIEContainerListCodec]
//   - [TAIItemIEValueERABIEContainerListCodec]
//   - [TraceFailureIndicationIEValueERABIEContainerListCodec]
//   - [TraceStartIEValueERABIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueERABIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueERABIEContainerListCodec]
//   - [UEContextModificationFailureIEValueERABIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueERABIEContainerListCodec]
//   - [UEContextModificationRequestIEValueERABIEContainerListCodec]
//   - [UEContextModificationResponseIEValueERABIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueERABIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueERABIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueERABIEContainerListCodec]
//   - [UEContextResumeFailureIEValueERABIEContainerListCodec]
//   - [UEContextResumeRequestIEValueERABIEContainerListCodec]
//   - [UEContextResumeResponseIEValueERABIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueERABIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueERABIEContainerListCodec]
//   - [UEInformationTransferIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec]
//   - [UplinkNASTransportIEValueERABIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueERABIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueERABIEContainerListCodec]
type ERABIEContainerListCodec[V ProtocolOpenValueConstraint[V]] struct{}

// ERABIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueERABIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueERABIEContainerListCodec]
//   - [CellTrafficTraceIEValueERABIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueERABIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueERABIEContainerListCodec]
//   - [DeactivateTraceIEValueERABIEContainerListCodec]
//   - [DownlinkNASTransportIEValueERABIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueERABIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueERABIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueERABIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueERABIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueERABIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueERABIEContainerListCodec]
//   - [ENBStatusTransferIEValueERABIEContainerListCodec]
//   - [ERABAdmittedItemIEValueERABIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueERABIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueERABIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueERABIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListCodec]
//   - [ERABInformationListIEValueERABIEContainerListCodec]
//   - [ERABItemIEValueERABIEContainerListCodec]
//   - [ERABModificationConfirmIEValueERABIEContainerListCodec]
//   - [ERABModificationIndicationIEValueERABIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueERABIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueERABIEContainerListCodec]
//   - [ERABModifyRequestIEValueERABIEContainerListCodec]
//   - [ERABModifyResponseIEValueERABIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec]
//   - [ERABReleaseCommandIEValueERABIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueERABIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueERABIEContainerListCodec]
//   - [ERABReleaseResponseIEValueERABIEContainerListCodec]
//   - [ERABSecurityResultListIEValueERABIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueERABIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueERABIEContainerListCodec]
//   - [ERABSetupRequestIEValueERABIEContainerListCodec]
//   - [ERABSetupResponseIEValueERABIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueERABIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueERABIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueERABIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueERABIEContainerListCodec]
//   - [ERABUsageReportItemIEValueERABIEContainerListCodec]
//   - [ErrorIndicationIEValueERABIEContainerListCodec]
//   - [EventTriggerExtIEValueERABIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueERABIEContainerListCodec]
//   - [HandoverCancelIEValueERABIEContainerListCodec]
//   - [HandoverCommandIEValueERABIEContainerListCodec]
//   - [HandoverFailureIEValueERABIEContainerListCodec]
//   - [HandoverNotifyIEValueERABIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueERABIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueERABIEContainerListCodec]
//   - [HandoverRequestIEValueERABIEContainerListCodec]
//   - [HandoverRequiredIEValueERABIEContainerListCodec]
//   - [HandoverSuccessIEValueERABIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueERABIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueERABIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueERABIEContainerListCodec]
//   - [InitialUEMessageIEValueERABIEContainerListCodec]
//   - [KillRequestIEValueERABIEContainerListCodec]
//   - [KillResponseIEValueERABIEContainerListCodec]
//   - [LocationReportIEValueERABIEContainerListCodec]
//   - [LocationReportingControlIEValueERABIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueERABIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueERABIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueERABIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueERABIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueERABIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueERABIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueERABIEContainerListCodec]
//   - [MMEStatusTransferIEValueERABIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueERABIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueERABIEContainerListCodec]
//   - [OverloadStartIEValueERABIEContainerListCodec]
//   - [OverloadStopIEValueERABIEContainerListCodec]
//   - [PWSFailureIndicationIEValueERABIEContainerListCodec]
//   - [PWSRestartIndicationIEValueERABIEContainerListCodec]
//   - [PagingIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueERABIEContainerListCodec]
//   - [PathSwitchRequestIEValueERABIEContainerListCodec]
//   - [RecommendedCellItemIEValueERABIEContainerListCodec]
//   - [RecommendedENBItemIEValueERABIEContainerListCodec]
//   - [RerouteNASRequestIEValueERABIEContainerListCodec]
//   - [ResetAcknowledgeIEValueERABIEContainerListCodec]
//   - [ResetIEValueERABIEContainerListCodec]
//   - [RetrieveUEInformationIEValueERABIEContainerListCodec]
//   - [S1RemovalFailureIEValueERABIEContainerListCodec]
//   - [S1RemovalRequestIEValueERABIEContainerListCodec]
//   - [S1RemovalResponseIEValueERABIEContainerListCodec]
//   - [S1SetupFailureIEValueERABIEContainerListCodec]
//   - [S1SetupRequestIEValueERABIEContainerListCodec]
//   - [S1SetupResponseIEValueERABIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueERABIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueERABIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueERABIEContainerListCodec]
//   - [SensorNameConfigExtIEValueERABIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueERABIEContainerListCodec]
//   - [TAIItemIEValueERABIEContainerListCodec]
//   - [TraceFailureIndicationIEValueERABIEContainerListCodec]
//   - [TraceStartIEValueERABIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueERABIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueERABIEContainerListCodec]
//   - [UEContextModificationFailureIEValueERABIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueERABIEContainerListCodec]
//   - [UEContextModificationRequestIEValueERABIEContainerListCodec]
//   - [UEContextModificationResponseIEValueERABIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueERABIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueERABIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueERABIEContainerListCodec]
//   - [UEContextResumeFailureIEValueERABIEContainerListCodec]
//   - [UEContextResumeRequestIEValueERABIEContainerListCodec]
//   - [UEContextResumeResponseIEValueERABIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueERABIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueERABIEContainerListCodec]
//   - [UEInformationTransferIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec]
//   - [UplinkNASTransportIEValueERABIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueERABIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueERABIEContainerListCodec]
func (ERABIEContainerListCodec[V]) Call(table IETable[V]) ValueCodec[ERABIEContainerList[V]] {
	codec := (IETableCodec[V]{}).Call(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ValueCodec[ERABIEContainerList[V]]{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ValueCodec[ERABIEContainerList[V]]{path: "ERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ERABIEContainerList[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ERABIEContainerList[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ProtocolIEField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ERABIEContainerList[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ProtocolIEContainer[V](value), fresh, budget)
	}, capture: func(v ERABIEContainerList[V], options aper.DecodeState) (ERABIEContainerList[V], aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APERABIEContainerList[V](&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ERABIEContainerList[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APERABIEContainerList[V](&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ProtocolErrorIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListCodec]
//   - [CellTrafficTraceIEValueProtocolErrorIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueProtocolErrorIEContainerListCodec]
//   - [DeactivateTraceIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkNASTransportIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueProtocolErrorIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ERABAdmittedItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListCodec]
//   - [ERABInformationListIEValueProtocolErrorIEContainerListCodec]
//   - [ERABItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModificationConfirmIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModificationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseCommandIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSecurityResultListIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec]
//   - [ErrorIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [EventTriggerExtIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCancelIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCommandIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverFailureIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverNotifyIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequestIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequiredIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverSuccessIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [InitialUEMessageIEValueProtocolErrorIEContainerListCodec]
//   - [KillRequestIEValueProtocolErrorIEContainerListCodec]
//   - [KillResponseIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportingControlIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueProtocolErrorIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [OverloadStartIEValueProtocolErrorIEContainerListCodec]
//   - [OverloadStopIEValueProtocolErrorIEContainerListCodec]
//   - [PWSFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [PagingIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestIEValueProtocolErrorIEContainerListCodec]
//   - [RecommendedCellItemIEValueProtocolErrorIEContainerListCodec]
//   - [RecommendedENBItemIEValueProtocolErrorIEContainerListCodec]
//   - [RerouteNASRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [ResetIEValueProtocolErrorIEContainerListCodec]
//   - [RetrieveUEInformationIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalFailureIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalRequestIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalResponseIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupFailureIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListCodec]
//   - [SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [TAIItemIEValueProtocolErrorIEContainerListCodec]
//   - [TraceFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [TraceStartIEValueProtocolErrorIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkNASTransportIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec]
type ProtocolErrorIEContainerListCodec[V ProtocolOpenValueConstraint[V]] struct{}

// ProtocolErrorIEContainerListCodec constructs a codec for a bound table.
//
// Use these concrete factory variables to call it from outside the package:
//   - [BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListCodec]
//   - [BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListCodec]
//   - [BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListCodec]
//   - [CellTrafficTraceIEValueProtocolErrorIEContainerListCodec]
//   - [ConnectionEstablishmentIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [DAPSResponseInfoListIEValueProtocolErrorIEContainerListCodec]
//   - [DeactivateTraceIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkNASTransportIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec]
//   - [DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec]
//   - [ENBConfigurationUpdateIEValueProtocolErrorIEContainerListCodec]
//   - [ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ENBStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [ERABAdmittedItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABDataForwardingItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedToResumeItemResumeResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListCodec]
//   - [ERABInformationListIEValueProtocolErrorIEContainerListCodec]
//   - [ERABItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModificationConfirmIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModificationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ERABModifyResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseCommandIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListCodec]
//   - [ERABReleaseResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSecurityResultListIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ERABSetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeModifiedItemBearerModReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemBearerSUReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemCtxtSUReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSetupItemHOReqIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSwitchedDLItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABToBeUpdatedItemIEValueProtocolErrorIEContainerListCodec]
//   - [ERABUsageReportItemIEValueProtocolErrorIEContainerListCodec]
//   - [ErrorIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [EventTriggerExtIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCancelAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCancelIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverCommandIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverFailureIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverNotifyIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverPreparationFailureIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequestIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverRequiredIEValueProtocolErrorIEContainerListCodec]
//   - [HandoverSuccessIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupFailureIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [InitialContextSetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [InitialUEMessageIEValueProtocolErrorIEContainerListCodec]
//   - [KillRequestIEValueProtocolErrorIEContainerListCodec]
//   - [KillResponseIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportingControlIEValueProtocolErrorIEContainerListCodec]
//   - [LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [MDTModeExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [MMECPRelocationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec]
//   - [MMEConfigurationUpdateIEValueProtocolErrorIEContainerListCodec]
//   - [MMEDirectInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MMEStatusTransferIEValueProtocolErrorIEContainerListCodec]
//   - [MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListCodec]
//   - [NASDeliveryIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [OverloadStartIEValueProtocolErrorIEContainerListCodec]
//   - [OverloadStopIEValueProtocolErrorIEContainerListCodec]
//   - [PWSFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [PagingIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestFailureIEValueProtocolErrorIEContainerListCodec]
//   - [PathSwitchRequestIEValueProtocolErrorIEContainerListCodec]
//   - [RecommendedCellItemIEValueProtocolErrorIEContainerListCodec]
//   - [RecommendedENBItemIEValueProtocolErrorIEContainerListCodec]
//   - [RerouteNASRequestIEValueProtocolErrorIEContainerListCodec]
//   - [ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec]
//   - [ResetIEValueProtocolErrorIEContainerListCodec]
//   - [RetrieveUEInformationIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalFailureIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalRequestIEValueProtocolErrorIEContainerListCodec]
//   - [S1RemovalResponseIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupFailureIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupRequestIEValueProtocolErrorIEContainerListCodec]
//   - [S1SetupResponseIEValueProtocolErrorIEContainerListCodec]
//   - [SONInformationExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListCodec]
//   - [SecondaryRATDataUsageReportItemIEValueProtocolErrorIEContainerListCodec]
//   - [SensorNameConfigExtIEValueProtocolErrorIEContainerListCodec]
//   - [SourceNodeIDExtensionIEIEValueProtocolErrorIEContainerListCodec]
//   - [TAIItemIEValueProtocolErrorIEContainerListCodec]
//   - [TraceFailureIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [TraceStartIEValueProtocolErrorIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListCodec]
//   - [UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListCodec]
//   - [UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationConfirmIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseCompleteIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextReleaseRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextResumeResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextSuspendRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UEInformationTransferIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec]
//   - [UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkNASTransportIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec]
//   - [UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec]
//   - [WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec]
//   - [WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec]
func (ProtocolErrorIEContainerListCodec[V]) Call(table IETable[V]) ValueCodec[ProtocolErrorIEContainerList[V]] {
	codec := (IETableCodec[V]{}).Call(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ValueCodec[ProtocolErrorIEContainerList[V]]{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ValueCodec[ProtocolErrorIEContainerList[V]]{path: "ProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ProtocolErrorIEContainerList[V], error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ProtocolErrorIEContainerList[V]
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ProtocolIEField[V]
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ProtocolErrorIEContainerList[V], fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ProtocolIEContainer[V](value), fresh, budget)
	}, capture: func(v ProtocolErrorIEContainerList[V], options aper.DecodeState) (ProtocolErrorIEContainerList[V], aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APProtocolErrorIEContainerList[V](&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ProtocolErrorIEContainerList[V], root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APProtocolErrorIEContainerList[V](
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

type ProtocolOpenValueConstraint[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}
type ProtocolIEField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         V
	received      aper.CompletePadding
}
type ProtocolIEContainer[V ProtocolOpenValueConstraint[V]] []ProtocolIEField[V]
type ProtocolIEContainerList[V ProtocolOpenValueConstraint[V]] []ProtocolIESingleContainer[V]
type ERABIEContainerList[V ProtocolOpenValueConstraint[V]] []ProtocolIESingleContainer[V]
type ERABIEContainerPairList[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEContainerPair[A, B]
type ProtocolErrorIEContainerList[V ProtocolOpenValueConstraint[V]] []ProtocolIESingleContainer[V]

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProtocolIEField[V]) WithoutReplay() ProtocolIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ProtocolIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ProtocolIEField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ProtocolIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolIEField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type ProtocolExtensionField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue V
	received       aper.CompletePadding
}
type ProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]] []ProtocolExtensionField[V]

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProtocolExtensionField[V]) WithoutReplay() ProtocolExtensionField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ProtocolExtensionField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ProtocolExtensionField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *ProtocolExtensionField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolExtensionField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type ProtocolPrivateValueConstraint[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s23.PrivateIEID, ...*aper.DecodeBudget) bool
	decode(s23.PrivateIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}
type PrivateIEField[V ProtocolPrivateValueConstraint[V]] struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s23.PrivateIEID
	Criticality   s00.Criticality
	Value         V
	received      aper.CompletePadding
}
type PrivateIEContainer[V ProtocolPrivateValueConstraint[V]] []PrivateIEField[V]

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateIEField[V]) WithoutReplay() PrivateIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PrivateIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PrivateIEField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: private field id does not match its value selector", aper.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := s23.BridgePrivateIEIDMethodMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return aper.EncodeOpenTypeAligned(bb, data)
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *PrivateIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEField[V]{}
	if err := s23.BridgePrivateIEIDMethodUnmarshalAPERFrom(&v.Id, bb); err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type ProtocolIEFieldPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] struct {
	Id                s00.ProtocolIEID
	FirstCriticality  s00.Criticality
	FirstValue        A
	SecondCriticality s00.Criticality
	SecondValue       B
}
type ProtocolIEContainerPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEFieldPair[A, B]
type ProtocolIEContainerPairList[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEContainerPair[A, B]
type ProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]] = ProtocolIEField[V]
type HandoverPreparationDescriptor struct{}

func HandoverPreparationProcedure() HandoverPreparationDescriptor {
	return HandoverPreparationDescriptor{}
}

// Info returns the source-derived procedure metadata for HandoverPreparationDescriptor.
func (HandoverPreparationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(0), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-HandoverPreparation"}}}
}

type HandoverResourceAllocationDescriptor struct{}

func HandoverResourceAllocationProcedure() HandoverResourceAllocationDescriptor {
	return HandoverResourceAllocationDescriptor{}
}

// Info returns the source-derived procedure metadata for HandoverResourceAllocationDescriptor.
func (HandoverResourceAllocationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(1), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-HandoverResourceAllocation"}}}
}

type HandoverNotificationDescriptor struct{}

func HandoverNotificationProcedure() HandoverNotificationDescriptor {
	return HandoverNotificationDescriptor{}
}

// Info returns the source-derived procedure metadata for HandoverNotificationDescriptor.
func (HandoverNotificationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(2), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-HandoverNotification"}}}
}

type HandoverCancelDescriptor struct{}

func HandoverCancelProcedure() HandoverCancelDescriptor { return HandoverCancelDescriptor{} }

// Info returns the source-derived procedure metadata for HandoverCancelDescriptor.
func (HandoverCancelDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(4), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-HandoverCancel"}}}
}

type ERABSetupDescriptor struct{}

func ERABSetupProcedure() ERABSetupDescriptor { return ERABSetupDescriptor{} }

// Info returns the source-derived procedure metadata for ERABSetupDescriptor.
func (ERABSetupDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(5), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-E-RABSetup"}}}
}

type ERABModifyDescriptor struct{}

func ERABModifyProcedure() ERABModifyDescriptor { return ERABModifyDescriptor{} }

// Info returns the source-derived procedure metadata for ERABModifyDescriptor.
func (ERABModifyDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(6), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-E-RABModify"}}}
}

type ERABReleaseDescriptor struct{}

func ERABReleaseProcedure() ERABReleaseDescriptor { return ERABReleaseDescriptor{} }

// Info returns the source-derived procedure metadata for ERABReleaseDescriptor.
func (ERABReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(7), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-E-RABRelease"}}}
}

type ERABReleaseIndicationDescriptor struct{}

func ERABReleaseIndicationProcedure() ERABReleaseIndicationDescriptor {
	return ERABReleaseIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for ERABReleaseIndicationDescriptor.
func (ERABReleaseIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(8), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-E-RABReleaseIndication"}}}
}

type InitialContextSetupDescriptor struct{}

func InitialContextSetupProcedure() InitialContextSetupDescriptor {
	return InitialContextSetupDescriptor{}
}

// Info returns the source-derived procedure metadata for InitialContextSetupDescriptor.
func (InitialContextSetupDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(9), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-InitialContextSetup"}}}
}

type DownlinkNASTransportDescriptor struct{}

func DownlinkNASTransportProcedure() DownlinkNASTransportDescriptor {
	return DownlinkNASTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for DownlinkNASTransportDescriptor.
func (DownlinkNASTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(11), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-downlinkNASTransport"}}}
}

type InitialUEMessageDescriptor struct{}

func InitialUEMessageProcedure() InitialUEMessageDescriptor { return InitialUEMessageDescriptor{} }

// Info returns the source-derived procedure metadata for InitialUEMessageDescriptor.
func (InitialUEMessageDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(12), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-initialUEMessage"}}}
}

type ErrorIndicationDescriptor struct{}

func ErrorIndicationProcedure() ErrorIndicationDescriptor { return ErrorIndicationDescriptor{} }

// Info returns the source-derived procedure metadata for ErrorIndicationDescriptor.
func (ErrorIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(15), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-ErrorIndication"}}}
}

type NASNonDeliveryIndicationDescriptor struct{}

func NASNonDeliveryIndicationProcedure() NASNonDeliveryIndicationDescriptor {
	return NASNonDeliveryIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for NASNonDeliveryIndicationDescriptor.
func (NASNonDeliveryIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(16), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-NASNonDeliveryIndication"}}}
}

type DownlinkS1cdma2000tunnellingDescriptor struct{}

func DownlinkS1cdma2000tunnellingProcedure() DownlinkS1cdma2000tunnellingDescriptor {
	return DownlinkS1cdma2000tunnellingDescriptor{}
}

// Info returns the source-derived procedure metadata for DownlinkS1cdma2000tunnellingDescriptor.
func (DownlinkS1cdma2000tunnellingDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(19), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-DownlinkS1cdma2000tunnelling"}}}
}

type ENBStatusTransferDescriptor struct{}

func ENBStatusTransferProcedure() ENBStatusTransferDescriptor { return ENBStatusTransferDescriptor{} }

// Info returns the source-derived procedure metadata for ENBStatusTransferDescriptor.
func (ENBStatusTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(24), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-eNBStatusTransfer"}}}
}

type MMEStatusTransferDescriptor struct{}

func MMEStatusTransferProcedure() MMEStatusTransferDescriptor { return MMEStatusTransferDescriptor{} }

// Info returns the source-derived procedure metadata for MMEStatusTransferDescriptor.
func (MMEStatusTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(25), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMEStatusTransfer"}}}
}

type DeactivateTraceDescriptor struct{}

func DeactivateTraceProcedure() DeactivateTraceDescriptor { return DeactivateTraceDescriptor{} }

// Info returns the source-derived procedure metadata for DeactivateTraceDescriptor.
func (DeactivateTraceDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(26), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-DeactivateTrace"}}}
}

type ENBConfigurationUpdateDescriptor struct{}

func ENBConfigurationUpdateProcedure() ENBConfigurationUpdateDescriptor {
	return ENBConfigurationUpdateDescriptor{}
}

// Info returns the source-derived procedure metadata for ENBConfigurationUpdateDescriptor.
func (ENBConfigurationUpdateDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(29), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-ENBConfigurationUpdate"}}}
}

type MMEConfigurationUpdateDescriptor struct{}

func MMEConfigurationUpdateProcedure() MMEConfigurationUpdateDescriptor {
	return MMEConfigurationUpdateDescriptor{}
}

// Info returns the source-derived procedure metadata for MMEConfigurationUpdateDescriptor.
func (MMEConfigurationUpdateDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(30), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMEConfigurationUpdate"}}}
}

type LocationReportingControlDescriptor struct{}

func LocationReportingControlProcedure() LocationReportingControlDescriptor {
	return LocationReportingControlDescriptor{}
}

// Info returns the source-derived procedure metadata for LocationReportingControlDescriptor.
func (LocationReportingControlDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(31), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-LocationReportingControl"}}}
}

type LocationReportingFailureIndicationDescriptor struct{}

func LocationReportingFailureIndicationProcedure() LocationReportingFailureIndicationDescriptor {
	return LocationReportingFailureIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for LocationReportingFailureIndicationDescriptor.
func (LocationReportingFailureIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(32), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-LocationReportingFailureIndication"}}}
}

type LocationReportDescriptor struct{}

func LocationReportProcedure() LocationReportDescriptor { return LocationReportDescriptor{} }

// Info returns the source-derived procedure metadata for LocationReportDescriptor.
func (LocationReportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(33), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-LocationReport"}}}
}

type ENBDirectInformationTransferDescriptor struct{}

func ENBDirectInformationTransferProcedure() ENBDirectInformationTransferDescriptor {
	return ENBDirectInformationTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for ENBDirectInformationTransferDescriptor.
func (ENBDirectInformationTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(37), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-eNBDirectInformationTransfer"}}}
}

type MMEDirectInformationTransferDescriptor struct{}

func MMEDirectInformationTransferProcedure() MMEDirectInformationTransferDescriptor {
	return MMEDirectInformationTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for MMEDirectInformationTransferDescriptor.
func (MMEDirectInformationTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(38), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMEDirectInformationTransfer"}}}
}

type CellTrafficTraceDescriptor struct{}

func CellTrafficTraceProcedure() CellTrafficTraceDescriptor { return CellTrafficTraceDescriptor{} }

// Info returns the source-derived procedure metadata for CellTrafficTraceDescriptor.
func (CellTrafficTraceDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(42), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-CellTrafficTrace"}}}
}

type KillDescriptor struct{}

func KillProcedure() KillDescriptor { return KillDescriptor{} }

// Info returns the source-derived procedure metadata for KillDescriptor.
func (KillDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(43), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-Kill"}}}
}

type DownlinkUEAssociatedLPPaTransportDescriptor struct{}

func DownlinkUEAssociatedLPPaTransportProcedure() DownlinkUEAssociatedLPPaTransportDescriptor {
	return DownlinkUEAssociatedLPPaTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for DownlinkUEAssociatedLPPaTransportDescriptor.
func (DownlinkUEAssociatedLPPaTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(44), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-downlinkUEAssociatedLPPaTransport"}}}
}

type DownlinkNonUEAssociatedLPPaTransportDescriptor struct{}

func DownlinkNonUEAssociatedLPPaTransportProcedure() DownlinkNonUEAssociatedLPPaTransportDescriptor {
	return DownlinkNonUEAssociatedLPPaTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for DownlinkNonUEAssociatedLPPaTransportDescriptor.
func (DownlinkNonUEAssociatedLPPaTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(46), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-downlinkNonUEAssociatedLPPaTransport"}}}
}

type ERABModificationIndicationDescriptor struct{}

func ERABModificationIndicationProcedure() ERABModificationIndicationDescriptor {
	return ERABModificationIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for ERABModificationIndicationDescriptor.
func (ERABModificationIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(50), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-E-RABModificationIndication"}}}
}

type ConnectionEstablishmentIndicationDescriptor struct{}

func ConnectionEstablishmentIndicationProcedure() ConnectionEstablishmentIndicationDescriptor {
	return ConnectionEstablishmentIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for ConnectionEstablishmentIndicationDescriptor.
func (ConnectionEstablishmentIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(54), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-ConnectionEstablishmentIndication"}}}
}

type NASDeliveryIndicationDescriptor struct{}

func NASDeliveryIndicationProcedure() NASDeliveryIndicationDescriptor {
	return NASDeliveryIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for NASDeliveryIndicationDescriptor.
func (NASDeliveryIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(57), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-NASDeliveryIndication"}}}
}

type ENBCPRelocationIndicationDescriptor struct{}

func ENBCPRelocationIndicationProcedure() ENBCPRelocationIndicationDescriptor {
	return ENBCPRelocationIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for ENBCPRelocationIndicationDescriptor.
func (ENBCPRelocationIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(60), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-eNBCPRelocationIndication"}}}
}

type MMECPRelocationIndicationDescriptor struct{}

func MMECPRelocationIndicationProcedure() MMECPRelocationIndicationDescriptor {
	return MMECPRelocationIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for MMECPRelocationIndicationDescriptor.
func (MMECPRelocationIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(61), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMECPRelocationIndication"}}}
}

type HandoverSuccessDescriptor struct{}

func HandoverSuccessProcedure() HandoverSuccessDescriptor { return HandoverSuccessDescriptor{} }

// Info returns the source-derived procedure metadata for HandoverSuccessDescriptor.
func (HandoverSuccessDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(64), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-HandoverSuccess"}}}
}

type ENBEarlyStatusTransferDescriptor struct{}

func ENBEarlyStatusTransferProcedure() ENBEarlyStatusTransferDescriptor {
	return ENBEarlyStatusTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for ENBEarlyStatusTransferDescriptor.
func (ENBEarlyStatusTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(65), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-eNBEarlyStatusTransfer"}}}
}

type MMEEarlyStatusTransferDescriptor struct{}

func MMEEarlyStatusTransferProcedure() MMEEarlyStatusTransferDescriptor {
	return MMEEarlyStatusTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for MMEEarlyStatusTransferDescriptor.
func (MMEEarlyStatusTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(66), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMEEarlyStatusTransfer"}}}
}

type ENBConfigurationTransferIETable struct{}

func ENBConfigurationTransferIEs() ENBConfigurationTransferIETable {
	return ENBConfigurationTransferIETable{}
}

// ID returns the ASN.1 object-set identity of ENBConfigurationTransferIETable.
func (ENBConfigurationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBConfigurationTransferIETable.
func (ENBConfigurationTransferIETable) Table() s00.ENBConfigurationTransferIEValueIETable {
	return func() s00.ENBConfigurationTransferIEValueIETable {
		sealed := s00.ENBConfigurationTransferIEValueIETable{}
		*s00.BridgeENBConfigurationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBConfigurationTransferIETable) infoSONConfigurationTransferECT() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(129), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationTransferIEs", Row: "id-SONConfigurationTransferECT"}}}
}

// SONConfigurationTransferECT returns the typed binding for the SONConfigurationTransferECT row of ENBConfigurationTransferIETable.
func (t ENBConfigurationTransferIETable) SONConfigurationTransferECT() ENBConfigurationTransferSONConfigurationTransferIEBinding {
	return ENBConfigurationTransferSONConfigurationTransferIEBinding{info: t.infoSONConfigurationTransferECT(), codec: func() s64.SONConfigurationTransferValueCodec {
		sealed := s64.SONConfigurationTransferValueCodec{}
		*s64.BridgeSONConfigurationTransferValueCodecFieldPath(&sealed) = "SONConfigurationTransfer"
		*s64.BridgeSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.SONConfigurationTransfer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s64.SONConfigurationTransfer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SONConfigurationTransfer")
			var zero s64.ENBConfigurationTransferIEValue
			decoded, err := s64.BridgeENBConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(129), raw)
			if err != nil {
				var empty s64.SONConfigurationTransfer
				return empty, runtime.WrapDecodePath(err, "SONConfigurationTransfer")
			}
			value, ok := decoded.AsSONConfigurationTransferECT()
			if !ok {
				var empty s64.SONConfigurationTransfer
				return empty, fmt.Errorf("binding ENBConfigurationTransferIEs.id-SONConfigurationTransferECT: no selected value")
			}
			return *value, nil
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s64.SONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s64.BridgeENBConfigurationTransferIEValueMethodEncodeFresh((func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(129)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowSONConfigurationTransferECT(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s64.SONConfigurationTransfer, options aper.DecodeState) (s64.SONConfigurationTransfer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s64.BridgeCaptureS1APSONConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s64.SONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s64.BridgeCompareS1APSONConfigurationTransfer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s64.SONConfigurationTransfer) s64.ENBConfigurationTransferIEValue {
			return func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(129)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowSONConfigurationTransferECT(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s64.ENBConfigurationTransferIEValue) (*s64.SONConfigurationTransfer, bool) {
			return value.AsSONConfigurationTransferECT()
		}}
}
func (ENBConfigurationTransferIETable) infoENDCSONConfigurationTransferECT() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(294), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCSONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationTransferIEs", Row: "id-EN-DCSONConfigurationTransfer-ECT"}}}
}

// ENDCSONConfigurationTransferECT returns the typed binding for the ENDCSONConfigurationTransferECT row of ENBConfigurationTransferIETable.
func (t ENBConfigurationTransferIETable) ENDCSONConfigurationTransferECT() s64.ENBConfigurationTransferENDCSONConfigurationTransferIEBinding {
	return func() s64.ENBConfigurationTransferENDCSONConfigurationTransferIEBinding {
		sealed := s64.ENBConfigurationTransferENDCSONConfigurationTransferIEBinding{}
		*s64.BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInfo(&sealed) = t.infoENDCSONConfigurationTransferECT()
		*s64.BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldCodec(&sealed) = func() s64.ENDCSONConfigurationTransferValueCodec {
			sealed := s64.ENDCSONConfigurationTransferValueCodec{}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldPath(&sealed) = "ENDCSONConfigurationTransfer"
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENDCSONConfigurationTransfer, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENDCSONConfigurationTransfer")
				var zero s64.ENBConfigurationTransferIEValue
				decoded, err := s64.BridgeENBConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(294), raw)
				if err != nil {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransfer")
				}
				value, ok := decoded.AsENDCSONConfigurationTransferECT()
				if !ok {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, fmt.Errorf("binding ENBConfigurationTransferIEs.id-EN-DCSONConfigurationTransfer-ECT: no selected value")
				}
				return *value, nil
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s64.ENDCSONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s64.BridgeENBConfigurationTransferIEValueMethodEncodeFresh((func() s64.ENBConfigurationTransferIEValue {
					sealed := s64.ENBConfigurationTransferIEValue{}
					*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(294)
					*s64.BridgeENBConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferECT(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s64.ENDCSONConfigurationTransfer, options aper.DecodeState) (s64.ENDCSONConfigurationTransfer, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s64.BridgeCaptureS1APENDCSONConfigurationTransfer(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s64.ENDCSONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.
					Begin()
				s64.BridgeCompareS1APENDCSONConfigurationTransfer(&v, &s)
				s.End(
					f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCSONConfigurationTransfer"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s64.BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInject(&sealed) = func(value s64.ENDCSONConfigurationTransfer) s64.ENBConfigurationTransferIEValue {
			return func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(294)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferECT(&sealed) = &value
				return sealed
			}()
		}
		*s64.BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldGet(&sealed) = func(value *s64.ENBConfigurationTransferIEValue) (*s64.ENDCSONConfigurationTransfer, bool) {
			return value.AsENDCSONConfigurationTransferECT()
		}
		return sealed
	}()
}
func (ENBConfigurationTransferIETable) infoIntersystemSONConfigurationTransferECT() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(310), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IntersystemSONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationTransferIEs", Row: "id-IntersystemSONConfigurationTransferECT"}}}
}

// IntersystemSONConfigurationTransferECT returns the typed binding for the IntersystemSONConfigurationTransferECT row of ENBConfigurationTransferIETable.
func (t ENBConfigurationTransferIETable) IntersystemSONConfigurationTransferECT() s64.ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding {
	return func() s64.ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding {
		sealed := s64.ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding{}
		*s64.BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInfo(&sealed) = t.infoIntersystemSONConfigurationTransferECT()
		*s64.BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldCodec(&sealed) = func() s01.IntersystemSONConfigurationTransferValueCodec {
			sealed := s01.IntersystemSONConfigurationTransferValueCodec{}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldPath(&sealed) = "IntersystemSONConfigurationTransfer"
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("IntersystemSONConfigurationTransfer")
				var zero s64.ENBConfigurationTransferIEValue
				decoded, err := s64.BridgeENBConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(310), raw)
				if err != nil {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, runtime.WrapDecodePath(err, "IntersystemSONConfigurationTransfer")
				}
				value, ok := decoded.AsIntersystemSONConfigurationTransferECT()
				if !ok {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, fmt.Errorf("binding ENBConfigurationTransferIEs.id-IntersystemSONConfigurationTransferECT: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s00.IntersystemSONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s64.BridgeENBConfigurationTransferIEValueMethodEncodeFresh((func() s64.ENBConfigurationTransferIEValue {
					sealed := s64.ENBConfigurationTransferIEValue{}
					*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(310)
					*s64.BridgeENBConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferECT(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s00.IntersystemSONConfigurationTransfer, options aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APIntersystemSONConfigurationTransfer(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s00.IntersystemSONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APIntersystemSONConfigurationTransfer(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntersystemSONConfigurationTransfer"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s64.BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInject(&sealed) = func(value s00.IntersystemSONConfigurationTransfer) s64.ENBConfigurationTransferIEValue {
			return func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(310)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferECT(&sealed) = &value
				return sealed
			}()
		}
		*s64.BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldGet(&sealed) = func(value *s64.ENBConfigurationTransferIEValue) (*s00.IntersystemSONConfigurationTransfer, bool) {
			return value.AsIntersystemSONConfigurationTransferECT()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBConfigurationTransferIETable.
func (t ENBConfigurationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s64.ENBConfigurationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(129):
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-SONConfigurationTransferECT requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(294):
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-EN-DCSONConfigurationTransfer-ECT requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(310):
		return s64.ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-IntersystemSONConfigurationTransferECT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s64.ENBConfigurationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s64.ENBConfigurationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return s64.ENBConfigurationTransferIEField{Id: id, Criticality: criticality, Value: func() s64.ENBConfigurationTransferIEValue {
			sealed := s64.ENBConfigurationTransferIEValue{}
			*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = id
			*s64.BridgeENBConfigurationTransferIEValueFieldOpaque(&sealed) = opaque
			*s64.BridgeENBConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type MMEConfigurationTransferIETable struct{}

func MMEConfigurationTransferIEs() MMEConfigurationTransferIETable {
	return MMEConfigurationTransferIETable{}
}

// ID returns the ASN.1 object-set identity of MMEConfigurationTransferIETable.
func (MMEConfigurationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEConfigurationTransferIETable.
func (MMEConfigurationTransferIETable) Table() s00.MMEConfigurationTransferIEValueIETable {
	return func() s00.MMEConfigurationTransferIEValueIETable {
		sealed := s00.MMEConfigurationTransferIEValueIETable{}
		*s00.BridgeMMEConfigurationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEConfigurationTransferIETable) infoSONConfigurationTransferMCT() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(130), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationTransferIEs", Row: "id-SONConfigurationTransferMCT"}}}
}

// SONConfigurationTransferMCT returns the typed binding for the SONConfigurationTransferMCT row of MMEConfigurationTransferIETable.
func (t MMEConfigurationTransferIETable) SONConfigurationTransferMCT() MMEConfigurationTransferSONConfigurationTransferIEBinding {
	return MMEConfigurationTransferSONConfigurationTransferIEBinding{info: t.infoSONConfigurationTransferMCT(), codec: func() s64.SONConfigurationTransferValueCodec {
		sealed := s64.SONConfigurationTransferValueCodec{}
		*s64.BridgeSONConfigurationTransferValueCodecFieldPath(&sealed) = "SONConfigurationTransfer"
		*s64.BridgeSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.SONConfigurationTransfer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s64.SONConfigurationTransfer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SONConfigurationTransfer")
			var zero s64.MMEConfigurationTransferIEValue
			decoded, err := s64.BridgeMMEConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(130), raw)
			if err != nil {
				var empty s64.SONConfigurationTransfer
				return empty, runtime.WrapDecodePath(err, "SONConfigurationTransfer")
			}
			value, ok := decoded.AsSONConfigurationTransferMCT()
			if !ok {
				var empty s64.SONConfigurationTransfer
				return empty, fmt.Errorf("binding MMEConfigurationTransferIEs.id-SONConfigurationTransferMCT: no selected value")
			}
			return *value, nil
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s64.SONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s64.BridgeMMEConfigurationTransferIEValueMethodEncodeFresh((func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(130)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowSONConfigurationTransferMCT(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s64.SONConfigurationTransfer, options aper.DecodeState) (s64.SONConfigurationTransfer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s64.BridgeCaptureS1APSONConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s64.SONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s64.BridgeCompareS1APSONConfigurationTransfer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s64.SONConfigurationTransfer) s64.MMEConfigurationTransferIEValue {
			return func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(130)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowSONConfigurationTransferMCT(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s64.MMEConfigurationTransferIEValue) (*s64.SONConfigurationTransfer, bool) {
			return value.AsSONConfigurationTransferMCT()
		}}
}
func (MMEConfigurationTransferIETable) infoENDCSONConfigurationTransferMCT() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(295), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EN-DCSONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationTransferIEs", Row: "id-EN-DCSONConfigurationTransfer-MCT"}}}
}

// ENDCSONConfigurationTransferMCT returns the typed binding for the ENDCSONConfigurationTransferMCT row of MMEConfigurationTransferIETable.
func (t MMEConfigurationTransferIETable) ENDCSONConfigurationTransferMCT() s64.MMEConfigurationTransferENDCSONConfigurationTransferIEBinding {
	return func() s64.MMEConfigurationTransferENDCSONConfigurationTransferIEBinding {
		sealed := s64.MMEConfigurationTransferENDCSONConfigurationTransferIEBinding{}
		*s64.BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInfo(&sealed) = t.infoENDCSONConfigurationTransferMCT()
		*s64.BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldCodec(&sealed) = func() s64.ENDCSONConfigurationTransferValueCodec {
			sealed := s64.ENDCSONConfigurationTransferValueCodec{}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldPath(&sealed) = "ENDCSONConfigurationTransfer"
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.ENDCSONConfigurationTransfer, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENDCSONConfigurationTransfer")
				var zero s64.MMEConfigurationTransferIEValue
				decoded, err := s64.BridgeMMEConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(295), raw)
				if err != nil {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransfer")
				}
				value, ok := decoded.AsENDCSONConfigurationTransferMCT()
				if !ok {
					var empty s64.ENDCSONConfigurationTransfer
					return empty, fmt.Errorf("binding MMEConfigurationTransferIEs.id-EN-DCSONConfigurationTransfer-MCT: no selected value")
				}
				return *value, nil
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s64.ENDCSONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s64.BridgeMMEConfigurationTransferIEValueMethodEncodeFresh((func() s64.MMEConfigurationTransferIEValue {
					sealed := s64.MMEConfigurationTransferIEValue{}
					*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(295)
					*s64.BridgeMMEConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferMCT(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s64.ENDCSONConfigurationTransfer, options aper.DecodeState) (s64.ENDCSONConfigurationTransfer, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s64.BridgeCaptureS1APENDCSONConfigurationTransfer(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s64.ENDCSONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.
					Begin()
				s64.BridgeCompareS1APENDCSONConfigurationTransfer(&v, &s)
				s.End(
					f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s64.BridgeENDCSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENDCSONConfigurationTransfer"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s64.BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInject(&sealed) = func(value s64.ENDCSONConfigurationTransfer) s64.MMEConfigurationTransferIEValue {
			return func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(295)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferMCT(&sealed) = &value
				return sealed
			}()
		}
		*s64.BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldGet(&sealed) = func(value *s64.MMEConfigurationTransferIEValue) (*s64.ENDCSONConfigurationTransfer, bool) {
			return value.AsENDCSONConfigurationTransferMCT()
		}
		return sealed
	}()
}
func (MMEConfigurationTransferIETable) infoIntersystemSONConfigurationTransferMCT() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEConfigurationTransferIEs().ID(), ID: s00.ProtocolIEID(309), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IntersystemSONConfigurationTransfer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationTransferIEs", Row: "id-IntersystemSONConfigurationTransferMCT"}}}
}

// IntersystemSONConfigurationTransferMCT returns the typed binding for the IntersystemSONConfigurationTransferMCT row of MMEConfigurationTransferIETable.
func (t MMEConfigurationTransferIETable) IntersystemSONConfigurationTransferMCT() s64.MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding {
	return func() s64.MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding {
		sealed := s64.MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding{}
		*s64.BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInfo(&sealed) = t.infoIntersystemSONConfigurationTransferMCT()
		*s64.BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldCodec(&sealed) = func() s01.IntersystemSONConfigurationTransferValueCodec {
			sealed := s01.IntersystemSONConfigurationTransferValueCodec{}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldPath(&sealed) = "IntersystemSONConfigurationTransfer"
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("IntersystemSONConfigurationTransfer")
				var zero s64.MMEConfigurationTransferIEValue
				decoded, err := s64.BridgeMMEConfigurationTransferIEValueMethodDecode(zero, s00.ProtocolIEID(309), raw)
				if err != nil {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, runtime.WrapDecodePath(err, "IntersystemSONConfigurationTransfer")
				}
				value, ok := decoded.AsIntersystemSONConfigurationTransferMCT()
				if !ok {
					var empty s00.IntersystemSONConfigurationTransfer
					return empty, fmt.Errorf("binding MMEConfigurationTransferIEs.id-IntersystemSONConfigurationTransferMCT: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldEncode(&sealed) = func(value s00.IntersystemSONConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s64.BridgeMMEConfigurationTransferIEValueMethodEncodeFresh((func() s64.MMEConfigurationTransferIEValue {
					sealed := s64.MMEConfigurationTransferIEValue{}
					*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(309)
					*s64.BridgeMMEConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferMCT(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldCapture(&sealed) = func(v s00.IntersystemSONConfigurationTransfer, options aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APIntersystemSONConfigurationTransfer(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldCompare(&sealed) = func(v s00.IntersystemSONConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APIntersystemSONConfigurationTransfer(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntersystemSONConfigurationTransfer"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s64.BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInject(&sealed) = func(value s00.IntersystemSONConfigurationTransfer) s64.MMEConfigurationTransferIEValue {
			return func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(309)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferMCT(&sealed) = &value
				return sealed
			}()
		}
		*s64.BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldGet(&sealed) = func(value *s64.MMEConfigurationTransferIEValue) (*s00.IntersystemSONConfigurationTransfer, bool) {
			return value.AsIntersystemSONConfigurationTransferMCT()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEConfigurationTransferIETable.
func (t MMEConfigurationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s64.MMEConfigurationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(130):
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-SONConfigurationTransferMCT requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(295):
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-EN-DCSONConfigurationTransfer-MCT requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(309):
		return s64.MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-IntersystemSONConfigurationTransferMCT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s64.MMEConfigurationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s64.MMEConfigurationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return s64.MMEConfigurationTransferIEField{Id: id, Criticality: criticality, Value: func() s64.MMEConfigurationTransferIEValue {
			sealed := s64.MMEConfigurationTransferIEValue{}
			*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = id
			*s64.BridgeMMEConfigurationTransferIEValueFieldOpaque(&sealed) = opaque
			*s64.BridgeMMEConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// CellTrafficTraceCodec binds the complete APER value type.
func CellTrafficTraceCodec() s25.CellTrafficTraceValueCodec {
	return CellTrafficTraceProcedure().Initiating().Codec()
}

// ConnectionEstablishmentIndicationCodec binds the complete APER value type.
func ConnectionEstablishmentIndicationCodec() s40.ConnectionEstablishmentIndicationValueCodec {
	return ConnectionEstablishmentIndicationProcedure().Initiating().Codec()
}

// DeactivateTraceCodec binds the complete APER value type.
func DeactivateTraceCodec() s18.DeactivateTraceValueCodec {
	return DeactivateTraceProcedure().Initiating().Codec()
}

// DownlinkNASTransportCodec binds the complete APER value type.
func DownlinkNASTransportCodec() s53.DownlinkNASTransportValueCodec {
	return DownlinkNASTransportProcedure().Initiating().Codec()
}

// DownlinkNonUEAssociatedLPPaTransportCodec binds the complete APER value type.
func DownlinkNonUEAssociatedLPPaTransportCodec() s18.DownlinkNonUEAssociatedLPPaTransportValueCodec {
	return DownlinkNonUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// DownlinkS1cdma2000tunnellingCodec binds the complete APER value type.
func DownlinkS1cdma2000tunnellingCodec() s50.DownlinkS1cdma2000tunnellingValueCodec {
	return DownlinkS1cdma2000tunnellingProcedure().Initiating().Codec()
}

// DownlinkUEAssociatedLPPaTransportCodec binds the complete APER value type.
func DownlinkUEAssociatedLPPaTransportCodec() s18.DownlinkUEAssociatedLPPaTransportValueCodec {
	return DownlinkUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// ENBCPRelocationIndicationCodec binds the complete APER value type.
func ENBCPRelocationIndicationCodec() s47.ENBCPRelocationIndicationValueCodec {
	return ENBCPRelocationIndicationProcedure().Initiating().Codec()
}

// ENBConfigurationUpdateAcknowledgeCodec binds the complete APER value type.
func ENBConfigurationUpdateAcknowledgeCodec() s28.ENBConfigurationUpdateAcknowledgeValueCodec {
	return ENBConfigurationUpdateProcedure().Successful().Codec()
}

// ENBConfigurationUpdateCodec binds the complete APER value type.
func ENBConfigurationUpdateCodec() s54.ENBConfigurationUpdateValueCodec {
	return ENBConfigurationUpdateProcedure().Initiating().Codec()
}

// ENBConfigurationUpdateFailureCodec binds the complete APER value type.
func ENBConfigurationUpdateFailureCodec() s28.ENBConfigurationUpdateFailureValueCodec {
	return ENBConfigurationUpdateProcedure().Unsuccessful().Codec()
}

// ENBDirectInformationTransferCodec binds the complete APER value type.
func ENBDirectInformationTransferCodec() s43.ENBDirectInformationTransferValueCodec {
	return ENBDirectInformationTransferProcedure().Initiating().Codec()
}

// ENBEarlyStatusTransferCodec binds the complete APER value type.
func ENBEarlyStatusTransferCodec() s47.ENBEarlyStatusTransferValueCodec {
	return ENBEarlyStatusTransferProcedure().Initiating().Codec()
}

// ENBStatusTransferCodec binds the complete APER value type.
func ENBStatusTransferCodec() s28.ENBStatusTransferValueCodec {
	return ENBStatusTransferProcedure().Initiating().Codec()
}

// ENDCSONConfigurationTransferCodec binds the complete APER value type.
func ENDCSONConfigurationTransferCodec() s64.ENDCSONConfigurationTransferValueCodec {
	return ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Codec()
}

// ERABModificationConfirmCodec binds the complete APER value type.
func ERABModificationConfirmCodec() s49.ERABModificationConfirmValueCodec {
	return ERABModificationIndicationProcedure().Successful().Codec()
}

// ERABModificationIndicationCodec binds the complete APER value type.
func ERABModificationIndicationCodec() s57.ERABModificationIndicationValueCodec {
	return ERABModificationIndicationProcedure().Initiating().Codec()
}

// ERABModifyRequestCodec binds the complete APER value type.
func ERABModifyRequestCodec() s51.ERABModifyRequestValueCodec {
	return ERABModifyProcedure().Initiating().Codec()
}

// ERABModifyResponseCodec binds the complete APER value type.
func ERABModifyResponseCodec() s57.ERABModifyResponseValueCodec {
	return ERABModifyProcedure().Successful().Codec()
}

// ERABReleaseCommandCodec binds the complete APER value type.
func ERABReleaseCommandCodec() s49.ERABReleaseCommandValueCodec {
	return ERABReleaseProcedure().Initiating().Codec()
}

// ERABReleaseIndicationCodec binds the complete APER value type.
func ERABReleaseIndicationCodec() s57.ERABReleaseIndicationValueCodec {
	return ERABReleaseIndicationProcedure().Initiating().Codec()
}

// ERABReleaseResponseCodec binds the complete APER value type.
func ERABReleaseResponseCodec() s57.ERABReleaseResponseValueCodec {
	return ERABReleaseProcedure().Successful().Codec()
}

// ERABSetupRequestCodec binds the complete APER value type.
func ERABSetupRequestCodec() s51.ERABSetupRequestValueCodec {
	return ERABSetupProcedure().Initiating().Codec()
}

// ERABSetupResponseCodec binds the complete APER value type.
func ERABSetupResponseCodec() s57.ERABSetupResponseValueCodec {
	return ERABSetupProcedure().Successful().Codec()
}

// ErrorIndicationCodec binds the complete APER value type.
func ErrorIndicationCodec() s36.ErrorIndicationValueCodec {
	return ErrorIndicationProcedure().Initiating().Codec()
}

// HandoverCancelAcknowledgeCodec binds the complete APER value type.
func HandoverCancelAcknowledgeCodec() s29.HandoverCancelAcknowledgeValueCodec {
	return HandoverCancelProcedure().Successful().Codec()
}

// HandoverCancelCodec binds the complete APER value type.
func HandoverCancelCodec() s29.HandoverCancelValueCodec {
	return HandoverCancelProcedure().Initiating().Codec()
}

// HandoverCommandCodec binds the complete APER value type.
func HandoverCommandCodec() s50.HandoverCommandValueCodec {
	return HandoverPreparationProcedure().Successful().Codec()
}

// HandoverFailureCodec binds the complete APER value type.
func HandoverFailureCodec() s29.HandoverFailureValueCodec {
	return HandoverResourceAllocationProcedure().Unsuccessful().Codec()
}

// HandoverNotifyCodec binds the complete APER value type.
func HandoverNotifyCodec() s45.HandoverNotifyValueCodec {
	return HandoverNotificationProcedure().Initiating().Codec()
}

// HandoverPreparationFailureCodec binds the complete APER value type.
func HandoverPreparationFailureCodec() s29.HandoverPreparationFailureValueCodec {
	return HandoverPreparationProcedure().Unsuccessful().Codec()
}

// HandoverRequestAcknowledgeCodec binds the complete APER value type.
func HandoverRequestAcknowledgeCodec() s49.HandoverRequestAcknowledgeValueCodec {
	return HandoverResourceAllocationProcedure().Successful().Codec()
}

// HandoverRequestCodec binds the complete APER value type.
func HandoverRequestCodec() s60.HandoverRequestValueCodec {
	return HandoverResourceAllocationProcedure().Initiating().Codec()
}

// HandoverRequiredCodec binds the complete APER value type.
func HandoverRequiredCodec() s43.HandoverRequiredValueCodec {
	return HandoverPreparationProcedure().Initiating().Codec()
}

// HandoverSuccessCodec binds the complete APER value type.
func HandoverSuccessCodec() s21.HandoverSuccessValueCodec {
	return HandoverSuccessProcedure().Initiating().Codec()
}

// InitialContextSetupFailureCodec binds the complete APER value type.
func InitialContextSetupFailureCodec() s30.InitialContextSetupFailureValueCodec {
	return InitialContextSetupProcedure().Unsuccessful().Codec()
}

// InitialContextSetupRequestCodec binds the complete APER value type.
func InitialContextSetupRequestCodec() s60.InitialContextSetupRequestValueCodec {
	return InitialContextSetupProcedure().Initiating().Codec()
}

// InitialContextSetupResponseCodec binds the complete APER value type.
func InitialContextSetupResponseCodec() s50.InitialContextSetupResponseValueCodec {
	return InitialContextSetupProcedure().Successful().Codec()
}

// InitialUEMessageCodec binds the complete APER value type.
func InitialUEMessageCodec() s45.InitialUEMessageValueCodec {
	return InitialUEMessageProcedure().Initiating().Codec()
}

// InitiatingMessageCodec binds the complete source value type.
func InitiatingMessageCodec() InitiatingMessageValueCodec {
	return InitiatingMessageValueCodec{path: "InitiatingMessage", decode: func(data []byte, options aper.DecodeState) (InitiatingMessage, error) {
		var value InitiatingMessage
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InitiatingMessage{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InitiatingMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InitiatingMessage, options aper.DecodeState) (InitiatingMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APInitiatingMessage(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v InitiatingMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APInitiatingMessage(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitiatingMessage"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// IntersystemSONConfigurationTransferCodec binds the complete APER value type.
func IntersystemSONConfigurationTransferCodec() s01.IntersystemSONConfigurationTransferValueCodec {
	return ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Codec()
}

// KillRequestCodec binds the complete APER value type.
func KillRequestCodec() s42.KillRequestValueCodec { return KillProcedure().Initiating().Codec() }

// KillResponseCodec binds the complete APER value type.
func KillResponseCodec() s42.KillResponseValueCodec { return KillProcedure().Successful().Codec() }

// LocationReportCodec binds the complete APER value type.
func LocationReportCodec() s42.LocationReportValueCodec {
	return LocationReportProcedure().Initiating().Codec()
}

// LocationReportingControlCodec binds the complete APER value type.
func LocationReportingControlCodec() s31.LocationReportingControlValueCodec {
	return LocationReportingControlProcedure().Initiating().Codec()
}

// LocationReportingFailureIndicationCodec binds the complete APER value type.
func LocationReportingFailureIndicationCodec() s30.LocationReportingFailureIndicationValueCodec {
	return LocationReportingFailureIndicationProcedure().Initiating().Codec()
}

// MMECPRelocationIndicationCodec binds the complete APER value type.
func MMECPRelocationIndicationCodec() s22.MMECPRelocationIndicationValueCodec {
	return MMECPRelocationIndicationProcedure().Initiating().Codec()
}

// MMEConfigurationUpdateAcknowledgeCodec binds the complete APER value type.
func MMEConfigurationUpdateAcknowledgeCodec() s30.MMEConfigurationUpdateAcknowledgeValueCodec {
	return MMEConfigurationUpdateProcedure().Successful().Codec()
}

// MMEConfigurationUpdateCodec binds the complete APER value type.
func MMEConfigurationUpdateCodec() s54.MMEConfigurationUpdateValueCodec {
	return MMEConfigurationUpdateProcedure().Initiating().Codec()
}

// MMEConfigurationUpdateFailureCodec binds the complete APER value type.
func MMEConfigurationUpdateFailureCodec() s30.MMEConfigurationUpdateFailureValueCodec {
	return MMEConfigurationUpdateProcedure().Unsuccessful().Codec()
}

// MMEDirectInformationTransferCodec binds the complete APER value type.
func MMEDirectInformationTransferCodec() s43.MMEDirectInformationTransferValueCodec {
	return MMEDirectInformationTransferProcedure().Initiating().Codec()
}

// MMEEarlyStatusTransferCodec binds the complete APER value type.
func MMEEarlyStatusTransferCodec() s48.MMEEarlyStatusTransferValueCodec {
	return MMEEarlyStatusTransferProcedure().Initiating().Codec()
}

// MMEStatusTransferCodec binds the complete APER value type.
func MMEStatusTransferCodec() s30.MMEStatusTransferValueCodec {
	return MMEStatusTransferProcedure().Initiating().Codec()
}

// NASDeliveryIndicationCodec binds the complete APER value type.
func NASDeliveryIndicationCodec() s22.NASDeliveryIndicationValueCodec {
	return NASDeliveryIndicationProcedure().Initiating().Codec()
}

// NASNonDeliveryIndicationCodec binds the complete APER value type.
func NASNonDeliveryIndicationCodec() s30.NASNonDeliveryIndicationValueCodec {
	return NASNonDeliveryIndicationProcedure().Initiating().Codec()
}

// SONConfigurationTransferCodec binds the complete APER value type.
func SONConfigurationTransferCodec() s64.SONConfigurationTransferValueCodec {
	return ENBConfigurationTransferIEs().SONConfigurationTransferECT().Codec()
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeValidateS1APIEContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolIEContainer[V], rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeValidateS1APExtensionContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolExtensionContainer[V], rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ProtocolIEField[V]](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(ProtocolIEContainer[V], len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeENBConfigurationTransferFieldReceived(v *ENBConfigurationTransfer) *bool {
	return &v.received
}
func BridgeENBConfigurationTransferFieldReceivedAbsolute(v *ENBConfigurationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationTransferFieldReceivedBytes(v *ENBConfigurationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationTransferInitiatingBindingFieldCapture(v *ENBConfigurationTransferInitiatingBinding) *func(ENBConfigurationTransfer, aper.DecodeState) (ENBConfigurationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferInitiatingBindingFieldCompare(v *ENBConfigurationTransferInitiatingBinding) *func(ENBConfigurationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferInitiatingBindingFieldContext(v *ENBConfigurationTransferInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferInitiatingBindingFieldDecode(v *ENBConfigurationTransferInitiatingBinding) *func([]byte, aper.DecodeState) (ENBConfigurationTransfer, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferInitiatingBindingFieldEncode(v *ENBConfigurationTransferInitiatingBinding) *func(*ENBConfigurationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferInitiatingBindingFieldInfo(v *ENBConfigurationTransferInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeENBConfigurationTransferInitiatingBindingFieldInject(v *ENBConfigurationTransferInitiatingBinding) *func(ENBConfigurationTransfer) InitiatingValue {
	return &v.inject
}
func BridgeENBConfigurationTransferInitiatingBindingFieldValidate(v *ENBConfigurationTransferInitiatingBinding) *func(*ENBConfigurationTransfer, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeENBConfigurationTransferMethodMarshalAPERBudget(v *ENBConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationTransferMethodUnmarshalAPERWithOptions(v *ENBConfigurationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERBudget(v *InitiatingMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERTo(v *InitiatingMessage, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitiatingMessageMethodUnmarshalAPERFrom(v *InitiatingMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitiatingValueFieldBodyCellTrafficTrace(v *InitiatingValue) **s25.CellTrafficTrace {
	return &v.bodyCellTrafficTrace
}
func BridgeInitiatingValueFieldBodyConnectionEstablishmentIndication(v *InitiatingValue) **s40.ConnectionEstablishmentIndication {
	return &v.bodyConnectionEstablishmentIndication
}
func BridgeInitiatingValueFieldBodyDeactivateTrace(v *InitiatingValue) **s18.DeactivateTrace {
	return &v.bodyDeactivateTrace
}
func BridgeInitiatingValueFieldBodyDownlinkNASTransport(v *InitiatingValue) **s53.DownlinkNASTransport {
	return &v.bodyDownlinkNASTransport
}
func BridgeInitiatingValueFieldBodyDownlinkNonUEAssociatedLPPaTransport(v *InitiatingValue) **s18.DownlinkNonUEAssociatedLPPaTransport {
	return &v.bodyDownlinkNonUEAssociatedLPPaTransport
}
func BridgeInitiatingValueFieldBodyDownlinkS1cdma2000tunnelling(v *InitiatingValue) **s50.DownlinkS1cdma2000tunnelling {
	return &v.bodyDownlinkS1cdma2000tunnelling
}
func BridgeInitiatingValueFieldBodyDownlinkUEAssociatedLPPaTransport(v *InitiatingValue) **s18.DownlinkUEAssociatedLPPaTransport {
	return &v.bodyDownlinkUEAssociatedLPPaTransport
}
func BridgeInitiatingValueFieldBodyENBCPRelocationIndication(v *InitiatingValue) **s47.ENBCPRelocationIndication {
	return &v.bodyENBCPRelocationIndication
}
func BridgeInitiatingValueFieldBodyENBConfigurationTransfer(v *InitiatingValue) **ENBConfigurationTransfer {
	return &v.bodyENBConfigurationTransfer
}
func BridgeInitiatingValueFieldBodyENBConfigurationUpdate(v *InitiatingValue) **s54.ENBConfigurationUpdate {
	return &v.bodyENBConfigurationUpdate
}
func BridgeInitiatingValueFieldBodyENBDirectInformationTransfer(v *InitiatingValue) **s43.ENBDirectInformationTransfer {
	return &v.bodyENBDirectInformationTransfer
}
func BridgeInitiatingValueFieldBodyENBEarlyStatusTransfer(v *InitiatingValue) **s47.ENBEarlyStatusTransfer {
	return &v.bodyENBEarlyStatusTransfer
}
func BridgeInitiatingValueFieldBodyENBStatusTransfer(v *InitiatingValue) **s28.ENBStatusTransfer {
	return &v.bodyENBStatusTransfer
}
func BridgeInitiatingValueFieldBodyERABModificationIndication(v *InitiatingValue) **s57.ERABModificationIndication {
	return &v.bodyERABModificationIndication
}
func BridgeInitiatingValueFieldBodyERABModifyRequest(v *InitiatingValue) **s51.ERABModifyRequest {
	return &v.bodyERABModifyRequest
}
func BridgeInitiatingValueFieldBodyERABReleaseCommand(v *InitiatingValue) **s49.ERABReleaseCommand {
	return &v.bodyERABReleaseCommand
}
func BridgeInitiatingValueFieldBodyERABReleaseIndication(v *InitiatingValue) **s57.ERABReleaseIndication {
	return &v.bodyERABReleaseIndication
}
func BridgeInitiatingValueFieldBodyERABSetupRequest(v *InitiatingValue) **s51.ERABSetupRequest {
	return &v.bodyERABSetupRequest
}
func BridgeInitiatingValueFieldBodyErrorIndication(v *InitiatingValue) **s36.ErrorIndication {
	return &v.bodyErrorIndication
}
func BridgeInitiatingValueFieldBodyHandoverCancel(v *InitiatingValue) **s29.HandoverCancel {
	return &v.bodyHandoverCancel
}
func BridgeInitiatingValueFieldBodyHandoverNotify(v *InitiatingValue) **s44.HandoverNotify {
	return &v.bodyHandoverNotify
}
func BridgeInitiatingValueFieldBodyHandoverRequest(v *InitiatingValue) **s60.HandoverRequest {
	return &v.bodyHandoverRequest
}
func BridgeInitiatingValueFieldBodyHandoverRequired(v *InitiatingValue) **s43.HandoverRequired {
	return &v.bodyHandoverRequired
}
func BridgeInitiatingValueFieldBodyHandoverSuccess(v *InitiatingValue) **s21.HandoverSuccess {
	return &v.bodyHandoverSuccess
}
func BridgeInitiatingValueFieldBodyInitialContextSetupRequest(v *InitiatingValue) **s60.InitialContextSetupRequest {
	return &v.bodyInitialContextSetupRequest
}
func BridgeInitiatingValueFieldBodyInitialUEMessage(v *InitiatingValue) **s45.InitialUEMessage {
	return &v.bodyInitialUEMessage
}
func BridgeInitiatingValueFieldBodyKillRequest(v *InitiatingValue) **s42.KillRequest {
	return &v.bodyKillRequest
}
func BridgeInitiatingValueFieldBodyLocationReport(v *InitiatingValue) **s42.LocationReport {
	return &v.bodyLocationReport
}
func BridgeInitiatingValueFieldBodyLocationReportingControl(v *InitiatingValue) **s31.LocationReportingControl {
	return &v.bodyLocationReportingControl
}
func BridgeInitiatingValueFieldBodyLocationReportingFailureIndication(v *InitiatingValue) **s30.LocationReportingFailureIndication {
	return &v.bodyLocationReportingFailureIndication
}
func BridgeInitiatingValueFieldBodyMMECPRelocationIndication(v *InitiatingValue) **s22.MMECPRelocationIndication {
	return &v.bodyMMECPRelocationIndication
}
func BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(v *InitiatingValue) **MMEConfigurationTransfer {
	return &v.bodyMMEConfigurationTransfer
}
func BridgeInitiatingValueFieldBodyMMEConfigurationUpdate(v *InitiatingValue) **s54.MMEConfigurationUpdate {
	return &v.bodyMMEConfigurationUpdate
}
func BridgeInitiatingValueFieldBodyMMEDirectInformationTransfer(v *InitiatingValue) **s43.MMEDirectInformationTransfer {
	return &v.bodyMMEDirectInformationTransfer
}
func BridgeInitiatingValueFieldBodyMMEEarlyStatusTransfer(v *InitiatingValue) **s48.MMEEarlyStatusTransfer {
	return &v.bodyMMEEarlyStatusTransfer
}
func BridgeInitiatingValueFieldBodyMMEStatusTransfer(v *InitiatingValue) **s30.MMEStatusTransfer {
	return &v.bodyMMEStatusTransfer
}
func BridgeInitiatingValueFieldBodyNASDeliveryIndication(v *InitiatingValue) **s22.NASDeliveryIndication {
	return &v.bodyNASDeliveryIndication
}
func BridgeInitiatingValueFieldBodyNASNonDeliveryIndication(v *InitiatingValue) **s30.NASNonDeliveryIndication {
	return &v.bodyNASNonDeliveryIndication
}
func BridgeInitiatingValueFieldBodyOverloadStart(v *InitiatingValue) **s52.OverloadStart {
	return &v.bodyOverloadStart
}
func BridgeInitiatingValueFieldBodyOverloadStop(v *InitiatingValue) **s52.OverloadStop {
	return &v.bodyOverloadStop
}
func BridgeInitiatingValueFieldBodyPWSFailureIndication(v *InitiatingValue) **s52.PWSFailureIndication {
	return &v.bodyPWSFailureIndication
}
func BridgeInitiatingValueFieldBodyPWSRestartIndication(v *InitiatingValue) **s55.PWSRestartIndication {
	return &v.bodyPWSRestartIndication
}
func BridgeInitiatingValueFieldBodyPaging(v *InitiatingValue) **s61.Paging { return &v.bodyPaging }
func BridgeInitiatingValueFieldBodyPathSwitchRequest(v *InitiatingValue) **s51.PathSwitchRequest {
	return &v.bodyPathSwitchRequest
}
func BridgeInitiatingValueFieldBodyPrivateMessage(v *InitiatingValue) **s30.PrivateMessage {
	return &v.bodyPrivateMessage
}
func BridgeInitiatingValueFieldBodyRerouteNASRequest(v *InitiatingValue) **s31.RerouteNASRequest {
	return &v.bodyRerouteNASRequest
}
func BridgeInitiatingValueFieldBodyReset(v *InitiatingValue) **s45.Reset { return &v.bodyReset }
func BridgeInitiatingValueFieldBodyRetrieveUEInformation(v *InitiatingValue) **s36.RetrieveUEInformation {
	return &v.bodyRetrieveUEInformation
}
func BridgeInitiatingValueFieldBodyS1RemovalRequest(v *InitiatingValue) **s31.S1RemovalRequest {
	return &v.bodyS1RemovalRequest
}
func BridgeInitiatingValueFieldBodyS1SetupRequest(v *InitiatingValue) **s54.S1SetupRequest {
	return &v.bodyS1SetupRequest
}
func BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(v *InitiatingValue) **s57.SecondaryRATDataUsageReport {
	return &v.bodySecondaryRATDataUsageReport
}
func BridgeInitiatingValueFieldBodyTraceFailureIndication(v *InitiatingValue) **s44.TraceFailureIndication {
	return &v.bodyTraceFailureIndication
}
func BridgeInitiatingValueFieldBodyTraceStart(v *InitiatingValue) **s61.TraceStart {
	return &v.bodyTraceStart
}
func BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(v *InitiatingValue) **s45.UECapabilityInfoIndication {
	return &v.bodyUECapabilityInfoIndication
}
func BridgeInitiatingValueFieldBodyUEContextModificationIndication(v *InitiatingValue) **s46.UEContextModificationIndication {
	return &v.bodyUEContextModificationIndication
}
func BridgeInitiatingValueFieldBodyUEContextModificationRequest(v *InitiatingValue) **s58.UEContextModificationRequest {
	return &v.bodyUEContextModificationRequest
}
func BridgeInitiatingValueFieldBodyUEContextReleaseCommand(v *InitiatingValue) **s47.UEContextReleaseCommand {
	return &v.bodyUEContextReleaseCommand
}
func BridgeInitiatingValueFieldBodyUEContextReleaseRequest(v *InitiatingValue) **s53.UEContextReleaseRequest {
	return &v.bodyUEContextReleaseRequest
}
func BridgeInitiatingValueFieldBodyUEContextResumeRequest(v *InitiatingValue) **s48.UEContextResumeRequest {
	return &v.bodyUEContextResumeRequest
}
func BridgeInitiatingValueFieldBodyUEContextSuspendRequest(v *InitiatingValue) **s57.UEContextSuspendRequest {
	return &v.bodyUEContextSuspendRequest
}
func BridgeInitiatingValueFieldBodyUEInformationTransfer(v *InitiatingValue) **s46.UEInformationTransfer {
	return &v.bodyUEInformationTransfer
}
func BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(v *InitiatingValue) **s46.UERadioCapabilityIDMappingRequest {
	return &v.bodyUERadioCapabilityIDMappingRequest
}
func BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(v *InitiatingValue) **s46.UERadioCapabilityMatchRequest {
	return &v.bodyUERadioCapabilityMatchRequest
}
func BridgeInitiatingValueFieldBodyUplinkNASTransport(v *InitiatingValue) **s55.UplinkNASTransport {
	return &v.bodyUplinkNASTransport
}
func BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(v *InitiatingValue) **s55.UplinkNonUEAssociatedLPPaTransport {
	return &v.bodyUplinkNonUEAssociatedLPPaTransport
}
func BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(v *InitiatingValue) **s55.UplinkS1cdma2000tunnelling {
	return &v.bodyUplinkS1cdma2000tunnelling
}
func BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(v *InitiatingValue) **s55.UplinkUEAssociatedLPPaTransport {
	return &v.bodyUplinkUEAssociatedLPPaTransport
}
func BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(v *InitiatingValue) **s64.WriteReplaceWarningRequest {
	return &v.bodyWriteReplaceWarningRequest
}
func BridgeInitiatingValueFieldCode(v *InitiatingValue) *s00.ProcedureCode     { return &v.code }
func BridgeInitiatingValueFieldIsOpaque(v *InitiatingValue) *bool              { return &v.isOpaque }
func BridgeInitiatingValueFieldOpaque(v *InitiatingValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeMMEConfigurationTransferFieldReceived(v *MMEConfigurationTransfer) *bool {
	return &v.received
}
func BridgeMMEConfigurationTransferFieldReceivedAbsolute(v *MMEConfigurationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEConfigurationTransferFieldReceivedBytes(v *MMEConfigurationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldCapture(v *MMEConfigurationTransferInitiatingBinding) *func(MMEConfigurationTransfer, aper.DecodeState) (MMEConfigurationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldCompare(v *MMEConfigurationTransferInitiatingBinding) *func(MMEConfigurationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldContext(v *MMEConfigurationTransferInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldDecode(v *MMEConfigurationTransferInitiatingBinding) *func([]byte, aper.DecodeState) (MMEConfigurationTransfer, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldEncode(v *MMEConfigurationTransferInitiatingBinding) *func(*MMEConfigurationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldInfo(v *MMEConfigurationTransferInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldInject(v *MMEConfigurationTransferInitiatingBinding) *func(MMEConfigurationTransfer) InitiatingValue {
	return &v.inject
}
func BridgeMMEConfigurationTransferInitiatingBindingFieldValidate(v *MMEConfigurationTransferInitiatingBinding) *func(*MMEConfigurationTransfer, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v *MMEConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEConfigurationTransferMethodUnmarshalAPERWithOptions(v *MMEConfigurationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *InitiatingValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case 0:
		if value, ok := v.AsHandoverRequired(); ok {
			return value, true
		}
	case 1:
		if value, ok := v.AsHandoverRequest(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsHandoverNotify(); ok {
			return value, true
		}
	case 3:
		if value, ok := v.AsPathSwitchRequest(); ok {
			return value, true
		}
	case 4:
		if value, ok := v.AsHandoverCancel(); ok {
			return value, true
		}
	case 5:
		if value, ok := v.AsERABSetupRequest(); ok {
			return value, true
		}
	case 6:
		if value, ok := v.AsERABModifyRequest(); ok {
			return value, true
		}
	case 7:
		if value, ok := v.AsERABReleaseCommand(); ok {
			return value, true
		}
	case 8:
		if value, ok := v.AsERABReleaseIndication(); ok {
			return value, true
		}
	case 9:
		if value, ok := v.AsInitialContextSetupRequest(); ok {
			return value, true
		}
	case 10:
		if value, ok := v.AsPaging(); ok {
			return value, true
		}
	case 11:
		if value, ok := v.AsDownlinkNASTransport(); ok {
			return value, true
		}
	case 12:
		if value, ok := v.AsInitialUEMessage(); ok {
			return value, true
		}
	case 13:
		if value, ok := v.AsUplinkNASTransport(); ok {
			return value, true
		}
	case 14:
		if value, ok := v.AsReset(); ok {
			return value, true
		}
	case 15:
		if value, ok := v.AsErrorIndication(); ok {
			return value, true
		}
	case 16:
		if value, ok := v.AsNASNonDeliveryIndication(); ok {
			return value, true
		}
	case 17:
		if value, ok := v.AsS1SetupRequest(); ok {
			return value, true
		}
	case 18:
		if value, ok := v.AsUEContextReleaseRequest(); ok {
			return value, true
		}
	case 19:
		if value, ok := v.AsDownlinkS1cdma2000tunnelling(); ok {
			return value, true
		}
	case 20:
		if value, ok := v.AsUplinkS1cdma2000tunnelling(); ok {
			return value, true
		}
	case 21:
		if value, ok := v.AsUEContextModificationRequest(); ok {
			return value, true
		}
	case 22:
		if value, ok := v.AsUECapabilityInfoIndication(); ok {
			return value, true
		}
	case 23:
		if value, ok := v.AsUEContextReleaseCommand(); ok {
			return value, true
		}
	case 24:
		if value, ok := v.AsENBStatusTransfer(); ok {
			return value, true
		}
	case 25:
		if value, ok := v.AsMMEStatusTransfer(); ok {
			return value, true
		}
	case 26:
		if value, ok := v.AsDeactivateTrace(); ok {
			return value, true
		}
	case 27:
		if value, ok := v.AsTraceStart(); ok {
			return value, true
		}
	case 28:
		if value, ok := v.AsTraceFailureIndication(); ok {
			return value, true
		}
	case 29:
		if value, ok := v.AsENBConfigurationUpdate(); ok {
			return value, true
		}
	case 30:
		if value, ok := v.AsMMEConfigurationUpdate(); ok {
			return value, true
		}
	case 31:
		if value, ok := v.AsLocationReportingControl(); ok {
			return value, true
		}
	case 32:
		if value, ok := v.AsLocationReportingFailureIndication(); ok {
			return value, true
		}
	case 33:
		if value, ok := v.AsLocationReport(); ok {
			return value, true
		}
	case 34:
		if value, ok := v.AsOverloadStart(); ok {
			return value, true
		}
	case 35:
		if value, ok := v.AsOverloadStop(); ok {
			return value, true
		}
	case 36:
		if value, ok := v.AsWriteReplaceWarningRequest(); ok {
			return value, true
		}
	case 37:
		if value, ok := v.AsENBDirectInformationTransfer(); ok {
			return value, true
		}
	case 38:
		if value, ok := v.AsMMEDirectInformationTransfer(); ok {
			return value, true
		}
	case 39:
		if value, ok := v.AsPrivateMessage(); ok {
			return value, true
		}
	case 40:
		if value, ok := v.AsENBConfigurationTransfer(); ok {
			return value, true
		}
	case 41:
		if value, ok := v.AsMMEConfigurationTransfer(); ok {
			return value, true
		}
	case 42:
		if value, ok := v.AsCellTrafficTrace(); ok {
			return value, true
		}
	case 43:
		if value, ok := v.AsKillRequest(); ok {
			return value, true
		}
	case 44:
		if value, ok := v.AsDownlinkUEAssociatedLPPaTransport(); ok {
			return value, true
		}
	case 45:
		if value, ok := v.AsUplinkUEAssociatedLPPaTransport(); ok {
			return value, true
		}
	case 46:
		if value, ok := v.AsDownlinkNonUEAssociatedLPPaTransport(); ok {
			return value, true
		}
	case 47:
		if value, ok := v.AsUplinkNonUEAssociatedLPPaTransport(); ok {
			return value, true
		}
	case 48:
		if value, ok := v.AsUERadioCapabilityMatchRequest(); ok {
			return value, true
		}
	case 49:
		if value, ok := v.AsPWSRestartIndication(); ok {
			return value, true
		}
	case 50:
		if value, ok := v.AsERABModificationIndication(); ok {
			return value, true
		}
	case 51:
		if value, ok := v.AsPWSFailureIndication(); ok {
			return value, true
		}
	case 52:
		if value, ok := v.AsRerouteNASRequest(); ok {
			return value, true
		}
	case 53:
		if value, ok := v.AsUEContextModificationIndication(); ok {
			return value, true
		}
	case 54:
		if value, ok := v.AsConnectionEstablishmentIndication(); ok {
			return value, true
		}
	case 55:
		if value, ok := v.AsUEContextSuspendRequest(); ok {
			return value, true
		}
	case 56:
		if value, ok := v.AsUEContextResumeRequest(); ok {
			return value, true
		}
	case 57:
		if value, ok := v.AsNASDeliveryIndication(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsRetrieveUEInformation(); ok {
			return value, true
		}
	case 59:
		if value, ok := v.AsUEInformationTransfer(); ok {
			return value, true
		}
	case 60:
		if value, ok := v.AsENBCPRelocationIndication(); ok {
			return value, true
		}
	case 61:
		if value, ok := v.AsMMECPRelocationIndication(); ok {
			return value, true
		}
	case 62:
		if value, ok := v.AsSecondaryRATDataUsageReport(); ok {
			return value, true
		}
	case 63:
		if value, ok := v.AsUERadioCapabilityIDMappingRequest(); ok {
			return value, true
		}
	case 64:
		if value, ok := v.AsHandoverSuccess(); ok {
			return value, true
		}
	case 65:
		if value, ok := v.AsENBEarlyStatusTransfer(); ok {
			return value, true
		}
	case 66:
		if value, ok := v.AsMMEEarlyStatusTransfer(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsS1RemovalRequest(); ok {
			return value, true
		}
	}
	return nil, false
}
