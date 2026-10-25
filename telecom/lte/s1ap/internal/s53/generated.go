// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s53 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s53

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewENBConfigurationTransfer(fields s51.ENBConfigurationTransferIEContainer, options ...aper.BuildOption) (s52.ENBConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.ENBConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	v := s52.ENBConfigurationTransfer{ProtocolIEs: make(s51.ENBConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationTransfer")
	}
	if _, err := s52.BridgeENBConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s52.ENBConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationTransfer.protocolIEs:", err), "ENBConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "ENBConfigurationTransfer")
}
func NewMMEConfigurationTransfer(fields s52.MMEConfigurationTransferIEContainer, options ...aper.BuildOption) (s52.MMEConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s52.MMEConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	v := s52.MMEConfigurationTransfer{ProtocolIEs: make(s52.MMEConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationTransfer")
	}
	if _, err := s52.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s52.MMEConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationTransfer.protocolIEs:", err), "MMEConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "MMEConfigurationTransfer")
}

// Initiating returns the typed binding for the initiating message of PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Initiating() PathSwitchRequestInitiatingBinding {
	return PathSwitchRequestInitiatingBinding{info: PathSwitchRequestProcedure().Info(), validate: func(v *s41.PathSwitchRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidatePathSwitchRequestBudget(v, budget)
	}, encode: func(v *s41.PathSwitchRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s41.BridgePathSwitchRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s41.PathSwitchRequest, error) {
		var v s41.PathSwitchRequest
		err := s41.BridgePathSwitchRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s41.PathSwitchRequest{}, err
		}
		*s41.BridgePathSwitchRequestFieldReceived(&v) = true
		*s41.BridgePathSwitchRequestFieldReceivedAbsolute(&v) = true
		*s41.BridgePathSwitchRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s41.PathSwitchRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(3)
			*s52.BridgeInitiatingValueFieldBodyPathSwitchRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s41.PathSwitchRequest, options aper.DecodeState) (s41.PathSwitchRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s41.BridgeCaptureS1APPathSwitchRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s41.PathSwitchRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s41.BridgeCompareS1APPathSwitchRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PathSwitchRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Successful() s51.PathSwitchRequestAcknowledgeSuccessfulBinding {
	return func() s51.PathSwitchRequestAcknowledgeSuccessfulBinding {
		sealed := s51.PathSwitchRequestAcknowledgeSuccessfulBinding{}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInfo(&sealed) = PathSwitchRequestProcedure().Info()
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s48.PathSwitchRequestAcknowledge, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidatePathSwitchRequestAcknowledgeBudget(v, budget)
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s48.PathSwitchRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s48.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.PathSwitchRequestAcknowledge, error) {
			var v s48.PathSwitchRequestAcknowledge
			err := s48.BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s48.PathSwitchRequestAcknowledge{}, err
			}
			*s48.BridgePathSwitchRequestAcknowledgeFieldReceived(&v) = true
			*s48.BridgePathSwitchRequestAcknowledgeFieldReceivedAbsolute(&v) = true
			*s48.BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s48.PathSwitchRequestAcknowledge) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s51.BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s48.PathSwitchRequestAcknowledge, options aper.DecodeState) (s48.PathSwitchRequestAcknowledge, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s48.BridgeCaptureS1APPathSwitchRequestAcknowledge(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s48.PathSwitchRequestAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s48.BridgeCompareS1APPathSwitchRequestAcknowledge(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PathSwitchRequestAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Unsuccessful() s37.PathSwitchRequestFailureUnsuccessfulBinding {
	return func() s37.PathSwitchRequestFailureUnsuccessfulBinding {
		sealed := s37.PathSwitchRequestFailureUnsuccessfulBinding{}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInfo(&sealed) = PathSwitchRequestProcedure().Info()
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s26.PathSwitchRequestFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidatePathSwitchRequestFailureBudget(v, budget)
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s26.PathSwitchRequestFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s26.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.PathSwitchRequestFailure, error) {
			var v s26.PathSwitchRequestFailure
			err := s26.BridgePathSwitchRequestFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s26.PathSwitchRequestFailure{}, err
			}
			*s26.BridgePathSwitchRequestFailureFieldReceived(&v) = true
			*s26.BridgePathSwitchRequestFailureFieldReceivedAbsolute(&v) = true
			*s26.BridgePathSwitchRequestFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s26.PathSwitchRequestFailure) s37.UnsuccessfulValue {
			return func() s37.UnsuccessfulValue {
				sealed := s37.UnsuccessfulValue{}
				*s37.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s37.BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(&sealed) = &v
				return sealed
			}()
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s26.PathSwitchRequestFailure, options aper.DecodeState) (s26.PathSwitchRequestFailure, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APPathSwitchRequestFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s26.PathSwitchRequestFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APPathSwitchRequestFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PathSwitchRequestFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UplinkNASTransportDescriptor.
func (UplinkNASTransportDescriptor) Initiating() UplinkNASTransportInitiatingBinding {
	return UplinkNASTransportInitiatingBinding{info: UplinkNASTransportProcedure().Info(), validate: func(v *s45.UplinkNASTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUplinkNASTransportBudget(v, budget)
	}, encode: func(v *s45.UplinkNASTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.UplinkNASTransport, error) {
		var v s45.UplinkNASTransport
		err := s45.BridgeUplinkNASTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.UplinkNASTransport{}, err
		}
		*s45.BridgeUplinkNASTransportFieldReceived(&v) = true
		*s45.BridgeUplinkNASTransportFieldReceivedAbsolute(&v) = true
		*s45.BridgeUplinkNASTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.UplinkNASTransport) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(13)
			*s52.BridgeInitiatingValueFieldBodyUplinkNASTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.UplinkNASTransport, options aper.DecodeState) (s45.UplinkNASTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APUplinkNASTransport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s45.UplinkNASTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APUplinkNASTransport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UplinkNASTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ResetDescriptor.
func (ResetDescriptor) Initiating() ResetInitiatingBinding {
	return ResetInitiatingBinding{info: ResetProcedure().Info(), validate: func(v *s36.Reset, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateResetBudget(v, budget)
	}, encode: func(v *s36.Reset, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeResetMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.Reset, error) {
		var v s36.Reset
		err := s36.BridgeResetMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.Reset{}, err
		}
		*s36.BridgeResetFieldReceived(&v) = true
		*s36.BridgeResetFieldReceivedAbsolute(&v) = true
		*s36.BridgeResetFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.Reset) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(14)
			*s52.BridgeInitiatingValueFieldBodyReset(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.Reset, options aper.DecodeState) (s36.Reset, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.
			Begin()
		s36.BridgeCaptureS1APReset(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.Reset, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APReset(&v, &s)
		s.End(
			f,
			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Reset"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of ResetDescriptor.
func (ResetDescriptor) Successful() s51.ResetAcknowledgeSuccessfulBinding {
	return func() s51.ResetAcknowledgeSuccessfulBinding {
		sealed := s51.ResetAcknowledgeSuccessfulBinding{}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldInfo(&sealed) = ResetProcedure().Info()
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s45.ResetAcknowledge, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateResetAcknowledgeBudget(v, budget)
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s45.ResetAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s45.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ResetAcknowledge, error) {
			var v s45.ResetAcknowledge
			err := s45.BridgeResetAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s45.ResetAcknowledge{}, err
			}
			*s45.BridgeResetAcknowledgeFieldReceived(&v) = true
			*s45.BridgeResetAcknowledgeFieldReceivedAbsolute(&v) = true
			*s45.BridgeResetAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s45.ResetAcknowledge) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s51.BridgeSuccessfulValueFieldBodyResetAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s45.ResetAcknowledge, options aper.DecodeState) (s45.ResetAcknowledge, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APResetAcknowledge(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s45.ResetAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APResetAcknowledge(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s51.BridgeResetAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResetAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of S1SetupDescriptor.
func (S1SetupDescriptor) Initiating() S1SetupRequestInitiatingBinding {
	return S1SetupRequestInitiatingBinding{info: S1SetupProcedure().Info(), validate: func(v *s44.S1SetupRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateS1SetupRequestBudget(v, budget)
	}, encode: func(v *s44.S1SetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.S1SetupRequest, error) {
		var v s44.S1SetupRequest
		err := s44.BridgeS1SetupRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.S1SetupRequest{}, err
		}
		*s44.BridgeS1SetupRequestFieldReceived(&v) = true
		*s44.BridgeS1SetupRequestFieldReceivedAbsolute(&v) = true
		*s44.BridgeS1SetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.S1SetupRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(17)
			*s52.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.S1SetupRequest, options aper.DecodeState) (s44.S1SetupRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s44.BridgeCaptureS1APS1SetupRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.S1SetupRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APS1SetupRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1SetupRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of S1SetupDescriptor.
func (S1SetupDescriptor) Successful() s51.S1SetupResponseSuccessfulBinding {
	return func() s51.S1SetupResponseSuccessfulBinding {
		sealed := s51.S1SetupResponseSuccessfulBinding{}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s44.S1SetupResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateS1SetupResponseBudget(v, budget)
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s44.S1SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s44.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s44.S1SetupResponse, error) {
			var v s44.S1SetupResponse
			err := s44.BridgeS1SetupResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s44.S1SetupResponse{}, err
			}
			*s44.BridgeS1SetupResponseFieldReceived(&v) = true
			*s44.BridgeS1SetupResponseFieldReceivedAbsolute(&v) = true
			*s44.BridgeS1SetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldInject(&sealed) = func(v s44.S1SetupResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s51.BridgeSuccessfulValueFieldBodyS1SetupResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldCapture(&sealed) = func(v s44.S1SetupResponse, options aper.DecodeState) (s44.S1SetupResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s44.BridgeCaptureS1APS1SetupResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldCompare(&sealed) = func(v s44.S1SetupResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APS1SetupResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s51.BridgeS1SetupResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1SetupResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1SetupDescriptor.
func (S1SetupDescriptor) Unsuccessful() s37.S1SetupFailureUnsuccessfulBinding {
	return func() s37.S1SetupFailureUnsuccessfulBinding {
		sealed := s37.S1SetupFailureUnsuccessfulBinding{}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s27.S1SetupFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateS1SetupFailureBudget(v, budget)
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s27.S1SetupFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s27.BridgeS1SetupFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.S1SetupFailure, error) {
			var v s27.S1SetupFailure
			err := s27.BridgeS1SetupFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s27.S1SetupFailure{}, err
			}
			*s27.BridgeS1SetupFailureFieldReceived(&v) = true
			*s27.BridgeS1SetupFailureFieldReceivedAbsolute(&v) = true
			*s27.BridgeS1SetupFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s27.S1SetupFailure) s37.UnsuccessfulValue {
			return func() s37.UnsuccessfulValue {
				sealed := s37.UnsuccessfulValue{}
				*s37.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s37.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = &v
				return sealed
			}()
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s27.S1SetupFailure, options aper.DecodeState) (s27.S1SetupFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s27.BridgeCaptureS1APS1SetupFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s27.S1SetupFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APS1SetupFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeS1SetupFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1SetupFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UEContextReleaseRequestDescriptor.
func (UEContextReleaseRequestDescriptor) Initiating() UEContextReleaseRequestInitiatingBinding {
	return UEContextReleaseRequestInitiatingBinding{info: UEContextReleaseRequestProcedure().Info(), validate: func(v *s43.UEContextReleaseRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextReleaseRequestBudget(v, budget)
	}, encode: func(v *s43.UEContextReleaseRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s43.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s43.UEContextReleaseRequest, error) {
		var v s43.UEContextReleaseRequest
		err := s43.BridgeUEContextReleaseRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s43.UEContextReleaseRequest{}, err
		}
		*s43.BridgeUEContextReleaseRequestFieldReceived(&v) = true
		*s43.BridgeUEContextReleaseRequestFieldReceivedAbsolute(&v) = true
		*s43.BridgeUEContextReleaseRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s43.UEContextReleaseRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(18)
			*s52.BridgeInitiatingValueFieldBodyUEContextReleaseRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s43.UEContextReleaseRequest, options aper.DecodeState) (s43.UEContextReleaseRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s43.BridgeCaptureS1APUEContextReleaseRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s43.UEContextReleaseRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s43.BridgeCompareS1APUEContextReleaseRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextReleaseRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UplinkS1cdma2000tunnellingDescriptor.
func (UplinkS1cdma2000tunnellingDescriptor) Initiating() UplinkS1cdma2000tunnellingInitiatingBinding {
	return UplinkS1cdma2000tunnellingInitiatingBinding{info: UplinkS1cdma2000tunnellingProcedure().Info(), validate: func(v *s45.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	}, encode: func(v *s45.UplinkS1cdma2000tunnelling, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.UplinkS1cdma2000tunnelling, error) {
		var v s45.UplinkS1cdma2000tunnelling
		err := s45.BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.UplinkS1cdma2000tunnelling{}, err
		}
		*s45.BridgeUplinkS1cdma2000tunnellingFieldReceived(&v) = true
		*s45.BridgeUplinkS1cdma2000tunnellingFieldReceivedAbsolute(&v) = true
		*s45.BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.UplinkS1cdma2000tunnelling) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(20)
			*s52.BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.UplinkS1cdma2000tunnelling, options aper.DecodeState) (s45.UplinkS1cdma2000tunnelling, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APUplinkS1cdma2000tunnelling(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s45.UplinkS1cdma2000tunnelling, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APUplinkS1cdma2000tunnelling(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UplinkS1cdma2000tunnelling"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Initiating() UEContextModificationRequestInitiatingBinding {
	return UEContextModificationRequestInitiatingBinding{info: UEContextModificationProcedure().Info(), validate: func(v *s48.UEContextModificationRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextModificationRequestBudget(v, budget)
	}, encode: func(v *s48.UEContextModificationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s48.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s48.UEContextModificationRequest, error) {
		var v s48.UEContextModificationRequest
		err := s48.BridgeUEContextModificationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s48.UEContextModificationRequest{}, err
		}
		*s48.BridgeUEContextModificationRequestFieldReceived(&v) = true
		*s48.BridgeUEContextModificationRequestFieldReceivedAbsolute(&v) = true
		*s48.BridgeUEContextModificationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s48.UEContextModificationRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(21)
			*s52.BridgeInitiatingValueFieldBodyUEContextModificationRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s48.UEContextModificationRequest, options aper.DecodeState) (s48.UEContextModificationRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s48.BridgeCaptureS1APUEContextModificationRequest(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s48.UEContextModificationRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s48.BridgeCompareS1APUEContextModificationRequest(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Successful() s51.UEContextModificationResponseSuccessfulBinding {
	return func() s51.UEContextModificationResponseSuccessfulBinding {
		sealed := s51.UEContextModificationResponseSuccessfulBinding{}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s37.UEContextModificationResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextModificationResponseBudget(v, budget)
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s37.UEContextModificationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s37.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UEContextModificationResponse, error) {
			var v s37.UEContextModificationResponse
			err := s37.BridgeUEContextModificationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s37.UEContextModificationResponse{}, err
			}
			*s37.BridgeUEContextModificationResponseFieldReceived(&v) = true
			*s37.BridgeUEContextModificationResponseFieldReceivedAbsolute(&v) = true
			*s37.BridgeUEContextModificationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldInject(&sealed) = func(v s37.UEContextModificationResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s51.BridgeSuccessfulValueFieldBodyUEContextModificationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s37.UEContextModificationResponse, options aper.DecodeState) (s37.UEContextModificationResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUEContextModificationResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s37.UEContextModificationResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUEContextModificationResponse(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUEContextModificationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Unsuccessful() s37.UEContextModificationFailureUnsuccessfulBinding {
	return func() s37.UEContextModificationFailureUnsuccessfulBinding {
		sealed := s37.UEContextModificationFailureUnsuccessfulBinding{}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextModificationFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextModificationFailureBudget(v, budget)
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextModificationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextModificationFailure, error) {
			var v s36.UEContextModificationFailure
			err := s36.BridgeUEContextModificationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UEContextModificationFailure{}, err
			}
			*s36.BridgeUEContextModificationFailureFieldReceived(&v) = true
			*s36.BridgeUEContextModificationFailureFieldReceivedAbsolute(&v) = true
			*s36.BridgeUEContextModificationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextModificationFailure) s37.UnsuccessfulValue {
			return func() s37.UnsuccessfulValue {
				sealed := s37.UnsuccessfulValue{}
				*s37.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s37.BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextModificationFailure, options aper.DecodeState) (s36.UEContextModificationFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextModificationFailure(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextModificationFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextModificationFailure(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UECapabilityInfoIndicationDescriptor.
func (UECapabilityInfoIndicationDescriptor) Initiating() UECapabilityInfoIndicationInitiatingBinding {
	return UECapabilityInfoIndicationInitiatingBinding{info: UECapabilityInfoIndicationProcedure().Info(), validate: func(v *s36.UECapabilityInfoIndication, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUECapabilityInfoIndicationBudget(v, budget)
	}, encode: func(v *s36.UECapabilityInfoIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.UECapabilityInfoIndication, error) {
		var v s36.UECapabilityInfoIndication
		err := s36.BridgeUECapabilityInfoIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.UECapabilityInfoIndication{}, err
		}
		*s36.BridgeUECapabilityInfoIndicationFieldReceived(&v) = true
		*s36.BridgeUECapabilityInfoIndicationFieldReceivedAbsolute(&v) = true
		*s36.BridgeUECapabilityInfoIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.UECapabilityInfoIndication) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(22)
			*s52.BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.UECapabilityInfoIndication, options aper.DecodeState) (s36.UECapabilityInfoIndication, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APUECapabilityInfoIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s36.UECapabilityInfoIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APUECapabilityInfoIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UECapabilityInfoIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UEContextReleaseDescriptor.
func (UEContextReleaseDescriptor) Initiating() UEContextReleaseCommandInitiatingBinding {
	return UEContextReleaseCommandInitiatingBinding{info: UEContextReleaseProcedure().Info(), validate: func(v *s37.UEContextReleaseCommand, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextReleaseCommandBudget(v, budget)
	}, encode: func(v *s37.UEContextReleaseCommand, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s37.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s37.UEContextReleaseCommand, error) {
		var v s37.UEContextReleaseCommand
		err := s37.BridgeUEContextReleaseCommandMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s37.UEContextReleaseCommand{}, err
		}
		*s37.BridgeUEContextReleaseCommandFieldReceived(&v) = true
		*s37.BridgeUEContextReleaseCommandFieldReceivedAbsolute(&v) = true
		*s37.BridgeUEContextReleaseCommandFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s37.UEContextReleaseCommand) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(23)
			*s52.BridgeInitiatingValueFieldBodyUEContextReleaseCommand(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s37.UEContextReleaseCommand, options aper.DecodeState) (s37.UEContextReleaseCommand, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s37.BridgeCaptureS1APUEContextReleaseCommand(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s37.UEContextReleaseCommand, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s37.BridgeCompareS1APUEContextReleaseCommand(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextReleaseCommand"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UEContextReleaseDescriptor.
func (UEContextReleaseDescriptor) Successful() s51.UEContextReleaseCompleteSuccessfulBinding {
	return func() s51.UEContextReleaseCompleteSuccessfulBinding {
		sealed := s51.UEContextReleaseCompleteSuccessfulBinding{}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(&sealed) = UEContextReleaseProcedure().Info()
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(&sealed) = func(v *s47.UEContextReleaseComplete, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextReleaseCompleteBudget(v, budget)
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(&sealed) = func(v *s47.UEContextReleaseComplete, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s47.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.UEContextReleaseComplete, error) {
			var v s47.UEContextReleaseComplete
			err := s47.BridgeUEContextReleaseCompleteMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s47.UEContextReleaseComplete{}, err
			}
			*s47.BridgeUEContextReleaseCompleteFieldReceived(&v) = true
			*s47.BridgeUEContextReleaseCompleteFieldReceivedAbsolute(&v) = true
			*s47.BridgeUEContextReleaseCompleteFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(&sealed) = func(v s47.UEContextReleaseComplete) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s51.BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(&sealed) = func(v s47.UEContextReleaseComplete, options aper.DecodeState) (s47.UEContextReleaseComplete, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APUEContextReleaseComplete(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(&sealed) = func(v s47.UEContextReleaseComplete, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APUEContextReleaseComplete(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextReleaseComplete"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of TraceStartDescriptor.
func (TraceStartDescriptor) Initiating() TraceStartInitiatingBinding {
	return TraceStartInitiatingBinding{info: TraceStartProcedure().Info(), validate: func(v *s49.TraceStart, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateTraceStartBudget(v, budget)
	}, encode: func(v *s49.TraceStart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s49.BridgeTraceStartMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s49.TraceStart, error) {
		var v s49.TraceStart
		err := s49.BridgeTraceStartMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s49.TraceStart{}, err
		}
		*s49.BridgeTraceStartFieldReceived(&v) = true
		*s49.BridgeTraceStartFieldReceivedAbsolute(&v) = true
		*s49.BridgeTraceStartFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s49.TraceStart) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(27)
			*s52.BridgeInitiatingValueFieldBodyTraceStart(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s49.TraceStart, options aper.DecodeState) (s49.TraceStart, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s49.BridgeCaptureS1APTraceStart(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s49.TraceStart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s49.BridgeCompareS1APTraceStart(&v,
			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceStart"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of TraceFailureIndicationDescriptor.
func (TraceFailureIndicationDescriptor) Initiating() TraceFailureIndicationInitiatingBinding {
	return TraceFailureIndicationInitiatingBinding{info: TraceFailureIndicationProcedure().Info(), validate: func(v *s35.TraceFailureIndication, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateTraceFailureIndicationBudget(v, budget)
	}, encode: func(v *s35.TraceFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s35.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s35.TraceFailureIndication, error) {
		var v s35.TraceFailureIndication
		err := s35.BridgeTraceFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s35.TraceFailureIndication{}, err
		}
		*s35.BridgeTraceFailureIndicationFieldReceived(&v) = true
		*s35.BridgeTraceFailureIndicationFieldReceivedAbsolute(&v) = true
		*s35.BridgeTraceFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s35.TraceFailureIndication) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(28)
			*s52.BridgeInitiatingValueFieldBodyTraceFailureIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s35.TraceFailureIndication, options aper.DecodeState) (s35.TraceFailureIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s35.BridgeCaptureS1APTraceFailureIndication(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s35.TraceFailureIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s35.BridgeCompareS1APTraceFailureIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceFailureIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of WriteReplaceWarningDescriptor.
func (WriteReplaceWarningDescriptor) Initiating() WriteReplaceWarningRequestInitiatingBinding {
	return WriteReplaceWarningRequestInitiatingBinding{info: WriteReplaceWarningProcedure().Info(), validate: func(v *s51.WriteReplaceWarningRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	}, encode: func(v *s51.WriteReplaceWarningRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s51.BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s51.WriteReplaceWarningRequest, error) {
		var v s51.WriteReplaceWarningRequest
		err := s51.BridgeWriteReplaceWarningRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s51.WriteReplaceWarningRequest{}, err
		}
		*s51.BridgeWriteReplaceWarningRequestFieldReceived(&v) = true
		*s51.BridgeWriteReplaceWarningRequestFieldReceivedAbsolute(&v) = true
		*s51.BridgeWriteReplaceWarningRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s51.WriteReplaceWarningRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(36)
			*s52.BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s51.WriteReplaceWarningRequest, options aper.DecodeState) (s51.WriteReplaceWarningRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s51.BridgeCaptureS1APWriteReplaceWarningRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s51.WriteReplaceWarningRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s51.BridgeCompareS1APWriteReplaceWarningRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WriteReplaceWarningRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of WriteReplaceWarningDescriptor.
func (WriteReplaceWarningDescriptor) Successful() s51.WriteReplaceWarningResponseSuccessfulBinding {
	return func() s51.WriteReplaceWarningResponseSuccessfulBinding {
		sealed := s51.WriteReplaceWarningResponseSuccessfulBinding{}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInfo(&sealed) = WriteReplaceWarningProcedure().Info()
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s51.WriteReplaceWarningResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateWriteReplaceWarningResponseBudget(v, budget)
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s51.WriteReplaceWarningResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s51.BridgeWriteReplaceWarningResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.WriteReplaceWarningResponse, error) {
			var v s51.WriteReplaceWarningResponse
			err := s51.BridgeWriteReplaceWarningResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s51.WriteReplaceWarningResponse{}, err
			}
			*s51.BridgeWriteReplaceWarningResponseFieldReceived(&v) = true
			*s51.BridgeWriteReplaceWarningResponseFieldReceivedAbsolute(&v) = true
			*s51.BridgeWriteReplaceWarningResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInject(&sealed) = func(v s51.WriteReplaceWarningResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s51.BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCapture(&sealed) = func(v s51.WriteReplaceWarningResponse, options aper.DecodeState) (s51.WriteReplaceWarningResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeCaptureS1APWriteReplaceWarningResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCompare(&sealed) = func(v s51.WriteReplaceWarningResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s51.BridgeCompareS1APWriteReplaceWarningResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WriteReplaceWarningResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of PrivateMessageDescriptor.
func (PrivateMessageDescriptor) Initiating() PrivateMessageInitiatingBinding {
	return PrivateMessageInitiatingBinding{info: PrivateMessageProcedure().Info(), validate: func(v *s26.PrivateMessage, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s48.BridgeValidatePrivateMessageBudget(v, budget)
	}, encode: func(v *s26.PrivateMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s26.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s26.PrivateMessage, error) {
		var v s26.PrivateMessage
		err := s26.BridgePrivateMessageMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s26.PrivateMessage{}, err
		}
		*s26.BridgePrivateMessageFieldReceived(&v) = true
		*s26.BridgePrivateMessageFieldReceivedAbsolute(&v) = true
		*s26.BridgePrivateMessageFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s26.PrivateMessage) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(39)
			*s52.BridgeInitiatingValueFieldBodyPrivateMessage(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s26.PrivateMessage, options aper.DecodeState) (s26.PrivateMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s26.BridgeCaptureS1APPrivateMessage(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s26.PrivateMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s26.BridgeCompareS1APPrivateMessage(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateMessage"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of ENBConfigurationTransferDescriptor.
func (ENBConfigurationTransferDescriptor) Initiating() s52.ENBConfigurationTransferInitiatingBinding {
	return func() s52.ENBConfigurationTransferInitiatingBinding {
		sealed := s52.ENBConfigurationTransferInitiatingBinding{}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldInfo(&sealed) = ENBConfigurationTransferProcedure().Info()
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s52.ENBConfigurationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return BridgeValidateENBConfigurationTransferBudget(v, budget)
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s52.ENBConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s52.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.ENBConfigurationTransfer, error) {
			var v s52.ENBConfigurationTransfer
			err := s52.BridgeENBConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s52.ENBConfigurationTransfer{}, err
			}
			*s52.BridgeENBConfigurationTransferFieldReceived(&v) = true
			*s52.BridgeENBConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s52.BridgeENBConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s52.ENBConfigurationTransfer) s52.InitiatingValue {
			return func() s52.InitiatingValue {
				sealed := s52.InitiatingValue{}
				*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(40)
				*s52.BridgeInitiatingValueFieldBodyENBConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s52.ENBConfigurationTransfer, options aper.DecodeState) (s52.ENBConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeCaptureS1APENBConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s52.ENBConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s52.BridgeCompareS1APENBConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeENBConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of MMEConfigurationTransferDescriptor.
func (MMEConfigurationTransferDescriptor) Initiating() s52.MMEConfigurationTransferInitiatingBinding {
	return func() s52.MMEConfigurationTransferInitiatingBinding {
		sealed := s52.MMEConfigurationTransferInitiatingBinding{}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldInfo(&sealed) = MMEConfigurationTransferProcedure().Info()
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s52.MMEConfigurationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return BridgeValidateMMEConfigurationTransferBudget(v, budget)
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s52.MMEConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s52.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.MMEConfigurationTransfer, error) {
			var v s52.MMEConfigurationTransfer
			err := s52.BridgeMMEConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s52.MMEConfigurationTransfer{}, err
			}
			*s52.BridgeMMEConfigurationTransferFieldReceived(&v) = true
			*s52.BridgeMMEConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s52.BridgeMMEConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s52.MMEConfigurationTransfer) s52.InitiatingValue {
			return func() s52.InitiatingValue {
				sealed := s52.InitiatingValue{}
				*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(41)
				*s52.BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s52.MMEConfigurationTransfer, options aper.DecodeState) (s52.MMEConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeCaptureS1APMMEConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s52.MMEConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s52.BridgeCompareS1APMMEConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeMMEConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UplinkUEAssociatedLPPaTransportDescriptor.
func (UplinkUEAssociatedLPPaTransportDescriptor) Initiating() UplinkUEAssociatedLPPaTransportInitiatingBinding {
	return UplinkUEAssociatedLPPaTransportInitiatingBinding{info: UplinkUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s45.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s45.UplinkUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.UplinkUEAssociatedLPPaTransport, error) {
		var v s45.UplinkUEAssociatedLPPaTransport
		err := s45.BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.UplinkUEAssociatedLPPaTransport{}, err
		}
		*s45.BridgeUplinkUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s45.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s45.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.UplinkUEAssociatedLPPaTransport) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(45)
			*s52.BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.UplinkUEAssociatedLPPaTransport, options aper.DecodeState) (s45.UplinkUEAssociatedLPPaTransport, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s45.UplinkUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APUplinkUEAssociatedLPPaTransport(&v, &s)
		s.End(
			f,
			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UplinkUEAssociatedLPPaTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UplinkNonUEAssociatedLPPaTransportDescriptor.
func (UplinkNonUEAssociatedLPPaTransportDescriptor) Initiating() UplinkNonUEAssociatedLPPaTransportInitiatingBinding {
	return UplinkNonUEAssociatedLPPaTransportInitiatingBinding{info: UplinkNonUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s45.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s45.UplinkNonUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.UplinkNonUEAssociatedLPPaTransport, error) {
		var v s45.UplinkNonUEAssociatedLPPaTransport
		err := s45.BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.UplinkNonUEAssociatedLPPaTransport{}, err
		}
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.UplinkNonUEAssociatedLPPaTransport) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(47)
			*s52.BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.UplinkNonUEAssociatedLPPaTransport, options aper.DecodeState) (s45.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s45.UplinkNonUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UplinkNonUEAssociatedLPPaTransport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UERadioCapabilityMatchDescriptor.
func (UERadioCapabilityMatchDescriptor) Initiating() UERadioCapabilityMatchRequestInitiatingBinding {
	return UERadioCapabilityMatchRequestInitiatingBinding{info: UERadioCapabilityMatchProcedure().Info(), validate: func(v *s37.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	}, encode: func(v *s37.UERadioCapabilityMatchRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s37.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s37.UERadioCapabilityMatchRequest, error) {
		var v s37.UERadioCapabilityMatchRequest
		err := s37.BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s37.UERadioCapabilityMatchRequest{}, err
		}
		*s37.BridgeUERadioCapabilityMatchRequestFieldReceived(&v) = true
		*s37.BridgeUERadioCapabilityMatchRequestFieldReceivedAbsolute(&v) = true
		*s37.BridgeUERadioCapabilityMatchRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s37.UERadioCapabilityMatchRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(48)
			*s52.BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s37.UERadioCapabilityMatchRequest, options aper.DecodeState) (s37.UERadioCapabilityMatchRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s37.BridgeCaptureS1APUERadioCapabilityMatchRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s37.UERadioCapabilityMatchRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s37.BridgeCompareS1APUERadioCapabilityMatchRequest(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityMatchRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UERadioCapabilityMatchDescriptor.
func (UERadioCapabilityMatchDescriptor) Successful() s51.UERadioCapabilityMatchResponseSuccessfulBinding {
	return func() s51.UERadioCapabilityMatchResponseSuccessfulBinding {
		sealed := s51.UERadioCapabilityMatchResponseSuccessfulBinding{}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityMatchProcedure().Info()
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s37.UERadioCapabilityMatchResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUERadioCapabilityMatchResponseBudget(v, budget)
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s37.UERadioCapabilityMatchResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s37.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UERadioCapabilityMatchResponse, error) {
			var v s37.UERadioCapabilityMatchResponse
			err := s37.BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s37.UERadioCapabilityMatchResponse{}, err
			}
			*s37.BridgeUERadioCapabilityMatchResponseFieldReceived(&v) = true
			*s37.BridgeUERadioCapabilityMatchResponseFieldReceivedAbsolute(&v) = true
			*s37.BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInject(&sealed) = func(v s37.UERadioCapabilityMatchResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s51.BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCapture(&sealed) = func(v s37.UERadioCapabilityMatchResponse, options aper.DecodeState) (s37.UERadioCapabilityMatchResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUERadioCapabilityMatchResponse(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCompare(&sealed) = func(v s37.UERadioCapabilityMatchResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUERadioCapabilityMatchResponse(&v, &s)
			s.End(f,
				root,
				false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityMatchResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of RerouteNASRequestDescriptor.
func (RerouteNASRequestDescriptor) Initiating() RerouteNASRequestInitiatingBinding {
	return RerouteNASRequestInitiatingBinding{info: RerouteNASRequestProcedure().Info(), validate: func(v *s27.RerouteNASRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateRerouteNASRequestBudget(v, budget)
	}, encode: func(v *s27.RerouteNASRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s27.BridgeRerouteNASRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s27.RerouteNASRequest, error) {
		var v s27.RerouteNASRequest
		err := s27.BridgeRerouteNASRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s27.RerouteNASRequest{}, err
		}
		*s27.BridgeRerouteNASRequestFieldReceived(&v) = true
		*s27.BridgeRerouteNASRequestFieldReceivedAbsolute(&v) = true
		*s27.BridgeRerouteNASRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s27.RerouteNASRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(52)
			*s52.BridgeInitiatingValueFieldBodyRerouteNASRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s27.RerouteNASRequest, options aper.DecodeState) (s27.RerouteNASRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s27.BridgeCaptureS1APRerouteNASRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s27.RerouteNASRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s27.BridgeCompareS1APRerouteNASRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RerouteNASRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UEContextModificationIndicationDescriptor.
func (UEContextModificationIndicationDescriptor) Initiating() UEContextModificationIndicationInitiatingBinding {
	return UEContextModificationIndicationInitiatingBinding{info: UEContextModificationIndicationProcedure().Info(), validate: func(v *s37.UEContextModificationIndication, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextModificationIndicationBudget(v, budget)
	}, encode: func(v *s37.UEContextModificationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s37.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s37.UEContextModificationIndication, error) {
		var v s37.UEContextModificationIndication
		err := s37.BridgeUEContextModificationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s37.UEContextModificationIndication{}, err
		}
		*s37.BridgeUEContextModificationIndicationFieldReceived(&v) = true
		*s37.BridgeUEContextModificationIndicationFieldReceivedAbsolute(&v) = true
		*s37.BridgeUEContextModificationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s37.UEContextModificationIndication) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(53)
			*s52.BridgeInitiatingValueFieldBodyUEContextModificationIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s37.UEContextModificationIndication, options aper.DecodeState) (s37.UEContextModificationIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s37.BridgeCaptureS1APUEContextModificationIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s37.UEContextModificationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s37.BridgeCompareS1APUEContextModificationIndication(&v, &s)
		s.End(
			f,
			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UEContextModificationIndicationDescriptor.
func (UEContextModificationIndicationDescriptor) Successful() s51.UEContextModificationConfirmSuccessfulBinding {
	return func() s51.UEContextModificationConfirmSuccessfulBinding {
		sealed := s51.UEContextModificationConfirmSuccessfulBinding{}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldInfo(&sealed) = UEContextModificationIndicationProcedure().Info()
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextModificationConfirm, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextModificationConfirmBudget(v, budget)
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextModificationConfirm, error) {
			var v s36.UEContextModificationConfirm
			err := s36.BridgeUEContextModificationConfirmMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UEContextModificationConfirm{}, err
			}
			*s36.BridgeUEContextModificationConfirmFieldReceived(&v) = true
			*s36.BridgeUEContextModificationConfirmFieldReceivedAbsolute(&v) = true
			*s36.BridgeUEContextModificationConfirmFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextModificationConfirm) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s51.BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextModificationConfirm, options aper.DecodeState) (s36.UEContextModificationConfirm, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextModificationConfirm(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextModificationConfirm, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextModificationConfirm(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUEContextModificationConfirmSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationConfirm"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UEContextSuspendDescriptor.
func (UEContextSuspendDescriptor) Initiating() UEContextSuspendRequestInitiatingBinding {
	return UEContextSuspendRequestInitiatingBinding{info: UEContextSuspendProcedure().Info(), validate: func(v *s47.UEContextSuspendRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextSuspendRequestBudget(v, budget)
	}, encode: func(v *s47.UEContextSuspendRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s47.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s47.UEContextSuspendRequest, error) {
		var v s47.UEContextSuspendRequest
		err := s47.BridgeUEContextSuspendRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s47.UEContextSuspendRequest{}, err
		}
		*s47.BridgeUEContextSuspendRequestFieldReceived(&v) = true
		*s47.BridgeUEContextSuspendRequestFieldReceivedAbsolute(&v) = true
		*s47.BridgeUEContextSuspendRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s47.UEContextSuspendRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(55)
			*s52.BridgeInitiatingValueFieldBodyUEContextSuspendRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s47.UEContextSuspendRequest, options aper.DecodeState) (s47.UEContextSuspendRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s47.BridgeCaptureS1APUEContextSuspendRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s47.UEContextSuspendRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s47.BridgeCompareS1APUEContextSuspendRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextSuspendRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UEContextSuspendDescriptor.
func (UEContextSuspendDescriptor) Successful() s51.UEContextSuspendResponseSuccessfulBinding {
	return func() s51.UEContextSuspendResponseSuccessfulBinding {
		sealed := s51.UEContextSuspendResponseSuccessfulBinding{}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(&sealed) = UEContextSuspendProcedure().Info()
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s37.UEContextSuspendResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextSuspendResponseBudget(v, budget)
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s37.UEContextSuspendResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s37.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UEContextSuspendResponse, error) {
			var v s37.UEContextSuspendResponse
			err := s37.BridgeUEContextSuspendResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s37.UEContextSuspendResponse{}, err
			}
			*s37.BridgeUEContextSuspendResponseFieldReceived(&v) = true
			*s37.BridgeUEContextSuspendResponseFieldReceivedAbsolute(&v) = true
			*s37.BridgeUEContextSuspendResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(&sealed) = func(v s37.UEContextSuspendResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s51.BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(&sealed) = func(v s37.UEContextSuspendResponse, options aper.DecodeState) (s37.UEContextSuspendResponse, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUEContextSuspendResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(&sealed) = func(v s37.UEContextSuspendResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUEContextSuspendResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextSuspendResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Initiating() UEContextResumeRequestInitiatingBinding {
	return UEContextResumeRequestInitiatingBinding{info: UEContextResumeProcedure().Info(), validate: func(v *s39.UEContextResumeRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEContextResumeRequestBudget(v, budget)
	}, encode: func(v *s39.UEContextResumeRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s39.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s39.UEContextResumeRequest, error) {
		var v s39.UEContextResumeRequest
		err := s39.BridgeUEContextResumeRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s39.UEContextResumeRequest{}, err
		}
		*s39.BridgeUEContextResumeRequestFieldReceived(&v) = true
		*s39.BridgeUEContextResumeRequestFieldReceivedAbsolute(&v) = true
		*s39.BridgeUEContextResumeRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s39.UEContextResumeRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(56)
			*s52.BridgeInitiatingValueFieldBodyUEContextResumeRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s39.UEContextResumeRequest, options aper.DecodeState) (s39.UEContextResumeRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s39.BridgeCaptureS1APUEContextResumeRequest(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s39.UEContextResumeRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s39.BridgeCompareS1APUEContextResumeRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextResumeRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Successful() s51.UEContextResumeResponseSuccessfulBinding {
	return func() s51.UEContextResumeResponseSuccessfulBinding {
		sealed := s51.UEContextResumeResponseSuccessfulBinding{}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s39.UEContextResumeResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextResumeResponseBudget(v, budget)
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s39.UEContextResumeResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s39.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEContextResumeResponse, error) {
			var v s39.UEContextResumeResponse
			err := s39.BridgeUEContextResumeResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s39.UEContextResumeResponse{}, err
			}
			*s39.BridgeUEContextResumeResponseFieldReceived(&v) = true
			*s39.BridgeUEContextResumeResponseFieldReceivedAbsolute(&v) = true
			*s39.BridgeUEContextResumeResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldInject(&sealed) = func(v s39.UEContextResumeResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s51.BridgeSuccessfulValueFieldBodyUEContextResumeResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(&sealed) = func(v s39.UEContextResumeResponse, options aper.DecodeState) (s39.UEContextResumeResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s39.BridgeCaptureS1APUEContextResumeResponse(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(&sealed) = func(v s39.UEContextResumeResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APUEContextResumeResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUEContextResumeResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextResumeResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Unsuccessful() s37.UEContextResumeFailureUnsuccessfulBinding {
	return func() s37.UEContextResumeFailureUnsuccessfulBinding {
		sealed := s37.UEContextResumeFailureUnsuccessfulBinding{}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s37.UEContextResumeFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUEContextResumeFailureBudget(v, budget)
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s37.UEContextResumeFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s37.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UEContextResumeFailure, error) {
			var v s37.UEContextResumeFailure
			err := s37.BridgeUEContextResumeFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s37.UEContextResumeFailure{}, err
			}
			*s37.BridgeUEContextResumeFailureFieldReceived(&v) = true
			*s37.BridgeUEContextResumeFailureFieldReceivedAbsolute(&v) = true
			*s37.BridgeUEContextResumeFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s37.UEContextResumeFailure) s37.UnsuccessfulValue {
			return func() s37.UnsuccessfulValue {
				sealed := s37.UnsuccessfulValue{}
				*s37.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s37.BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(&sealed) = &v
				return sealed
			}()
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s37.UEContextResumeFailure, options aper.DecodeState) (s37.UEContextResumeFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUEContextResumeFailure(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s37.UEContextResumeFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUEContextResumeFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUEContextResumeFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextResumeFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of RetrieveUEInformationDescriptor.
func (RetrieveUEInformationDescriptor) Initiating() RetrieveUEInformationInitiatingBinding {
	return RetrieveUEInformationInitiatingBinding{info: RetrieveUEInformationProcedure().Info(), validate: func(v *s28.RetrieveUEInformation, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateRetrieveUEInformationBudget(v, budget)
	}, encode: func(v *s28.RetrieveUEInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s28.BridgeRetrieveUEInformationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s28.RetrieveUEInformation, error) {
		var v s28.RetrieveUEInformation
		err := s28.BridgeRetrieveUEInformationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s28.RetrieveUEInformation{}, err
		}
		*s28.BridgeRetrieveUEInformationFieldReceived(&v) = true
		*s28.BridgeRetrieveUEInformationFieldReceivedAbsolute(&v) = true
		*s28.BridgeRetrieveUEInformationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s28.RetrieveUEInformation) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(58)
			*s52.BridgeInitiatingValueFieldBodyRetrieveUEInformation(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s28.RetrieveUEInformation, options aper.DecodeState) (s28.RetrieveUEInformation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s28.BridgeCaptureS1APRetrieveUEInformation(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s28.RetrieveUEInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s28.BridgeCompareS1APRetrieveUEInformation(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RetrieveUEInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UEInformationTransferDescriptor.
func (UEInformationTransferDescriptor) Initiating() UEInformationTransferInitiatingBinding {
	return UEInformationTransferInitiatingBinding{info: UEInformationTransferProcedure().Info(), validate: func(v *s37.UEInformationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUEInformationTransferBudget(v, budget)
	}, encode: func(v *s37.UEInformationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s37.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s37.UEInformationTransfer, error) {
		var v s37.UEInformationTransfer
		err := s37.BridgeUEInformationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s37.UEInformationTransfer{}, err
		}
		*s37.BridgeUEInformationTransferFieldReceived(&v) = true
		*s37.BridgeUEInformationTransferFieldReceivedAbsolute(&v) = true
		*s37.BridgeUEInformationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s37.UEInformationTransfer) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(59)
			*s52.BridgeInitiatingValueFieldBodyUEInformationTransfer(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s37.UEInformationTransfer, options aper.DecodeState) (s37.UEInformationTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s37.BridgeCaptureS1APUEInformationTransfer(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s37.UEInformationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s37.BridgeCompareS1APUEInformationTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEInformationTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of SecondaryRATDataUsageReportDescriptor.
func (SecondaryRATDataUsageReportDescriptor) Initiating() SecondaryRATDataUsageReportInitiatingBinding {
	return SecondaryRATDataUsageReportInitiatingBinding{info: SecondaryRATDataUsageReportProcedure().Info(), validate: func(v *s47.SecondaryRATDataUsageReport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	}, encode: func(v *s47.SecondaryRATDataUsageReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s47.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s47.SecondaryRATDataUsageReport, error) {
		var v s47.SecondaryRATDataUsageReport
		err := s47.BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s47.SecondaryRATDataUsageReport{}, err
		}
		*s47.BridgeSecondaryRATDataUsageReportFieldReceived(&v) = true
		*s47.BridgeSecondaryRATDataUsageReportFieldReceivedAbsolute(&v) = true
		*s47.BridgeSecondaryRATDataUsageReportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s47.SecondaryRATDataUsageReport) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(62)
			*s52.BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s47.SecondaryRATDataUsageReport, options aper.DecodeState) (s47.SecondaryRATDataUsageReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s47.BridgeCaptureS1APSecondaryRATDataUsageReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v s47.SecondaryRATDataUsageReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s47.BridgeCompareS1APSecondaryRATDataUsageReport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Initiating() UERadioCapabilityIDMappingRequestInitiatingBinding {
	return UERadioCapabilityIDMappingRequestInitiatingBinding{info: UERadioCapabilityIDMappingProcedure().Info(), validate: func(v *s37.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s51.BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	}, encode: func(v *s37.UERadioCapabilityIDMappingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s37.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s37.UERadioCapabilityIDMappingRequest, error) {
		var v s37.UERadioCapabilityIDMappingRequest
		err := s37.BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s37.UERadioCapabilityIDMappingRequest{}, err
		}
		*s37.BridgeUERadioCapabilityIDMappingRequestFieldReceived(&v) = true
		*s37.BridgeUERadioCapabilityIDMappingRequestFieldReceivedAbsolute(&v) = true
		*s37.BridgeUERadioCapabilityIDMappingRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s37.UERadioCapabilityIDMappingRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(63)
			*s52.BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s37.UERadioCapabilityIDMappingRequest, options aper.DecodeState) (s37.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s37.BridgeCaptureS1APUERadioCapabilityIDMappingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s37.UERadioCapabilityIDMappingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s37.BridgeCompareS1APUERadioCapabilityIDMappingRequest(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityIDMappingRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Successful() s51.UERadioCapabilityIDMappingResponseSuccessfulBinding {
	return func() s51.UERadioCapabilityIDMappingResponseSuccessfulBinding {
		sealed := s51.UERadioCapabilityIDMappingResponseSuccessfulBinding{}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityIDMappingProcedure().Info()
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s37.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s51.BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s37.UERadioCapabilityIDMappingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s37.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UERadioCapabilityIDMappingResponse, error) {
			var v s37.UERadioCapabilityIDMappingResponse
			err := s37.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s37.UERadioCapabilityIDMappingResponse{}, err
			}
			*s37.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&v) = true
			*s37.BridgeUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(&v) = true
			*s37.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(&sealed) = func(v s37.UERadioCapabilityIDMappingResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s51.BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(&sealed) = func(v s37.UERadioCapabilityIDMappingResponse, options aper.DecodeState) (s37.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(&sealed) = func(v s37.UERadioCapabilityIDMappingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUERadioCapabilityIDMappingResponse(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityIDMappingResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of S1RemovalDescriptor.
func (S1RemovalDescriptor) Initiating() S1RemovalRequestInitiatingBinding {
	return S1RemovalRequestInitiatingBinding{info: S1RemovalProcedure().Info(), validate: func(v *s27.S1RemovalRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateS1RemovalRequestBudget(v, budget)
	}, encode: func(v *s27.S1RemovalRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s27.BridgeS1RemovalRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s27.S1RemovalRequest, error) {
		var v s27.S1RemovalRequest
		err := s27.BridgeS1RemovalRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s27.S1RemovalRequest{}, err
		}
		*s27.BridgeS1RemovalRequestFieldReceived(&v) = true
		*s27.BridgeS1RemovalRequestFieldReceivedAbsolute(&v) = true
		*s27.BridgeS1RemovalRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s27.S1RemovalRequest) s52.InitiatingValue {
		return func() s52.InitiatingValue {
			sealed := s52.InitiatingValue{}
			*s52.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(67)
			*s52.BridgeInitiatingValueFieldBodyS1RemovalRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s27.S1RemovalRequest, options aper.DecodeState) (s27.S1RemovalRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s27.BridgeCaptureS1APS1RemovalRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s27.S1RemovalRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s27.BridgeCompareS1APS1RemovalRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Successful returns the typed binding for the successful outcome of S1RemovalDescriptor.
func (S1RemovalDescriptor) Successful() s51.S1RemovalResponseSuccessfulBinding {
	return func() s51.S1RemovalResponseSuccessfulBinding {
		sealed := s51.S1RemovalResponseSuccessfulBinding{}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s27.S1RemovalResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateS1RemovalResponseBudget(v, budget)
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s27.S1RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s27.BridgeS1RemovalResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.S1RemovalResponse, error) {
			var v s27.S1RemovalResponse
			err := s27.BridgeS1RemovalResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s27.S1RemovalResponse{}, err
			}
			*s27.BridgeS1RemovalResponseFieldReceived(&v) = true
			*s27.BridgeS1RemovalResponseFieldReceivedAbsolute(&v) = true
			*s27.BridgeS1RemovalResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldInject(&sealed) = func(v s27.S1RemovalResponse) s51.SuccessfulValue {
			return func() s51.SuccessfulValue {
				sealed := s51.SuccessfulValue{}
				*s51.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s51.BridgeSuccessfulValueFieldBodyS1RemovalResponse(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldCapture(&sealed) = func(v s27.S1RemovalResponse, options aper.DecodeState) (s27.S1RemovalResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options,
			)
			f := s.Begin()
			s27.BridgeCaptureS1APS1RemovalResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldCompare(&sealed) = func(v s27.S1RemovalResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APS1RemovalResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s51.BridgeS1RemovalResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1RemovalDescriptor.
func (S1RemovalDescriptor) Unsuccessful() s37.S1RemovalFailureUnsuccessfulBinding {
	return func() s37.S1RemovalFailureUnsuccessfulBinding {
		sealed := s37.S1RemovalFailureUnsuccessfulBinding{}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s27.S1RemovalFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateS1RemovalFailureBudget(v, budget)
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s27.S1RemovalFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s27.BridgeS1RemovalFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.S1RemovalFailure, error) {
			var v s27.S1RemovalFailure
			err := s27.BridgeS1RemovalFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s27.S1RemovalFailure{}, err
			}
			*s27.BridgeS1RemovalFailureFieldReceived(&v) = true
			*s27.BridgeS1RemovalFailureFieldReceivedAbsolute(&v) = true
			*s27.BridgeS1RemovalFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s27.S1RemovalFailure) s37.UnsuccessfulValue {
			return func() s37.UnsuccessfulValue {
				sealed := s37.UnsuccessfulValue{}
				*s37.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s37.BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(&sealed) = &v
				return sealed
			}()
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s27.S1RemovalFailure, options aper.DecodeState) (s27.S1RemovalFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeCaptureS1APS1RemovalFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s27.S1RemovalFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APS1RemovalFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s37.BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestInitiatingBinding is the concrete InitiatingBinding[PathSwitchRequest].
type PathSwitchRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s41.PathSwitchRequest, aper.DecodeState,

	) (s41.PathSwitchRequest, aper.Snapshot,

	)
	compare func(s41.PathSwitchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s41.PathSwitchRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s41.PathSwitchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s41.PathSwitchRequest,

		error)
	inject func(s41.PathSwitchRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestInitiatingBinding) Codec() s41.PathSwitchRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s41.PathSwitchRequestValueCodec{}
	}
	return func() s41.PathSwitchRequestValueCodec {
		sealed := s41.PathSwitchRequestValueCodec{}
		*s41.BridgePathSwitchRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s41.BridgePathSwitchRequestValueCodecFieldDecode(&sealed) = b.decode
		*s41.BridgePathSwitchRequestValueCodecFieldEncode(&sealed) = func(value s41.PathSwitchRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s41.BridgePathSwitchRequestValueCodecFieldCapture(&sealed) = b.capture
		*s41.BridgePathSwitchRequestValueCodecFieldCompare(&sealed) = b.compare
		*s41.BridgePathSwitchRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestInitiatingBinding) Build(body s41.PathSwitchRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkNASTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNASTransport].
type UplinkNASTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.UplinkNASTransport, aper.DecodeState,

	) (s45.UplinkNASTransport, aper.Snapshot,

	)
	compare func(s45.UplinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UplinkNASTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s45.UplinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UplinkNASTransport,

		error)
	inject func(s45.UplinkNASTransport,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportInitiatingBinding) Codec() s45.UplinkNASTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UplinkNASTransportValueCodec{}
	}
	return func() s45.UplinkNASTransportValueCodec {
		sealed := s45.UplinkNASTransportValueCodec{}
		*s45.BridgeUplinkNASTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUplinkNASTransportValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUplinkNASTransportValueCodecFieldEncode(&sealed) = func(value s45.UplinkNASTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUplinkNASTransportValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUplinkNASTransportValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUplinkNASTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNASTransportInitiatingBinding) Build(body s45.UplinkNASTransport,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ResetInitiatingBinding is the concrete InitiatingBinding[Reset].
type ResetInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.Reset, aper.DecodeState,

	) (s36.Reset, aper.Snapshot,

	)
	compare func(s36.Reset, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.Reset,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.Reset,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.Reset,

		error)
	inject func(s36.Reset,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ResetInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetInitiatingBinding) Codec() s36.ResetValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.ResetValueCodec{}
	}
	return func() s36.ResetValueCodec {
		sealed := s36.ResetValueCodec{}
		*s36.BridgeResetValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeResetValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeResetValueCodecFieldEncode(&sealed) = func(value s36.Reset,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeResetValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeResetValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeResetValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ResetInitiatingBinding) Build(body s36.Reset,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1SetupRequestInitiatingBinding is the concrete InitiatingBinding[S1SetupRequest].
type S1SetupRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.S1SetupRequest, aper.DecodeState,

	) (s44.S1SetupRequest, aper.Snapshot,

	)
	compare func(s44.S1SetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.S1SetupRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.S1SetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.S1SetupRequest,

		error)
	inject func(s44.S1SetupRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestInitiatingBinding) Codec() s44.S1SetupRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.S1SetupRequestValueCodec{}
	}
	return func() s44.S1SetupRequestValueCodec {
		sealed := s44.S1SetupRequestValueCodec{}
		*s44.BridgeS1SetupRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeS1SetupRequestValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeS1SetupRequestValueCodecFieldEncode(&sealed) = func(value s44.S1SetupRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeS1SetupRequestValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeS1SetupRequestValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeS1SetupRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupRequestInitiatingBinding) Build(body s44.S1SetupRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseRequestInitiatingBinding is the concrete InitiatingBinding[UEContextReleaseRequest].
type UEContextReleaseRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.UEContextReleaseRequest, aper.DecodeState,

	) (s43.UEContextReleaseRequest, aper.Snapshot,

	)
	compare func(s43.UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.UEContextReleaseRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s43.UEContextReleaseRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.UEContextReleaseRequest,

		error)
	inject func(s43.UEContextReleaseRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Codec() s43.UEContextReleaseRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.UEContextReleaseRequestValueCodec{}
	}
	return func() s43.UEContextReleaseRequestValueCodec {
		sealed := s43.UEContextReleaseRequestValueCodec{}
		*s43.BridgeUEContextReleaseRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeUEContextReleaseRequestValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeUEContextReleaseRequestValueCodecFieldEncode(&sealed) = func(value s43.UEContextReleaseRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeUEContextReleaseRequestValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeUEContextReleaseRequestValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeUEContextReleaseRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseRequestInitiatingBinding) Build(body s43.UEContextReleaseRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkS1cdma2000tunnellingInitiatingBinding is the concrete InitiatingBinding[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.UplinkS1cdma2000tunnelling, aper.DecodeState,

	) (s45.UplinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(s45.UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UplinkS1cdma2000tunnelling,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s45.UplinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UplinkS1cdma2000tunnelling,

		error)
	inject func(s45.UplinkS1cdma2000tunnelling,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Codec() s45.UplinkS1cdma2000tunnellingValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UplinkS1cdma2000tunnellingValueCodec{}
	}
	return func() s45.UplinkS1cdma2000tunnellingValueCodec {
		sealed := s45.UplinkS1cdma2000tunnellingValueCodec{}
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldEncode(&sealed) = func(value s45.UplinkS1cdma2000tunnelling,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUplinkS1cdma2000tunnellingValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Build(body s45.UplinkS1cdma2000tunnelling,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationRequestInitiatingBinding is the concrete InitiatingBinding[UEContextModificationRequest].
type UEContextModificationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s48.UEContextModificationRequest, aper.DecodeState,

	) (s48.UEContextModificationRequest, aper.Snapshot,

	)
	compare func(s48.UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s48.UEContextModificationRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s48.UEContextModificationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s48.UEContextModificationRequest,

		error)
	inject func(s48.UEContextModificationRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestInitiatingBinding) Codec() s48.UEContextModificationRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s48.UEContextModificationRequestValueCodec{}
	}
	return func() s48.UEContextModificationRequestValueCodec {
		sealed := s48.UEContextModificationRequestValueCodec{}
		*s48.BridgeUEContextModificationRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s48.BridgeUEContextModificationRequestValueCodecFieldDecode(&sealed) = b.decode
		*s48.BridgeUEContextModificationRequestValueCodecFieldEncode(&sealed) = func(value s48.UEContextModificationRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s48.BridgeUEContextModificationRequestValueCodecFieldCapture(&sealed) = b.capture
		*s48.BridgeUEContextModificationRequestValueCodecFieldCompare(&sealed) = b.compare
		*s48.BridgeUEContextModificationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationRequestInitiatingBinding) Build(body s48.UEContextModificationRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UECapabilityInfoIndicationInitiatingBinding is the concrete InitiatingBinding[UECapabilityInfoIndication].
type UECapabilityInfoIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UECapabilityInfoIndication, aper.DecodeState,

	) (s36.UECapabilityInfoIndication, aper.Snapshot,

	)
	compare func(s36.UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UECapabilityInfoIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UECapabilityInfoIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UECapabilityInfoIndication,

		error)
	inject func(s36.UECapabilityInfoIndication,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UECapabilityInfoIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UECapabilityInfoIndicationInitiatingBinding) Codec() s36.UECapabilityInfoIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UECapabilityInfoIndicationValueCodec{}
	}
	return func() s36.UECapabilityInfoIndicationValueCodec {
		sealed := s36.UECapabilityInfoIndicationValueCodec{}
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldEncode(&sealed) = func(value s36.UECapabilityInfoIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUECapabilityInfoIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UECapabilityInfoIndicationInitiatingBinding) Build(body s36.UECapabilityInfoIndication,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseCommandInitiatingBinding is the concrete InitiatingBinding[UEContextReleaseCommand].
type UEContextReleaseCommandInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UEContextReleaseCommand, aper.DecodeState,

	) (s37.UEContextReleaseCommand, aper.Snapshot,

	)
	compare func(s37.UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UEContextReleaseCommand,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UEContextReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UEContextReleaseCommand,

		error)
	inject func(s37.UEContextReleaseCommand,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandInitiatingBinding) Codec() s37.UEContextReleaseCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UEContextReleaseCommandValueCodec{}
	}
	return func() s37.UEContextReleaseCommandValueCodec {
		sealed := s37.UEContextReleaseCommandValueCodec{}
		*s37.BridgeUEContextReleaseCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUEContextReleaseCommandValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUEContextReleaseCommandValueCodecFieldEncode(&sealed) = func(value s37.UEContextReleaseCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUEContextReleaseCommandValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUEContextReleaseCommandValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUEContextReleaseCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseCommandInitiatingBinding) Build(body s37.UEContextReleaseCommand,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceStartInitiatingBinding is the concrete InitiatingBinding[TraceStart].
type TraceStartInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s49.TraceStart, aper.DecodeState,

	) (s49.TraceStart, aper.Snapshot,

	)
	compare func(s49.TraceStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s49.TraceStart,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s49.TraceStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s49.TraceStart,

		error)
	inject func(s49.TraceStart,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceStartInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartInitiatingBinding) Codec() s49.TraceStartValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s49.TraceStartValueCodec{}
	}
	return func() s49.TraceStartValueCodec {
		sealed := s49.TraceStartValueCodec{}
		*s49.BridgeTraceStartValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s49.BridgeTraceStartValueCodecFieldDecode(&sealed) = b.decode
		*s49.BridgeTraceStartValueCodecFieldEncode(&sealed) = func(value s49.TraceStart,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s49.BridgeTraceStartValueCodecFieldCapture(&sealed) = b.capture
		*s49.BridgeTraceStartValueCodecFieldCompare(&sealed) = b.compare
		*s49.BridgeTraceStartValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceStartInitiatingBinding) Build(body s49.TraceStart,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceFailureIndicationInitiatingBinding is the concrete InitiatingBinding[TraceFailureIndication].
type TraceFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s35.TraceFailureIndication, aper.DecodeState,

	) (s35.TraceFailureIndication, aper.Snapshot,

	)
	compare func(s35.TraceFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s35.TraceFailureIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s35.TraceFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s35.TraceFailureIndication,

		error)
	inject func(s35.TraceFailureIndication,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationInitiatingBinding) Codec() s35.TraceFailureIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s35.TraceFailureIndicationValueCodec{}
	}
	return func() s35.TraceFailureIndicationValueCodec {
		sealed := s35.TraceFailureIndicationValueCodec{}
		*s35.BridgeTraceFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s35.BridgeTraceFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s35.BridgeTraceFailureIndicationValueCodecFieldEncode(&sealed) = func(value s35.TraceFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s35.BridgeTraceFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s35.BridgeTraceFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s35.BridgeTraceFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceFailureIndicationInitiatingBinding) Build(body s35.TraceFailureIndication,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// WriteReplaceWarningRequestInitiatingBinding is the concrete InitiatingBinding[WriteReplaceWarningRequest].
type WriteReplaceWarningRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s51.WriteReplaceWarningRequest, aper.DecodeState,

	) (s51.WriteReplaceWarningRequest, aper.Snapshot,

	)
	compare func(s51.WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s51.WriteReplaceWarningRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s51.WriteReplaceWarningRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s51.WriteReplaceWarningRequest,

		error)
	inject func(s51.WriteReplaceWarningRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Codec() s51.WriteReplaceWarningRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.WriteReplaceWarningRequestValueCodec{}
	}
	return func() s51.WriteReplaceWarningRequestValueCodec {
		sealed := s51.WriteReplaceWarningRequestValueCodec{}
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldDecode(&sealed) = b.decode
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldEncode(&sealed) = func(value s51.WriteReplaceWarningRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldCapture(&sealed) = b.capture
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldCompare(&sealed) = b.compare
		*s51.BridgeWriteReplaceWarningRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b WriteReplaceWarningRequestInitiatingBinding) Build(body s51.WriteReplaceWarningRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.PrivateMessage, aper.DecodeState,

	) (s26.PrivateMessage, aper.Snapshot,

	)
	compare func(s26.PrivateMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.PrivateMessage,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.PrivateMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.PrivateMessage,

		error)
	inject func(s26.PrivateMessage,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PrivateMessageInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PrivateMessageInitiatingBinding) Codec() s26.PrivateMessageValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.PrivateMessageValueCodec{}
	}
	return func() s26.PrivateMessageValueCodec {
		sealed := s26.PrivateMessageValueCodec{}
		*s26.BridgePrivateMessageValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgePrivateMessageValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgePrivateMessageValueCodecFieldEncode(&sealed) = func(value s26.PrivateMessage,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgePrivateMessageValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgePrivateMessageValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgePrivateMessageValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PrivateMessageInitiatingBinding) Build(body s26.PrivateMessage,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.UplinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (s45.UplinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s45.UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UplinkUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s45.UplinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UplinkUEAssociatedLPPaTransport,

		error)
	inject func(s45.UplinkUEAssociatedLPPaTransport,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Codec() s45.UplinkUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UplinkUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s45.UplinkUEAssociatedLPPaTransportValueCodec {
		sealed := s45.UplinkUEAssociatedLPPaTransportValueCodec{}
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s45.UplinkUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Build(body s45.UplinkUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkNonUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.UplinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (s45.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s45.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UplinkNonUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s45.UplinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UplinkNonUEAssociatedLPPaTransport,

		error)
	inject func(s45.UplinkNonUEAssociatedLPPaTransport,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Codec() s45.UplinkNonUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UplinkNonUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s45.UplinkNonUEAssociatedLPPaTransportValueCodec {
		sealed := s45.UplinkNonUEAssociatedLPPaTransportValueCodec{}
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s45.UplinkNonUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Build(body s45.UplinkNonUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityMatchRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityMatchRequest].
type UERadioCapabilityMatchRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UERadioCapabilityMatchRequest, aper.DecodeState,

	) (s37.UERadioCapabilityMatchRequest, aper.Snapshot,

	)
	compare func(s37.UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UERadioCapabilityMatchRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UERadioCapabilityMatchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UERadioCapabilityMatchRequest,

		error)
	inject func(s37.UERadioCapabilityMatchRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Codec() s37.UERadioCapabilityMatchRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UERadioCapabilityMatchRequestValueCodec{}
	}
	return func() s37.UERadioCapabilityMatchRequestValueCodec {
		sealed := s37.UERadioCapabilityMatchRequestValueCodec{}
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldEncode(&sealed) = func(value s37.UERadioCapabilityMatchRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUERadioCapabilityMatchRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Build(body s37.UERadioCapabilityMatchRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// RerouteNASRequestInitiatingBinding is the concrete InitiatingBinding[RerouteNASRequest].
type RerouteNASRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s27.RerouteNASRequest, aper.DecodeState,

	) (s27.RerouteNASRequest, aper.Snapshot,

	)
	compare func(s27.RerouteNASRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s27.RerouteNASRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s27.RerouteNASRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s27.RerouteNASRequest,

		error)
	inject func(s27.RerouteNASRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestInitiatingBinding) Codec() s27.RerouteNASRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s27.RerouteNASRequestValueCodec{}
	}
	return func() s27.RerouteNASRequestValueCodec {
		sealed := s27.RerouteNASRequestValueCodec{}
		*s27.BridgeRerouteNASRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s27.BridgeRerouteNASRequestValueCodecFieldDecode(&sealed) = b.decode
		*s27.BridgeRerouteNASRequestValueCodecFieldEncode(&sealed) = func(value s27.RerouteNASRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s27.BridgeRerouteNASRequestValueCodecFieldCapture(&sealed) = b.capture
		*s27.BridgeRerouteNASRequestValueCodecFieldCompare(&sealed) = b.compare
		*s27.BridgeRerouteNASRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b RerouteNASRequestInitiatingBinding) Build(body s27.RerouteNASRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationIndicationInitiatingBinding is the concrete InitiatingBinding[UEContextModificationIndication].
type UEContextModificationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UEContextModificationIndication, aper.DecodeState,

	) (s37.UEContextModificationIndication, aper.Snapshot,

	)
	compare func(s37.UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UEContextModificationIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UEContextModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UEContextModificationIndication,

		error)
	inject func(s37.UEContextModificationIndication,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Codec() s37.UEContextModificationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UEContextModificationIndicationValueCodec{}
	}
	return func() s37.UEContextModificationIndicationValueCodec {
		sealed := s37.UEContextModificationIndicationValueCodec{}
		*s37.BridgeUEContextModificationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUEContextModificationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUEContextModificationIndicationValueCodecFieldEncode(&sealed) = func(value s37.UEContextModificationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUEContextModificationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUEContextModificationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUEContextModificationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationIndicationInitiatingBinding) Build(body s37.UEContextModificationIndication,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextSuspendRequestInitiatingBinding is the concrete InitiatingBinding[UEContextSuspendRequest].
type UEContextSuspendRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.UEContextSuspendRequest, aper.DecodeState,

	) (s47.UEContextSuspendRequest, aper.Snapshot,

	)
	compare func(s47.UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.UEContextSuspendRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s47.UEContextSuspendRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.UEContextSuspendRequest,

		error)
	inject func(s47.UEContextSuspendRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Codec() s47.UEContextSuspendRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.UEContextSuspendRequestValueCodec{}
	}
	return func() s47.UEContextSuspendRequestValueCodec {
		sealed := s47.UEContextSuspendRequestValueCodec{}
		*s47.BridgeUEContextSuspendRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeUEContextSuspendRequestValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeUEContextSuspendRequestValueCodecFieldEncode(&sealed) = func(value s47.UEContextSuspendRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeUEContextSuspendRequestValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeUEContextSuspendRequestValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeUEContextSuspendRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendRequestInitiatingBinding) Build(body s47.UEContextSuspendRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextResumeRequestInitiatingBinding is the concrete InitiatingBinding[UEContextResumeRequest].
type UEContextResumeRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s39.UEContextResumeRequest, aper.DecodeState,

	) (s39.UEContextResumeRequest, aper.Snapshot,

	)
	compare func(s39.UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s39.UEContextResumeRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s39.UEContextResumeRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s39.UEContextResumeRequest,

		error)
	inject func(s39.UEContextResumeRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestInitiatingBinding) Codec() s39.UEContextResumeRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s39.UEContextResumeRequestValueCodec{}
	}
	return func() s39.UEContextResumeRequestValueCodec {
		sealed := s39.UEContextResumeRequestValueCodec{}
		*s39.BridgeUEContextResumeRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s39.BridgeUEContextResumeRequestValueCodecFieldDecode(&sealed) = b.decode
		*s39.BridgeUEContextResumeRequestValueCodecFieldEncode(&sealed) = func(value s39.UEContextResumeRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s39.BridgeUEContextResumeRequestValueCodecFieldCapture(&sealed) = b.capture
		*s39.BridgeUEContextResumeRequestValueCodecFieldCompare(&sealed) = b.compare
		*s39.BridgeUEContextResumeRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeRequestInitiatingBinding) Build(body s39.UEContextResumeRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// RetrieveUEInformationInitiatingBinding is the concrete InitiatingBinding[RetrieveUEInformation].
type RetrieveUEInformationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s28.RetrieveUEInformation, aper.DecodeState,

	) (s28.RetrieveUEInformation, aper.Snapshot,

	)
	compare func(s28.RetrieveUEInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.RetrieveUEInformation,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s28.RetrieveUEInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.RetrieveUEInformation,

		error)
	inject func(s28.RetrieveUEInformation,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b RetrieveUEInformationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RetrieveUEInformationInitiatingBinding) Codec() s28.RetrieveUEInformationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.RetrieveUEInformationValueCodec{}
	}
	return func() s28.RetrieveUEInformationValueCodec {
		sealed := s28.RetrieveUEInformationValueCodec{}
		*s28.BridgeRetrieveUEInformationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeRetrieveUEInformationValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeRetrieveUEInformationValueCodecFieldEncode(&sealed) = func(value s28.RetrieveUEInformation,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeRetrieveUEInformationValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeRetrieveUEInformationValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeRetrieveUEInformationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b RetrieveUEInformationInitiatingBinding) Build(body s28.RetrieveUEInformation,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEInformationTransferInitiatingBinding is the concrete InitiatingBinding[UEInformationTransfer].
type UEInformationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UEInformationTransfer, aper.DecodeState,

	) (s37.UEInformationTransfer, aper.Snapshot,

	)
	compare func(s37.UEInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UEInformationTransfer,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UEInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UEInformationTransfer,

		error)
	inject func(s37.UEInformationTransfer,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferInitiatingBinding) Codec() s37.UEInformationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UEInformationTransferValueCodec{}
	}
	return func() s37.UEInformationTransferValueCodec {
		sealed := s37.UEInformationTransferValueCodec{}
		*s37.BridgeUEInformationTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUEInformationTransferValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUEInformationTransferValueCodecFieldEncode(&sealed) = func(value s37.UEInformationTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUEInformationTransferValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUEInformationTransferValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUEInformationTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEInformationTransferInitiatingBinding) Build(body s37.UEInformationTransfer,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// SecondaryRATDataUsageReportInitiatingBinding is the concrete InitiatingBinding[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.SecondaryRATDataUsageReport, aper.DecodeState,

	) (s47.SecondaryRATDataUsageReport, aper.Snapshot,

	)
	compare func(s47.SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.SecondaryRATDataUsageReport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s47.SecondaryRATDataUsageReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.SecondaryRATDataUsageReport,

		error)
	inject func(s47.SecondaryRATDataUsageReport,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Codec() s47.SecondaryRATDataUsageReportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.SecondaryRATDataUsageReportValueCodec{}
	}
	return func() s47.SecondaryRATDataUsageReportValueCodec {
		sealed := s47.SecondaryRATDataUsageReportValueCodec{}
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldEncode(&sealed) = func(value s47.SecondaryRATDataUsageReport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeSecondaryRATDataUsageReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b SecondaryRATDataUsageReportInitiatingBinding) Build(body s47.SecondaryRATDataUsageReport,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityIDMappingRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityIDMappingRequest].
type UERadioCapabilityIDMappingRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UERadioCapabilityIDMappingRequest, aper.DecodeState,

	) (s37.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	)
	compare func(s37.UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UERadioCapabilityIDMappingRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UERadioCapabilityIDMappingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UERadioCapabilityIDMappingRequest,

		error)
	inject func(s37.UERadioCapabilityIDMappingRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Codec() s37.UERadioCapabilityIDMappingRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UERadioCapabilityIDMappingRequestValueCodec{}
	}
	return func() s37.UERadioCapabilityIDMappingRequestValueCodec {
		sealed := s37.UERadioCapabilityIDMappingRequestValueCodec{}
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldEncode(&sealed) = func(value s37.UERadioCapabilityIDMappingRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Build(body s37.UERadioCapabilityIDMappingRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1RemovalRequestInitiatingBinding is the concrete InitiatingBinding[S1RemovalRequest].
type S1RemovalRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s27.S1RemovalRequest, aper.DecodeState,

	) (s27.S1RemovalRequest, aper.Snapshot,

	)
	compare func(s27.S1RemovalRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s27.S1RemovalRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s27.S1RemovalRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s27.S1RemovalRequest,

		error)
	inject func(s27.S1RemovalRequest,

	) s52.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalRequestInitiatingBinding) Codec() s27.S1RemovalRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s27.S1RemovalRequestValueCodec{}
	}
	return func() s27.S1RemovalRequestValueCodec {
		sealed := s27.S1RemovalRequestValueCodec{}
		*s27.BridgeS1RemovalRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s27.BridgeS1RemovalRequestValueCodecFieldDecode(&sealed) = b.decode
		*s27.BridgeS1RemovalRequestValueCodecFieldEncode(&sealed) = func(value s27.S1RemovalRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s27.BridgeS1RemovalRequestValueCodecFieldCapture(&sealed) = b.capture
		*s27.BridgeS1RemovalRequestValueCodecFieldCompare(&sealed) = b.compare
		*s27.BridgeS1RemovalRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalRequestInitiatingBinding) Build(body s27.S1RemovalRequest,

	options ...aper.BuildOption) (s52.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s52.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s52.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s52.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1APPDUValueCodec is the concrete ValueCodec[S1APPDU].
type S1APPDUValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1APPDU,

		error)
	encode func(S1APPDU,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1APPDU, aper.DecodeState,

	) (S1APPDU, aper.Snapshot,

	)
	compare func(S1APPDU, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1APPDUValueCodec) New(value S1APPDU,

) (S1APPDUAPERValue, error) {
	if c.encode == nil {
		return S1APPDUAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1APPDUAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1APPDUAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1APPDUAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1APPDUValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1APPDUAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1APPDUAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1APPDUAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1APPDUAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1APPDUAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1APPDUValueCodec) EncodeAPER(value S1APPDUAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1APPDUValueCodec) encodeBudgetValue(value S1APPDU,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1APPDUValueCodec) encodeChanged(value S1APPDU,

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
func BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields s52.MMEConfigurationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s52.BridgeMMEConfigurationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s52.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s52.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields s51.SONConfigurationTransferExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.SONConfigurationTransferExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s51.SONConfigurationTransferExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields s39.X2TNLConfigurationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.X2TNLConfigurationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s39.X2TNLConfigurationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// MMEConfigurationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueERABIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s52.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
	codec := s52.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s52.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s52.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
		sealed := s52.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
		*s52.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s52.MMEConfigurationTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s52.MMEConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s52.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s52.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s52.MMEConfigurationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s52.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s52.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s52.MMEConfigurationTransferIEValueERABIEContainerList, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeMMEConfigurationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s52.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s52.MMEConfigurationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := s52.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s52.MMEConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s52.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s52.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationTransferIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable, bounds aper.ListBounds) s52.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
	codec := s52.MMEConfigurationTransferIEValueIETableCodec(table, bounds)
	if *s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s52.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s52.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s52.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s52.MMEConfigurationTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s52.MMEConfigurationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s52.BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s52.MMEConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s52.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s52.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s52.MMEConfigurationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s52.MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s52.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s52.MMEConfigurationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s52.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// mMEConfigurationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEConfigurationTransferIEValue].
type MMEConfigurationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s52.MMEConfigurationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s52.MMEConfigurationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// sONConfigurationTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SONConfigurationTransferExtIEsValue].
type SONConfigurationTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s51.SONConfigurationTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s51.SONConfigurationTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// x2TNLConfigurationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[X2TNLConfigurationInfoExtIEsValue].
type X2TNLConfigurationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s39.X2TNLConfigurationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s39.X2TNLConfigurationInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// S1APPDUAPERValue is the concrete APERValue[S1APPDU].
type S1APPDUAPERValue struct {
	context s00.BridgeCodecContext
	Value   S1APPDU

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1APPDUAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1APPDUAPERValue) WithoutReplay() S1APPDUAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(fields s51.SONConfigurationTransferExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s51.BridgeSONConfigurationTransferExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s51.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s51.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(fields s39.X2TNLConfigurationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s39.BridgeX2TNLConfigurationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s39.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s39.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(v *s52.MMEConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s52.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(v *s52.MMEConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(v *s52.MMEConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s52.BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APS1APPDU(v *S1APPDU, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
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
	case s00.S1APPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				s52.BridgeCaptureS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s51.BridgeCaptureS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s37.BridgeCaptureS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APS1APPDU(v *S1APPDU, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
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
	case s00.S1APPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				s52.BridgeCompareS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s51.BridgeCompareS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s37.BridgeCompareS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}

// S1APPDU represents the ASN.1 CHOICE type S1AP-PDU.
type S1APPDU struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	Choice              int
	perPadding          aper.CompletePadding     `json:"-"`
	perOpenTypePadding  aper.CompletePadding     `json:"-"`
	UnknownExtension    *aper.ChoiceExtension    `json:"UnknownExtension,omitempty"`
	InitiatingMessage   *s52.InitiatingMessage   `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *s51.SuccessfulOutcome   `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *s37.UnsuccessfulOutcome `json:"UnsuccessfulOutcome,omitempty"`
}

// NewS1APPDUInitiatingMessage creates a S1APPDU with the initiatingMessage alternative.
func BridgeNewS1APPDUInitiatingMessageLegacy(v s52.InitiatingMessage) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewS1APPDUSuccessfulOutcome creates a S1APPDU with the successfulOutcome alternative.
func BridgeNewS1APPDUSuccessfulOutcomeLegacy(v s51.SuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewS1APPDUUnsuccessfulOutcome creates a S1APPDU with the unsuccessfulOutcome alternative.
func BridgeNewS1APPDUUnsuccessfulOutcomeLegacy(v s37.UnsuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:              s00.S1APPDUChoiceUnsuccessfulOutcome,
		UnsuccessfulOutcome: &v,
	}
}

// MarshalAPER encodes S1APPDU to APER format.
func (v *S1APPDU) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *S1APPDU) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "S1APPDU:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "S1APPDU:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "S1APPDU:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "S1APPDU:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return fmt.Errorf("choice alternative initiatingMessage is nil")
		}
		if err := s52.BridgeInitiatingMessageMethodMarshalAPERTo(v.InitiatingMessage, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := s51.BridgeSuccessfulOutcomeMethodMarshalAPERTo(v.SuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := s37.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v.UnsuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding unsuccessfulOutcome: %w", err)
		}
	default:
		return fmt.Errorf("unknown S1APPDU choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes S1APPDU from APER format.
func (v *S1APPDU) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes S1APPDU with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *S1APPDU) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "S1APPDU")
	}
	bb.EnterComponent("S1APPDU")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1APPDU")
	}
	padding, err := aper.CaptureFinalBits(bb, "S1APPDU")
	if err != nil {
		return runtime.WrapDecodePath(err, "S1APPDU")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *S1APPDU) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1APPDU{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

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
	case s00.S1APPDUChoiceInitiatingMessage:
		toleranceMark_initiatingmessage := bb.EnterComponent("InitiatingMessage")
		var dec_initiatingmessage s52.InitiatingMessage
		if err := s52.BridgeInitiatingMessageMethodUnmarshalAPERFrom(&dec_initiatingmessage, bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		if err := aper.ChargeValue(bb, dec_initiatingmessage); err != nil {
			return err
		}
		v.InitiatingMessage = &dec_initiatingmessage
		bb.LeaveComponent(toleranceMark_initiatingmessage)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		toleranceMark_successfuloutcome := bb.EnterComponent("SuccessfulOutcome")
		var dec_successfuloutcome s51.SuccessfulOutcome
		if err := s51.BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_successfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_successfuloutcome); err != nil {
			return err
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
		bb.LeaveComponent(toleranceMark_successfuloutcome)
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		toleranceMark_unsuccessfuloutcome := bb.EnterComponent("UnsuccessfulOutcome")
		var dec_unsuccessfuloutcome s37.UnsuccessfulOutcome
		if err := s37.BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_unsuccessfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_unsuccessfuloutcome); err != nil {
			return err
		}
		v.UnsuccessfulOutcome = &dec_unsuccessfuloutcome
		bb.LeaveComponent(toleranceMark_unsuccessfuloutcome)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *S1APPDU) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1APPDU", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "S1APPDU", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v S1APPDU) WithoutReplay() S1APPDU {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero S1APPDU
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *S1APPDU) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "S1APPDU")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *S1APPDU) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "S1APPDU")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APS1APPDU(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "S1APPDU")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "S1APPDU")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *S1APPDU) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "S1APPDU")
}
func (v *S1APPDU) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "S1APPDU")
}
func (v *S1APPDU) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APS1APPDU(v, &s)
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
func (v *S1APPDU) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *S1APPDU) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *S1APPDU) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "S1APPDU")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded S1APPDU
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APS1APPDU(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = S1APPDU{}
		return report, aper.OperationError(err, "S1APPDU")
	}
	*v = decoded
	return report, aper.OperationError(nil, "S1APPDU")
}

// NewS1APPDUInitiatingMessage constructs and validates a complete S1AP message.
func NewS1APPDUInitiatingMessage(v s52.InitiatingMessage, options ...aper.BuildOption) (S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	value := BridgeNewS1APPDUInitiatingMessageLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return S1APPDU{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1APPDUInitiatingMessage")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return S1APPDU{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1APPDUInitiatingMessage")
	}
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUInitiatingMessage")
	}
	return value, aper.OperationError(nil, "S1APPDUInitiatingMessage")
}

// NewS1APPDUSuccessfulOutcome constructs and validates a complete S1AP message.
func NewS1APPDUSuccessfulOutcome(v s51.SuccessfulOutcome, options ...aper.BuildOption) (S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	value := BridgeNewS1APPDUSuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return S1APPDU{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1APPDUSuccessfulOutcome")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return S1APPDU{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1APPDUSuccessfulOutcome")
	}
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUSuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "S1APPDUSuccessfulOutcome")
}

// NewS1APPDUUnsuccessfulOutcome constructs and validates a complete S1AP message.
func NewS1APPDUUnsuccessfulOutcome(v s37.UnsuccessfulOutcome, options ...aper.BuildOption) (S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	value := BridgeNewS1APPDUUnsuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return S1APPDU{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1APPDUUnsuccessfulOutcome")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return S1APPDU{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1APPDUUnsuccessfulOutcome")
	}
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnsuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "S1APPDUUnsuccessfulOutcome")
}

// NewS1APPDUUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewS1APPDUUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (S1APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnknownExtension")
	}
	value := S1APPDU{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return S1APPDU{}, aper.OperationError(err, "S1APPDUUnknownExtension")
	}
	return value, aper.OperationError(nil, "S1APPDUUnknownExtension")
}

type PathSwitchRequestDescriptor struct{}

func PathSwitchRequestProcedure() PathSwitchRequestDescriptor { return PathSwitchRequestDescriptor{} }

// Info returns the source-derived procedure metadata for PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(3), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-PathSwitchRequest"}}}
}

type UplinkNASTransportDescriptor struct{}

func UplinkNASTransportProcedure() UplinkNASTransportDescriptor {
	return UplinkNASTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for UplinkNASTransportDescriptor.
func (UplinkNASTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(13), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-uplinkNASTransport"}}}
}

type ResetDescriptor struct{}

func ResetProcedure() ResetDescriptor { return ResetDescriptor{} }

// Info returns the source-derived procedure metadata for ResetDescriptor.
func (ResetDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(14), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-Reset"}}}
}

type S1SetupDescriptor struct{}

func S1SetupProcedure() S1SetupDescriptor { return S1SetupDescriptor{} }

// Info returns the source-derived procedure metadata for S1SetupDescriptor.
func (S1SetupDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(17), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-S1Setup"}}}
}

type UEContextReleaseRequestDescriptor struct{}

func UEContextReleaseRequestProcedure() UEContextReleaseRequestDescriptor {
	return UEContextReleaseRequestDescriptor{}
}

// Info returns the source-derived procedure metadata for UEContextReleaseRequestDescriptor.
func (UEContextReleaseRequestDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(18), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextReleaseRequest"}}}
}

type UplinkS1cdma2000tunnellingDescriptor struct{}

func UplinkS1cdma2000tunnellingProcedure() UplinkS1cdma2000tunnellingDescriptor {
	return UplinkS1cdma2000tunnellingDescriptor{}
}

// Info returns the source-derived procedure metadata for UplinkS1cdma2000tunnellingDescriptor.
func (UplinkS1cdma2000tunnellingDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(20), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UplinkS1cdma2000tunnelling"}}}
}

type UEContextModificationDescriptor struct{}

func UEContextModificationProcedure() UEContextModificationDescriptor {
	return UEContextModificationDescriptor{}
}

// Info returns the source-derived procedure metadata for UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(21), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextModification"}}}
}

type UECapabilityInfoIndicationDescriptor struct{}

func UECapabilityInfoIndicationProcedure() UECapabilityInfoIndicationDescriptor {
	return UECapabilityInfoIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for UECapabilityInfoIndicationDescriptor.
func (UECapabilityInfoIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(22), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UECapabilityInfoIndication"}}}
}

type UEContextReleaseDescriptor struct{}

func UEContextReleaseProcedure() UEContextReleaseDescriptor { return UEContextReleaseDescriptor{} }

// Info returns the source-derived procedure metadata for UEContextReleaseDescriptor.
func (UEContextReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(23), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextRelease"}}}
}

type TraceStartDescriptor struct{}

func TraceStartProcedure() TraceStartDescriptor { return TraceStartDescriptor{} }

// Info returns the source-derived procedure metadata for TraceStartDescriptor.
func (TraceStartDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(27), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-TraceStart"}}}
}

type TraceFailureIndicationDescriptor struct{}

func TraceFailureIndicationProcedure() TraceFailureIndicationDescriptor {
	return TraceFailureIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for TraceFailureIndicationDescriptor.
func (TraceFailureIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(28), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-TraceFailureIndication"}}}
}

type WriteReplaceWarningDescriptor struct{}

func WriteReplaceWarningProcedure() WriteReplaceWarningDescriptor {
	return WriteReplaceWarningDescriptor{}
}

// Info returns the source-derived procedure metadata for WriteReplaceWarningDescriptor.
func (WriteReplaceWarningDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(36), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-WriteReplaceWarning"}}}
}

type PrivateMessageDescriptor struct{}

func PrivateMessageProcedure() PrivateMessageDescriptor { return PrivateMessageDescriptor{} }

// Info returns the source-derived procedure metadata for PrivateMessageDescriptor.
func (PrivateMessageDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(39), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-PrivateMessage"}}}
}

type ENBConfigurationTransferDescriptor struct{}

func ENBConfigurationTransferProcedure() ENBConfigurationTransferDescriptor {
	return ENBConfigurationTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for ENBConfigurationTransferDescriptor.
func (ENBConfigurationTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(40), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-eNBConfigurationTransfer"}}}
}

type MMEConfigurationTransferDescriptor struct{}

func MMEConfigurationTransferProcedure() MMEConfigurationTransferDescriptor {
	return MMEConfigurationTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for MMEConfigurationTransferDescriptor.
func (MMEConfigurationTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(41), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-MMEConfigurationTransfer"}}}
}

type UplinkUEAssociatedLPPaTransportDescriptor struct{}

func UplinkUEAssociatedLPPaTransportProcedure() UplinkUEAssociatedLPPaTransportDescriptor {
	return UplinkUEAssociatedLPPaTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for UplinkUEAssociatedLPPaTransportDescriptor.
func (UplinkUEAssociatedLPPaTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(45), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-uplinkUEAssociatedLPPaTransport"}}}
}

type UplinkNonUEAssociatedLPPaTransportDescriptor struct{}

func UplinkNonUEAssociatedLPPaTransportProcedure() UplinkNonUEAssociatedLPPaTransportDescriptor {
	return UplinkNonUEAssociatedLPPaTransportDescriptor{}
}

// Info returns the source-derived procedure metadata for UplinkNonUEAssociatedLPPaTransportDescriptor.
func (UplinkNonUEAssociatedLPPaTransportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(47), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-uplinkNonUEAssociatedLPPaTransport"}}}
}

type UERadioCapabilityMatchDescriptor struct{}

func UERadioCapabilityMatchProcedure() UERadioCapabilityMatchDescriptor {
	return UERadioCapabilityMatchDescriptor{}
}

// Info returns the source-derived procedure metadata for UERadioCapabilityMatchDescriptor.
func (UERadioCapabilityMatchDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(48), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UERadioCapabilityMatch"}}}
}

type RerouteNASRequestDescriptor struct{}

func RerouteNASRequestProcedure() RerouteNASRequestDescriptor { return RerouteNASRequestDescriptor{} }

// Info returns the source-derived procedure metadata for RerouteNASRequestDescriptor.
func (RerouteNASRequestDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(52), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-RerouteNASRequest"}}}
}

type UEContextModificationIndicationDescriptor struct{}

func UEContextModificationIndicationProcedure() UEContextModificationIndicationDescriptor {
	return UEContextModificationIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for UEContextModificationIndicationDescriptor.
func (UEContextModificationIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(53), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextModificationIndication"}}}
}

type UEContextSuspendDescriptor struct{}

func UEContextSuspendProcedure() UEContextSuspendDescriptor { return UEContextSuspendDescriptor{} }

// Info returns the source-derived procedure metadata for UEContextSuspendDescriptor.
func (UEContextSuspendDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(55), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextSuspend"}}}
}

type UEContextResumeDescriptor struct{}

func UEContextResumeProcedure() UEContextResumeDescriptor { return UEContextResumeDescriptor{} }

// Info returns the source-derived procedure metadata for UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(56), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEContextResume"}}}
}

type RetrieveUEInformationDescriptor struct{}

func RetrieveUEInformationProcedure() RetrieveUEInformationDescriptor {
	return RetrieveUEInformationDescriptor{}
}

// Info returns the source-derived procedure metadata for RetrieveUEInformationDescriptor.
func (RetrieveUEInformationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(58), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-RetrieveUEInformation"}}}
}

type UEInformationTransferDescriptor struct{}

func UEInformationTransferProcedure() UEInformationTransferDescriptor {
	return UEInformationTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for UEInformationTransferDescriptor.
func (UEInformationTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(59), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UEInformationTransfer"}}}
}

type SecondaryRATDataUsageReportDescriptor struct{}

func SecondaryRATDataUsageReportProcedure() SecondaryRATDataUsageReportDescriptor {
	return SecondaryRATDataUsageReportDescriptor{}
}

// Info returns the source-derived procedure metadata for SecondaryRATDataUsageReportDescriptor.
func (SecondaryRATDataUsageReportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(62), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-SecondaryRATDataUsageReport"}}}
}

type UERadioCapabilityIDMappingDescriptor struct{}

func UERadioCapabilityIDMappingProcedure() UERadioCapabilityIDMappingDescriptor {
	return UERadioCapabilityIDMappingDescriptor{}
}

// Info returns the source-derived procedure metadata for UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(63), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-UERadioCapabilityIDMapping"}}}
}

type S1RemovalDescriptor struct{}

func S1RemovalProcedure() S1RemovalDescriptor { return S1RemovalDescriptor{} }

// Info returns the source-derived procedure metadata for S1RemovalDescriptor.
func (S1RemovalDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(67), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-S1Removal"}}}
}

// ENBConfigurationTransferCodec binds the complete APER value type.
func ENBConfigurationTransferCodec() s52.ENBConfigurationTransferValueCodec {
	return ENBConfigurationTransferProcedure().Initiating().Codec()
}

// MMEConfigurationTransferCodec binds the complete APER value type.
func MMEConfigurationTransferCodec() s52.MMEConfigurationTransferValueCodec {
	return MMEConfigurationTransferProcedure().Initiating().Codec()
}

// PathSwitchRequestAcknowledgeCodec binds the complete APER value type.
func PathSwitchRequestAcknowledgeCodec() s48.PathSwitchRequestAcknowledgeValueCodec {
	return PathSwitchRequestProcedure().Successful().Codec()
}

// PathSwitchRequestCodec binds the complete APER value type.
func PathSwitchRequestCodec() s41.PathSwitchRequestValueCodec {
	return PathSwitchRequestProcedure().Initiating().Codec()
}

// PathSwitchRequestFailureCodec binds the complete APER value type.
func PathSwitchRequestFailureCodec() s26.PathSwitchRequestFailureValueCodec {
	return PathSwitchRequestProcedure().Unsuccessful().Codec()
}

// PrivateMessageCodec binds the complete APER value type.
func PrivateMessageCodec() s26.PrivateMessageValueCodec {
	return PrivateMessageProcedure().Initiating().Codec()
}

// RerouteNASRequestCodec binds the complete APER value type.
func RerouteNASRequestCodec() s27.RerouteNASRequestValueCodec {
	return RerouteNASRequestProcedure().Initiating().Codec()
}

// ResetAcknowledgeCodec binds the complete APER value type.
func ResetAcknowledgeCodec() s45.ResetAcknowledgeValueCodec {
	return ResetProcedure().Successful().Codec()
}

// ResetCodec binds the complete APER value type.
func ResetCodec() s36.ResetValueCodec { return ResetProcedure().Initiating().Codec() }

// RetrieveUEInformationCodec binds the complete APER value type.
func RetrieveUEInformationCodec() s28.RetrieveUEInformationValueCodec {
	return RetrieveUEInformationProcedure().Initiating().Codec()
}

// S1APPDUCodec binds the complete source value type.
func S1APPDUCodec() S1APPDUValueCodec {
	return S1APPDUValueCodec{path: "S1APPDU", decode: func(data []byte, options aper.DecodeState) (S1APPDU, error) {
		var value S1APPDU
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return S1APPDU{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value S1APPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v S1APPDU, options aper.DecodeState) (S1APPDU, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APS1APPDU(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v S1APPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APS1APPDU(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1APPDU"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// S1RemovalFailureCodec binds the complete APER value type.
func S1RemovalFailureCodec() s27.S1RemovalFailureValueCodec {
	return S1RemovalProcedure().Unsuccessful().Codec()
}

// S1RemovalRequestCodec binds the complete APER value type.
func S1RemovalRequestCodec() s27.S1RemovalRequestValueCodec {
	return S1RemovalProcedure().Initiating().Codec()
}

// S1RemovalResponseCodec binds the complete APER value type.
func S1RemovalResponseCodec() s27.S1RemovalResponseValueCodec {
	return S1RemovalProcedure().Successful().Codec()
}

// S1SetupFailureCodec binds the complete APER value type.
func S1SetupFailureCodec() s27.S1SetupFailureValueCodec {
	return S1SetupProcedure().Unsuccessful().Codec()
}

// S1SetupRequestCodec binds the complete APER value type.
func S1SetupRequestCodec() s44.S1SetupRequestValueCodec {
	return S1SetupProcedure().Initiating().Codec()
}

// S1SetupResponseCodec binds the complete APER value type.
func S1SetupResponseCodec() s44.S1SetupResponseValueCodec {
	return S1SetupProcedure().Successful().Codec()
}

// SecondaryRATDataUsageReportCodec binds the complete APER value type.
func SecondaryRATDataUsageReportCodec() s47.SecondaryRATDataUsageReportValueCodec {
	return SecondaryRATDataUsageReportProcedure().Initiating().Codec()
}

// TraceFailureIndicationCodec binds the complete APER value type.
func TraceFailureIndicationCodec() s35.TraceFailureIndicationValueCodec {
	return TraceFailureIndicationProcedure().Initiating().Codec()
}

// TraceStartCodec binds the complete APER value type.
func TraceStartCodec() s49.TraceStartValueCodec { return TraceStartProcedure().Initiating().Codec() }

// UECapabilityInfoIndicationCodec binds the complete APER value type.
func UECapabilityInfoIndicationCodec() s36.UECapabilityInfoIndicationValueCodec {
	return UECapabilityInfoIndicationProcedure().Initiating().Codec()
}

// UEContextModificationConfirmCodec binds the complete APER value type.
func UEContextModificationConfirmCodec() s36.UEContextModificationConfirmValueCodec {
	return UEContextModificationIndicationProcedure().Successful().Codec()
}

// UEContextModificationFailureCodec binds the complete APER value type.
func UEContextModificationFailureCodec() s36.UEContextModificationFailureValueCodec {
	return UEContextModificationProcedure().Unsuccessful().Codec()
}

// UEContextModificationIndicationCodec binds the complete APER value type.
func UEContextModificationIndicationCodec() s37.UEContextModificationIndicationValueCodec {
	return UEContextModificationIndicationProcedure().Initiating().Codec()
}

// UEContextModificationRequestCodec binds the complete APER value type.
func UEContextModificationRequestCodec() s48.UEContextModificationRequestValueCodec {
	return UEContextModificationProcedure().Initiating().Codec()
}

// UEContextModificationResponseCodec binds the complete APER value type.
func UEContextModificationResponseCodec() s37.UEContextModificationResponseValueCodec {
	return UEContextModificationProcedure().Successful().Codec()
}

// UEContextReleaseCommandCodec binds the complete APER value type.
func UEContextReleaseCommandCodec() s37.UEContextReleaseCommandValueCodec {
	return UEContextReleaseProcedure().Initiating().Codec()
}

// UEContextReleaseCompleteCodec binds the complete APER value type.
func UEContextReleaseCompleteCodec() s47.UEContextReleaseCompleteValueCodec {
	return UEContextReleaseProcedure().Successful().Codec()
}

// UEContextReleaseRequestCodec binds the complete APER value type.
func UEContextReleaseRequestCodec() s43.UEContextReleaseRequestValueCodec {
	return UEContextReleaseRequestProcedure().Initiating().Codec()
}

// UEContextResumeFailureCodec binds the complete APER value type.
func UEContextResumeFailureCodec() s37.UEContextResumeFailureValueCodec {
	return UEContextResumeProcedure().Unsuccessful().Codec()
}

// UEContextResumeRequestCodec binds the complete APER value type.
func UEContextResumeRequestCodec() s39.UEContextResumeRequestValueCodec {
	return UEContextResumeProcedure().Initiating().Codec()
}

// UEContextResumeResponseCodec binds the complete APER value type.
func UEContextResumeResponseCodec() s39.UEContextResumeResponseValueCodec {
	return UEContextResumeProcedure().Successful().Codec()
}

// UEContextSuspendRequestCodec binds the complete APER value type.
func UEContextSuspendRequestCodec() s47.UEContextSuspendRequestValueCodec {
	return UEContextSuspendProcedure().Initiating().Codec()
}

// UEContextSuspendResponseCodec binds the complete APER value type.
func UEContextSuspendResponseCodec() s37.UEContextSuspendResponseValueCodec {
	return UEContextSuspendProcedure().Successful().Codec()
}

// UEInformationTransferCodec binds the complete APER value type.
func UEInformationTransferCodec() s37.UEInformationTransferValueCodec {
	return UEInformationTransferProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingRequestCodec binds the complete APER value type.
func UERadioCapabilityIDMappingRequestCodec() s37.UERadioCapabilityIDMappingRequestValueCodec {
	return UERadioCapabilityIDMappingProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingResponseCodec binds the complete APER value type.
func UERadioCapabilityIDMappingResponseCodec() s37.UERadioCapabilityIDMappingResponseValueCodec {
	return UERadioCapabilityIDMappingProcedure().Successful().Codec()
}

// UERadioCapabilityMatchRequestCodec binds the complete APER value type.
func UERadioCapabilityMatchRequestCodec() s37.UERadioCapabilityMatchRequestValueCodec {
	return UERadioCapabilityMatchProcedure().Initiating().Codec()
}

// UERadioCapabilityMatchResponseCodec binds the complete APER value type.
func UERadioCapabilityMatchResponseCodec() s37.UERadioCapabilityMatchResponseValueCodec {
	return UERadioCapabilityMatchProcedure().Successful().Codec()
}

// UplinkNASTransportCodec binds the complete APER value type.
func UplinkNASTransportCodec() s45.UplinkNASTransportValueCodec {
	return UplinkNASTransportProcedure().Initiating().Codec()
}

// UplinkNonUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkNonUEAssociatedLPPaTransportCodec() s45.UplinkNonUEAssociatedLPPaTransportValueCodec {
	return UplinkNonUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// UplinkS1cdma2000tunnellingCodec binds the complete APER value type.
func UplinkS1cdma2000tunnellingCodec() s45.UplinkS1cdma2000tunnellingValueCodec {
	return UplinkS1cdma2000tunnellingProcedure().Initiating().Codec()
}

// UplinkUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkUEAssociatedLPPaTransportCodec() s45.UplinkUEAssociatedLPPaTransportValueCodec {
	return UplinkUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// WriteReplaceWarningRequestCodec binds the complete APER value type.
func WriteReplaceWarningRequestCodec() s51.WriteReplaceWarningRequestValueCodec {
	return WriteReplaceWarningProcedure().Initiating().Codec()
}

// WriteReplaceWarningResponseCodec binds the complete APER value type.
func WriteReplaceWarningResponseCodec() s51.WriteReplaceWarningResponseValueCodec {
	return WriteReplaceWarningProcedure().Successful().Codec()
}
func BridgeValidateENBConfigurationTransferBudget(v *s52.ENBConfigurationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s52.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s52.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s52.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
	report := s52.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationTransfer(v, &report, "ENBConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateMMEConfigurationTransferBudget(v *s52.MMEConfigurationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s52.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s52.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s52.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
	report := BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationTransfer(v, &report, "MMEConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateInitiatingMessage(v *s52.InitiatingMessage, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitiatingMessage")
	}
	if *s52.BridgeInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverRequired()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequired", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateHandoverRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateHandoverRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		body, ok := v.Value.AsHandoverNotify()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverNotify", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateHandoverNotifyBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverNotificationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidatePathSwitchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsHandoverCancel()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCancel", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateHandoverCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsERABSetupRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABSetupRequest", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateERABSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsERABModifyRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModifyRequest", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateERABModifyRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABModifyProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsERABReleaseCommand()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseCommand", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateERABReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsERABReleaseIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseIndication", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateERABReleaseIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABReleaseIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateInitialContextSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		body, ok := v.Value.AsPaging()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing Paging", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidatePagingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.PagingProcedure().Info().Rule}})
		}
		return report, nil
	case 11:
		body, ok := v.Value.AsDownlinkNASTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkNASTransport", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateDownlinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.DownlinkNASTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 12:
		body, ok := v.Value.AsInitialUEMessage()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialUEMessage", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateInitialUEMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.InitialUEMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 13:
		body, ok := v.Value.AsUplinkNASTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkNASTransport", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUplinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkNASTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 14:
		body, ok := v.Value.AsReset()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing Reset", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateResetBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		body, ok := v.Value.AsErrorIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ErrorIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ErrorIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 16:
		body, ok := v.Value.AsNASNonDeliveryIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing NASNonDeliveryIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateNASNonDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.NASNonDeliveryIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 17:
		body, ok := v.Value.AsS1SetupRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupRequest", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateS1SetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		body, ok := v.Value.AsUEContextReleaseRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextReleaseRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 19:
		body, ok := v.Value.AsDownlinkS1cdma2000tunnelling()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkS1cdma2000tunnelling", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateDownlinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.DownlinkS1cdma2000tunnellingProcedure().Info().Rule}})
		}
		return report, nil
	case 20:
		body, ok := v.Value.AsUplinkS1cdma2000tunnelling()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkS1cdma2000tunnelling", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUplinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkS1cdma2000tunnellingProcedure().Info().Rule}})
		}
		return report, nil
	case 21:
		body, ok := v.Value.AsUEContextModificationRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextModificationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		body, ok := v.Value.AsUECapabilityInfoIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UECapabilityInfoIndication", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUECapabilityInfoIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UECapabilityInfoIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 23:
		body, ok := v.Value.AsUEContextReleaseCommand()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseCommand", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		body, ok := v.Value.AsENBStatusTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateENBStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 25:
		body, ok := v.Value.AsMMEStatusTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateMMEStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 26:
		body, ok := v.Value.AsDeactivateTrace()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DeactivateTrace", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateDeactivateTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.DeactivateTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 27:
		body, ok := v.Value.AsTraceStart()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing TraceStart", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateTraceStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{TraceStartProcedure().Info().Rule}})
		}
		return report, nil
	case 28:
		body, ok := v.Value.AsTraceFailureIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing TraceFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateTraceFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{TraceFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdate()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdate", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateENBConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdate()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdate", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateMMEConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		body, ok := v.Value.AsLocationReportingControl()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReportingControl", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateLocationReportingControlBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.LocationReportingControlProcedure().Info().Rule}})
		}
		return report, nil
	case 32:
		body, ok := v.Value.AsLocationReportingFailureIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReportingFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateLocationReportingFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.LocationReportingFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 33:
		body, ok := v.Value.AsLocationReport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing LocationReport", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateLocationReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.LocationReportProcedure().Info().Rule}})
		}
		return report, nil
	case 34:
		body, ok := v.Value.AsOverloadStart()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OverloadStart", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateOverloadStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.OverloadStartProcedure().Info().Rule}})
		}
		return report, nil
	case 35:
		body, ok := v.Value.AsOverloadStop()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OverloadStop", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateOverloadStopBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.OverloadStopProcedure().Info().Rule}})
		}
		return report, nil
	case 36:
		body, ok := v.Value.AsWriteReplaceWarningRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing WriteReplaceWarningRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateWriteReplaceWarningRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{WriteReplaceWarningProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		body, ok := v.Value.AsENBDirectInformationTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBDirectInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateENBDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBDirectInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 38:
		body, ok := v.Value.AsMMEDirectInformationTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEDirectInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateMMEDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEDirectInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 39:
		body, ok := v.Value.AsPrivateMessage()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PrivateMessage", "InitiatingMessage.value:")
		}
		report, err := s48.BridgeValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PrivateMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 40:
		body, ok := v.Value.AsENBConfigurationTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationTransfer", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateENBConfigurationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ENBConfigurationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 41:
		body, ok := v.Value.AsMMEConfigurationTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationTransfer", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateMMEConfigurationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{MMEConfigurationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 42:
		body, ok := v.Value.AsCellTrafficTrace()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing CellTrafficTrace", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateCellTrafficTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.CellTrafficTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 43:
		body, ok := v.Value.AsKillRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing KillRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateKillRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.KillProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		body, ok := v.Value.AsDownlinkUEAssociatedLPPaTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.DownlinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 45:
		body, ok := v.Value.AsUplinkUEAssociatedLPPaTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 46:
		body, ok := v.Value.AsDownlinkNonUEAssociatedLPPaTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing DownlinkNonUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.DownlinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 47:
		body, ok := v.Value.AsUplinkNonUEAssociatedLPPaTransport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UplinkNonUEAssociatedLPPaTransport", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
		}
		return report, nil
	case 48:
		body, ok := v.Value.AsUERadioCapabilityMatchRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityMatchRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUERadioCapabilityMatchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityMatchProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		body, ok := v.Value.AsPWSRestartIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PWSRestartIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidatePWSRestartIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.PWSRestartIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 50:
		body, ok := v.Value.AsERABModificationIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModificationIndication", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateERABModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		body, ok := v.Value.AsPWSFailureIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PWSFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidatePWSFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.PWSFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 52:
		body, ok := v.Value.AsRerouteNASRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing RerouteNASRequest", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateRerouteNASRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{RerouteNASRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 53:
		body, ok := v.Value.AsUEContextModificationIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationIndication", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		body, ok := v.Value.AsConnectionEstablishmentIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ConnectionEstablishmentIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateConnectionEstablishmentIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ConnectionEstablishmentIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 55:
		body, ok := v.Value.AsUEContextSuspendRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextSuspendRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextSuspendRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextSuspendProcedure().Info().Rule}})
		}
		return report, nil
	case 56:
		body, ok := v.Value.AsUEContextResumeRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEContextResumeRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		body, ok := v.Value.AsNASDeliveryIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing NASDeliveryIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateNASDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.NASDeliveryIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 58:
		body, ok := v.Value.AsRetrieveUEInformation()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing RetrieveUEInformation", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateRetrieveUEInformationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{RetrieveUEInformationProcedure().Info().Rule}})
		}
		return report, nil
	case 59:
		body, ok := v.Value.AsUEInformationTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEInformationTransfer", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUEInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEInformationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 60:
		body, ok := v.Value.AsENBCPRelocationIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBCPRelocationIndication", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateENBCPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBCPRelocationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 61:
		body, ok := v.Value.AsMMECPRelocationIndication()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMECPRelocationIndication", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateMMECPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMECPRelocationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 62:
		body, ok := v.Value.AsSecondaryRATDataUsageReport()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing SecondaryRATDataUsageReport", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateSecondaryRATDataUsageReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{SecondaryRATDataUsageReportProcedure().Info().Rule}})
		}
		return report, nil
	case 63:
		body, ok := v.Value.AsUERadioCapabilityIDMappingRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityIDMappingRequest", "InitiatingMessage.value:")
		}
		report, err := s51.BridgeValidateUERadioCapabilityIDMappingRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 64:
		body, ok := v.Value.AsHandoverSuccess()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverSuccess", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateHandoverSuccessBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverSuccessProcedure().Info().Rule}})
		}
		return report, nil
	case 65:
		body, ok := v.Value.AsENBEarlyStatusTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBEarlyStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateENBEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBEarlyStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 66:
		body, ok := v.Value.AsMMEEarlyStatusTransfer()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEEarlyStatusTransfer", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateMMEEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEEarlyStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 67:
		body, ok := v.Value.AsS1RemovalRequest()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalRequest", "InitiatingMessage.value:")
		}
		report, err := s50.BridgeValidateS1RemovalRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}
func BridgeValidateSuccessfulOutcome(v *s51.SuccessfulOutcome, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SuccessfulOutcome")
	}
	if *s51.BridgeSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverCommand()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCommand", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateHandoverCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverRequestAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequestAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateHandoverRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequestAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequestAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidatePathSwitchRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsHandoverCancelAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCancelAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateHandoverCancelAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsERABSetupResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABSetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateERABSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsERABModifyResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModifyResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateERABModifyResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABModifyProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsERABReleaseResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateERABReleaseResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateInitialContextSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		body, ok := v.Value.AsResetAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ResetAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateResetAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		body, ok := v.Value.AsS1SetupResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateS1SetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsUEContextModificationResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextModificationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 23:
		body, ok := v.Value.AsUEContextReleaseComplete()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseComplete", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextReleaseCompleteBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdateAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdateAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateENBConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdateAcknowledge()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdateAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		body, ok := v.Value.AsWriteReplaceWarningResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing WriteReplaceWarningResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateWriteReplaceWarningResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{WriteReplaceWarningProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		body, ok := v.Value.AsKillResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing KillResponse", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateKillResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.KillProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		body, ok := v.Value.AsUERadioCapabilityMatchResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityMatchResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUERadioCapabilityMatchResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityMatchProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		body, ok := v.Value.AsERABModificationConfirm()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModificationConfirm", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateERABModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ERABModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		body, ok := v.Value.AsUEContextModificationConfirm()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationConfirm", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 55:
		body, ok := v.Value.AsUEContextSuspendResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextSuspendResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextSuspendResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextSuspendProcedure().Info().Rule}})
		}
		return report, nil
	case 56:
		body, ok := v.Value.AsUEContextResumeResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextResumeResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 63:
		body, ok := v.Value.AsUERadioCapabilityIDMappingResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityIDMappingResponse", "SuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUERadioCapabilityIDMappingResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 64:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 67:
		body, ok := v.Value.AsS1RemovalResponse()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalResponse", "SuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateS1RemovalResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateUnsuccessfulOutcome(v *s37.UnsuccessfulOutcome, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UnsuccessfulOutcome")
	}
	if *s37.BridgeUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverPreparationFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverPreparationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateHandoverPreparationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateHandoverFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequestFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequestFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidatePathSwitchRequestFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 7:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 8:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateInitialContextSetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 15:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		body, ok := v.Value.AsS1SetupFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateS1SetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsUEContextModificationFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextModificationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 23:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 24:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdateFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdateFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateENBConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdateFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdateFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateMMEConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s52.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 37:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 44:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 49:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 51:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 54:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 55:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 56:
		body, ok := v.Value.AsUEContextResumeFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s51.BridgeValidateUEContextResumeFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 63:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 64:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s27.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 67:
		body, ok := v.Value.AsS1RemovalFailure()
		if !ok {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s50.BridgeValidateS1RemovalFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s27.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "UnsuccessfulOutcome.value"})
			return report
		}(), nil
	}
}

// TS 36.413 V19.2.0 §9.3.2 and X.691 (02/2021) §§11.2.1,23 select one complete PDU alternative.
func BridgeValidateMessageBudget(v *S1APPDU, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1APPDU")
	}
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s known choice %d and unknown extension are both selected", "S1APPDU:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s extension index %d must be non-negative", "S1APPDU:", v.UnknownExtension.Index())
		}
		if len(v.UnknownExtension.Contents()) == 0 {
			return func() s21.ValidationReport {
				sealed := s21.ValidationReport{}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s unknown extension requires a complete encoding", "S1APPDU:")
		}
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "S1APPDU.unknownExtension"})
			return report
		}(), nil
	}
	switch v.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		return BridgeValidateInitiatingMessage(v.InitiatingMessage, budget)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		return BridgeValidateSuccessfulOutcome(v.SuccessfulOutcome, budget)
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		return BridgeValidateUnsuccessfulOutcome(v.UnsuccessfulOutcome, budget)
	default:
		if v.UnknownExtension != nil {
			if len(v.UnknownExtension.Contents()) == 0 {
				return func() s21.ValidationReport {
					sealed := s21.ValidationReport{}
					*s21.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}(), fmt.Errorf("%s unknown extension has empty complete encoding", "S1APPDU:")
			}
			return func() s21.ValidationReport {
				report := func() s21.ValidationReport {
					sealed := s21.ValidationReport{Complete: false}
					*s21.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}()
				s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "S1APPDU.unknownExtension"})
				return report
			}(), nil
		}
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("%s invalid choice %d", "S1APPDU:", v.Choice)
	}
}
func ValidateENBConfigurationTransfer(v *s52.ENBConfigurationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	report, err := BridgeValidateENBConfigurationTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s52.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationTransfer")
}
func ValidateMMEConfigurationTransfer(v *s52.MMEConfigurationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	report, err := BridgeValidateMMEConfigurationTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s52.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationTransfer")
}
func ValidateMessage(v *S1APPDU, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "Message")
	}
	report, err := BridgeValidateMessageBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Message")
}
func BridgeWalkValidationENBConfigurationTransfer(v *s52.ENBConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s52.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s52.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s52.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
			s26.BridgeMergeNestedValidation(report, s52.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(129):
				if value, ok := fields[i].Value.AsSONConfigurationTransferECT(); ok {
					BridgeWalkValidationSONConfigurationTransfer(value, report, fmt.Sprintf("%s[%d]{id=129}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(294):
				if value, ok := fields[i].Value.AsENDCSONConfigurationTransferECT(); ok {
					BridgeWalkValidationENDCSONConfigurationTransfer(value, report, fmt.Sprintf("%s[%d]{id=294}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONConfigurationTransfer(v *s51.ENDCSONConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s50.BridgeWalkValidationENDCSONTransferType(&v.Transfertype, report, path+".transfertype", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSONInformation(&v.SONInformation, report, path+".sONInformation", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.X2TNLConfigInfo != nil {
		BridgeWalkValidationX2TNLConfigurationInfo(v.X2TNLConfigInfo, report, path+".x2TNLConfigInfo", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s26.BridgeMergeNestedValidation(report, s27.BridgeENDCSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitiatingMessage(v *s52.InitiatingMessage, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationTransfer(v *s52.MMEConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s52.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s52.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s52.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
			s26.BridgeMergeNestedValidation(report, BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(130):
				if value, ok := fields[i].Value.AsSONConfigurationTransferMCT(); ok {
					BridgeWalkValidationSONConfigurationTransfer(value, report, fmt.Sprintf("%s[%d]{id=130}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(295):
				if value, ok := fields[i].Value.AsENDCSONConfigurationTransferMCT(); ok {
					BridgeWalkValidationENDCSONConfigurationTransfer(value, report, fmt.Sprintf("%s[%d]{id=295}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1APPDU(v *S1APPDU, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.S1APPDUChoiceInitiatingMessage && v.InitiatingMessage != nil {
		BridgeWalkValidationInitiatingMessage(v.InitiatingMessage, report, path+".initiatingMessage", false)
	}
	if v.Choice == s00.S1APPDUChoiceSuccessfulOutcome && v.SuccessfulOutcome != nil {
		s51.BridgeWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
	}
	if v.Choice == s00.S1APPDUChoiceUnsuccessfulOutcome && v.UnsuccessfulOutcome != nil {
		s51.BridgeWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
	}
}
func BridgeWalkValidationSONConfigurationTransfer(v *s51.SONConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s50.BridgeWalkValidationTargeteNBID(&v.TargeteNBID, report, path+".targeteNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s50.BridgeWalkValidationSourceeNBID(&v.SourceeNBID, report, path+".sourceeNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSONInformation(&v.SONInformation, report, path+".sONInformation", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s51.SONConfigurationTransferExtIEs().X2TNLConfigurationInfo().Info()), s00.FieldInfo(s51.SONConfigurationTransferExtIEs().SynchronisationInformation().Info()), s00.FieldInfo(s51.SONConfigurationTransferExtIEs().RequestedTNLInfo().Info())}
				s26.BridgeMergeNestedValidation(report, BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(152):
					if value, ok := fields[i].ExtensionValue.AsX2TNLConfigurationInfo(); ok {
						BridgeWalkValidationX2TNLConfigurationInfo(value, report, fmt.Sprintf("%s[%d]{id=152}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(209):
					if value, ok := fields[i].ExtensionValue.AsSynchronisationInformation(); ok {
						s50.BridgeWalkValidationSynchronisationInformation(value, report, fmt.Sprintf("%s[%d]{id=209}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(356):
					if value, ok := fields[i].ExtensionValue.AsRequestedTNLInfo(); ok {
						s50.BridgeWalkValidationRequestedTNLInfo(value, report, fmt.Sprintf("%s[%d]{id=356}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformation(v *s51.SONInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONInformationChoiceSONInformationReply && v.SONInformationReply != nil {
		BridgeWalkValidationSONInformationReply(v.SONInformationReply, report, path+".sONInformationReply", false)
	}
	if v.Choice == s00.SONInformationChoiceSONInformationExtension && v.SONInformationExtension != nil {
		s50.BridgeWalkValidationSONInformationExtension(v.SONInformationExtension, report, path+".sONInformation-Extension", false)
	}
}
func BridgeWalkValidationSONInformationReply(v *s51.SONInformationReply, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.X2TNLConfigurationInfo != nil {
		BridgeWalkValidationX2TNLConfigurationInfo(v.X2TNLConfigurationInfo, report, path+".x2TNLConfigurationInfo", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s35.SONInformationReplyExtIEs().TimeSynchronisationInfo().Info()), s00.FieldInfo(s35.SONInformationReplyExtIEs().MutingPatternInformation().Info())}
				s26.BridgeMergeNestedValidation(report, s35.BridgeSONInformationReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(149):
					if value, ok := fields[i].ExtensionValue.AsTimeSynchronisationInfo(); ok {
						s50.BridgeWalkValidationTimeSynchronisationInfo(value, report, fmt.Sprintf("%s[%d]{id=149}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(208):
					if value, ok := fields[i].ExtensionValue.AsMutingPatternInformation(); ok {
						s50.BridgeWalkValidationMutingPatternInformation(value, report, fmt.Sprintf("%s[%d]{id=208}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationX2TNLConfigurationInfo(v *s51.X2TNLConfigurationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s50.BridgeWalkValidationENBX2TLAs(&v.ENBX2TransportLayerAddresses, report, path+".eNBX2TransportLayerAddresses", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s39.X2TNLConfigurationInfoExtIEs().ENBX2ExtendedTransportLayerAddresses().Info()), s00.FieldInfo(s39.X2TNLConfigurationInfoExtIEs().ENBIndirectX2TransportLayerAddresses().Info())}
				s26.BridgeMergeNestedValidation(report, BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(153):
					if value, ok := fields[i].ExtensionValue.AsENBX2ExtendedTransportLayerAddresses(); ok {
						s50.BridgeWalkValidationENBX2ExtTLAs(value, report, fmt.Sprintf("%s[%d]{id=153}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(193):
					if value, ok := fields[i].ExtensionValue.AsENBIndirectX2TransportLayerAddresses(); ok {
						s50.BridgeWalkValidationENBIndirectX2TransportLayerAddresses(value, report, fmt.Sprintf("%s[%d]{id=193}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgePathSwitchRequestInitiatingBindingFieldCapture(v *PathSwitchRequestInitiatingBinding) *func(s41.PathSwitchRequest, aper.DecodeState) (s41.PathSwitchRequest, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestInitiatingBindingFieldCompare(v *PathSwitchRequestInitiatingBinding) *func(s41.PathSwitchRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestInitiatingBindingFieldContext(v *PathSwitchRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestInitiatingBindingFieldDecode(v *PathSwitchRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s41.PathSwitchRequest, error) {
	return &v.decode
}
func BridgePathSwitchRequestInitiatingBindingFieldEncode(v *PathSwitchRequestInitiatingBinding) *func(*s41.PathSwitchRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestInitiatingBindingFieldInfo(v *PathSwitchRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestInitiatingBindingFieldInject(v *PathSwitchRequestInitiatingBinding) *func(s41.PathSwitchRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgePathSwitchRequestInitiatingBindingFieldValidate(v *PathSwitchRequestInitiatingBinding) *func(*s41.PathSwitchRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgePrivateMessageInitiatingBindingFieldCapture(v *PrivateMessageInitiatingBinding) *func(s26.PrivateMessage, aper.DecodeState) (s26.PrivateMessage, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageInitiatingBindingFieldCompare(v *PrivateMessageInitiatingBinding) *func(s26.PrivateMessage, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivateMessageInitiatingBindingFieldContext(v *PrivateMessageInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageInitiatingBindingFieldDecode(v *PrivateMessageInitiatingBinding) *func([]byte, aper.DecodeState) (s26.PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageInitiatingBindingFieldEncode(v *PrivateMessageInitiatingBinding) *func(*s26.PrivateMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageInitiatingBindingFieldInfo(v *PrivateMessageInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePrivateMessageInitiatingBindingFieldInject(v *PrivateMessageInitiatingBinding) *func(s26.PrivateMessage) s52.InitiatingValue {
	return &v.inject
}
func BridgePrivateMessageInitiatingBindingFieldValidate(v *PrivateMessageInitiatingBinding) *func(*s26.PrivateMessage, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeRerouteNASRequestInitiatingBindingFieldCapture(v *RerouteNASRequestInitiatingBinding) *func(s27.RerouteNASRequest, aper.DecodeState) (s27.RerouteNASRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestInitiatingBindingFieldCompare(v *RerouteNASRequestInitiatingBinding) *func(s27.RerouteNASRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestInitiatingBindingFieldContext(v *RerouteNASRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestInitiatingBindingFieldDecode(v *RerouteNASRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s27.RerouteNASRequest, error) {
	return &v.decode
}
func BridgeRerouteNASRequestInitiatingBindingFieldEncode(v *RerouteNASRequestInitiatingBinding) *func(*s27.RerouteNASRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestInitiatingBindingFieldInfo(v *RerouteNASRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeRerouteNASRequestInitiatingBindingFieldInject(v *RerouteNASRequestInitiatingBinding) *func(s27.RerouteNASRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeRerouteNASRequestInitiatingBindingFieldValidate(v *RerouteNASRequestInitiatingBinding) *func(*s27.RerouteNASRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeResetInitiatingBindingFieldCapture(v *ResetInitiatingBinding) *func(s36.Reset, aper.DecodeState) (s36.Reset, aper.Snapshot) {
	return &v.capture
}
func BridgeResetInitiatingBindingFieldCompare(v *ResetInitiatingBinding) *func(s36.Reset, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetInitiatingBindingFieldContext(v *ResetInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetInitiatingBindingFieldDecode(v *ResetInitiatingBinding) *func([]byte, aper.DecodeState) (s36.Reset, error) {
	return &v.decode
}
func BridgeResetInitiatingBindingFieldEncode(v *ResetInitiatingBinding) *func(*s36.Reset, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetInitiatingBindingFieldInfo(v *ResetInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeResetInitiatingBindingFieldInject(v *ResetInitiatingBinding) *func(s36.Reset) s52.InitiatingValue {
	return &v.inject
}
func BridgeResetInitiatingBindingFieldValidate(v *ResetInitiatingBinding) *func(*s36.Reset, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeRetrieveUEInformationInitiatingBindingFieldCapture(v *RetrieveUEInformationInitiatingBinding) *func(s28.RetrieveUEInformation, aper.DecodeState) (s28.RetrieveUEInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeRetrieveUEInformationInitiatingBindingFieldCompare(v *RetrieveUEInformationInitiatingBinding) *func(s28.RetrieveUEInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRetrieveUEInformationInitiatingBindingFieldContext(v *RetrieveUEInformationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRetrieveUEInformationInitiatingBindingFieldDecode(v *RetrieveUEInformationInitiatingBinding) *func([]byte, aper.DecodeState) (s28.RetrieveUEInformation, error) {
	return &v.decode
}
func BridgeRetrieveUEInformationInitiatingBindingFieldEncode(v *RetrieveUEInformationInitiatingBinding) *func(*s28.RetrieveUEInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRetrieveUEInformationInitiatingBindingFieldInfo(v *RetrieveUEInformationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeRetrieveUEInformationInitiatingBindingFieldInject(v *RetrieveUEInformationInitiatingBinding) *func(s28.RetrieveUEInformation) s52.InitiatingValue {
	return &v.inject
}
func BridgeRetrieveUEInformationInitiatingBindingFieldValidate(v *RetrieveUEInformationInitiatingBinding) *func(*s28.RetrieveUEInformation, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1APPDUAPERValueFieldContext(v *S1APPDUAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1APPDUAPERValueFieldReceived(v *S1APPDUAPERValue) *aper.WireSpan { return &v.received }
func BridgeS1APPDUAPERValueFieldReplay(v *S1APPDUAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeS1APPDUAPERValueFieldWithoutReplay(v *S1APPDUAPERValue) *bool     { return &v.withoutReplay }
func BridgeS1APPDUFieldPerOpenTypePadding(v *S1APPDU) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeS1APPDUFieldPerPadding(v *S1APPDU) *aper.CompletePadding { return &v.perPadding }
func BridgeS1APPDUFieldReceived(v *S1APPDU) *bool                   { return &v.received }
func BridgeS1APPDUFieldReceivedAbsolute(v *S1APPDU) *bool           { return &v.receivedAbsolute }
func BridgeS1APPDUFieldReceivedBytes(v *S1APPDU) *aper.WireSpan     { return &v.receivedBytes }
func BridgeS1APPDUFieldReceivedLocation(v *S1APPDU) *aper.Location  { return &v.receivedLocation }
func BridgeS1APPDUFieldReplay(v *S1APPDU) *aper.Snapshot            { return &v.replay }
func BridgeS1APPDUFieldStream(v *S1APPDU) *aper.WireSpan            { return &v.stream }
func BridgeS1APPDUFieldWithoutReplay(v *S1APPDU) *bool              { return &v.withoutReplay }
func BridgeS1APPDUMethodMarshalAPERBudget(v *S1APPDU, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1APPDUMethodMarshalAPERBudgetValue(v *S1APPDU, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeS1APPDUMethodMarshalAPERChanged(v *S1APPDU, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeS1APPDUMethodMarshalAPERChangedValue(v *S1APPDU, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeS1APPDUMethodMarshalAPERLegacy(v *S1APPDU) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeS1APPDUMethodMarshalAPERNewValue(v *S1APPDU, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeS1APPDUMethodMarshalAPERPlanned(v *S1APPDU, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeS1APPDUMethodMarshalAPERTo(v *S1APPDU, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1APPDUMethodUnmarshalAPERFrom(v *S1APPDU, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1APPDUMethodUnmarshalAPERLegacy(v *S1APPDU, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeS1APPDUMethodUnmarshalAPERWithOptions(v *S1APPDU, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeS1APPDUValueCodecFieldCapture(v *S1APPDUValueCodec) *func(S1APPDU, aper.DecodeState) (S1APPDU, aper.Snapshot) {
	return &v.capture
}
func BridgeS1APPDUValueCodecFieldCompare(v *S1APPDUValueCodec) *func(S1APPDU, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1APPDUValueCodecFieldContext(v *S1APPDUValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1APPDUValueCodecFieldDecode(v *S1APPDUValueCodec) *func([]byte, aper.DecodeState) (S1APPDU, error) {
	return &v.decode
}
func BridgeS1APPDUValueCodecFieldEncode(v *S1APPDUValueCodec) *func(S1APPDU, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1APPDUValueCodecFieldPath(v *S1APPDUValueCodec) *aper.Path { return &v.path }
func BridgeS1APPDUValueCodecMethodEncodeBudgetValue(v S1APPDUValueCodec, a0 S1APPDU, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1APPDUValueCodecMethodEncodeChanged(v S1APPDUValueCodec, a0 S1APPDU, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalRequestInitiatingBindingFieldCapture(v *S1RemovalRequestInitiatingBinding) *func(s27.S1RemovalRequest, aper.DecodeState) (s27.S1RemovalRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestInitiatingBindingFieldCompare(v *S1RemovalRequestInitiatingBinding) *func(s27.S1RemovalRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestInitiatingBindingFieldContext(v *S1RemovalRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestInitiatingBindingFieldDecode(v *S1RemovalRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s27.S1RemovalRequest, error) {
	return &v.decode
}
func BridgeS1RemovalRequestInitiatingBindingFieldEncode(v *S1RemovalRequestInitiatingBinding) *func(*s27.S1RemovalRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestInitiatingBindingFieldInfo(v *S1RemovalRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalRequestInitiatingBindingFieldInject(v *S1RemovalRequestInitiatingBinding) *func(s27.S1RemovalRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeS1RemovalRequestInitiatingBindingFieldValidate(v *S1RemovalRequestInitiatingBinding) *func(*s27.S1RemovalRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupRequestInitiatingBindingFieldCapture(v *S1SetupRequestInitiatingBinding) *func(s44.S1SetupRequest, aper.DecodeState) (s44.S1SetupRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestInitiatingBindingFieldCompare(v *S1SetupRequestInitiatingBinding) *func(s44.S1SetupRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestInitiatingBindingFieldContext(v *S1SetupRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestInitiatingBindingFieldDecode(v *S1SetupRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s44.S1SetupRequest, error) {
	return &v.decode
}
func BridgeS1SetupRequestInitiatingBindingFieldEncode(v *S1SetupRequestInitiatingBinding) *func(*s44.S1SetupRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestInitiatingBindingFieldInfo(v *S1SetupRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupRequestInitiatingBindingFieldInject(v *S1SetupRequestInitiatingBinding) *func(s44.S1SetupRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeS1SetupRequestInitiatingBindingFieldValidate(v *S1SetupRequestInitiatingBinding) *func(*s44.S1SetupRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldCapture(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s47.SecondaryRATDataUsageReport, aper.DecodeState) (s47.SecondaryRATDataUsageReport, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldCompare(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s47.SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldContext(v *SecondaryRATDataUsageReportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldDecode(v *SecondaryRATDataUsageReportInitiatingBinding) *func([]byte, aper.DecodeState) (s47.SecondaryRATDataUsageReport, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldEncode(v *SecondaryRATDataUsageReportInitiatingBinding) *func(*s47.SecondaryRATDataUsageReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldInfo(v *SecondaryRATDataUsageReportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldInject(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s47.SecondaryRATDataUsageReport) s52.InitiatingValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldValidate(v *SecondaryRATDataUsageReportInitiatingBinding) *func(*s47.SecondaryRATDataUsageReport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeTraceFailureIndicationInitiatingBindingFieldCapture(v *TraceFailureIndicationInitiatingBinding) *func(s35.TraceFailureIndication, aper.DecodeState) (s35.TraceFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationInitiatingBindingFieldCompare(v *TraceFailureIndicationInitiatingBinding) *func(s35.TraceFailureIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationInitiatingBindingFieldContext(v *TraceFailureIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationInitiatingBindingFieldDecode(v *TraceFailureIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s35.TraceFailureIndication, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationInitiatingBindingFieldEncode(v *TraceFailureIndicationInitiatingBinding) *func(*s35.TraceFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationInitiatingBindingFieldInfo(v *TraceFailureIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeTraceFailureIndicationInitiatingBindingFieldInject(v *TraceFailureIndicationInitiatingBinding) *func(s35.TraceFailureIndication) s52.InitiatingValue {
	return &v.inject
}
func BridgeTraceFailureIndicationInitiatingBindingFieldValidate(v *TraceFailureIndicationInitiatingBinding) *func(*s35.TraceFailureIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeTraceStartInitiatingBindingFieldCapture(v *TraceStartInitiatingBinding) *func(s49.TraceStart, aper.DecodeState) (s49.TraceStart, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartInitiatingBindingFieldCompare(v *TraceStartInitiatingBinding) *func(s49.TraceStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartInitiatingBindingFieldContext(v *TraceStartInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartInitiatingBindingFieldDecode(v *TraceStartInitiatingBinding) *func([]byte, aper.DecodeState) (s49.TraceStart, error) {
	return &v.decode
}
func BridgeTraceStartInitiatingBindingFieldEncode(v *TraceStartInitiatingBinding) *func(*s49.TraceStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartInitiatingBindingFieldInfo(v *TraceStartInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeTraceStartInitiatingBindingFieldInject(v *TraceStartInitiatingBinding) *func(s49.TraceStart) s52.InitiatingValue {
	return &v.inject
}
func BridgeTraceStartInitiatingBindingFieldValidate(v *TraceStartInitiatingBinding) *func(*s49.TraceStart, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldCapture(v *UECapabilityInfoIndicationInitiatingBinding) *func(s36.UECapabilityInfoIndication, aper.DecodeState) (s36.UECapabilityInfoIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldCompare(v *UECapabilityInfoIndicationInitiatingBinding) *func(s36.UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldContext(v *UECapabilityInfoIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldDecode(v *UECapabilityInfoIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s36.UECapabilityInfoIndication, error) {
	return &v.decode
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldEncode(v *UECapabilityInfoIndicationInitiatingBinding) *func(*s36.UECapabilityInfoIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldInfo(v *UECapabilityInfoIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldInject(v *UECapabilityInfoIndicationInitiatingBinding) *func(s36.UECapabilityInfoIndication) s52.InitiatingValue {
	return &v.inject
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldValidate(v *UECapabilityInfoIndicationInitiatingBinding) *func(*s36.UECapabilityInfoIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldCapture(v *UEContextModificationIndicationInitiatingBinding) *func(s37.UEContextModificationIndication, aper.DecodeState) (s37.UEContextModificationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldCompare(v *UEContextModificationIndicationInitiatingBinding) *func(s37.UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldContext(v *UEContextModificationIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldDecode(v *UEContextModificationIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s37.UEContextModificationIndication, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldEncode(v *UEContextModificationIndicationInitiatingBinding) *func(*s37.UEContextModificationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldInfo(v *UEContextModificationIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldInject(v *UEContextModificationIndicationInitiatingBinding) *func(s37.UEContextModificationIndication) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldValidate(v *UEContextModificationIndicationInitiatingBinding) *func(*s37.UEContextModificationIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationRequestInitiatingBindingFieldCapture(v *UEContextModificationRequestInitiatingBinding) *func(s48.UEContextModificationRequest, aper.DecodeState) (s48.UEContextModificationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestInitiatingBindingFieldCompare(v *UEContextModificationRequestInitiatingBinding) *func(s48.UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestInitiatingBindingFieldContext(v *UEContextModificationRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestInitiatingBindingFieldDecode(v *UEContextModificationRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s48.UEContextModificationRequest, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestInitiatingBindingFieldEncode(v *UEContextModificationRequestInitiatingBinding) *func(*s48.UEContextModificationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestInitiatingBindingFieldInfo(v *UEContextModificationRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationRequestInitiatingBindingFieldInject(v *UEContextModificationRequestInitiatingBinding) *func(s48.UEContextModificationRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextModificationRequestInitiatingBindingFieldValidate(v *UEContextModificationRequestInitiatingBinding) *func(*s48.UEContextModificationRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldCapture(v *UEContextReleaseCommandInitiatingBinding) *func(s37.UEContextReleaseCommand, aper.DecodeState) (s37.UEContextReleaseCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldCompare(v *UEContextReleaseCommandInitiatingBinding) *func(s37.UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldContext(v *UEContextReleaseCommandInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldDecode(v *UEContextReleaseCommandInitiatingBinding) *func([]byte, aper.DecodeState) (s37.UEContextReleaseCommand, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldEncode(v *UEContextReleaseCommandInitiatingBinding) *func(*s37.UEContextReleaseCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldInfo(v *UEContextReleaseCommandInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldInject(v *UEContextReleaseCommandInitiatingBinding) *func(s37.UEContextReleaseCommand) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldValidate(v *UEContextReleaseCommandInitiatingBinding) *func(*s37.UEContextReleaseCommand, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldCapture(v *UEContextReleaseRequestInitiatingBinding) *func(s43.UEContextReleaseRequest, aper.DecodeState) (s43.UEContextReleaseRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldCompare(v *UEContextReleaseRequestInitiatingBinding) *func(s43.UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldContext(v *UEContextReleaseRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldDecode(v *UEContextReleaseRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s43.UEContextReleaseRequest, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldEncode(v *UEContextReleaseRequestInitiatingBinding) *func(*s43.UEContextReleaseRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldInfo(v *UEContextReleaseRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldInject(v *UEContextReleaseRequestInitiatingBinding) *func(s43.UEContextReleaseRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldValidate(v *UEContextReleaseRequestInitiatingBinding) *func(*s43.UEContextReleaseRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeRequestInitiatingBindingFieldCapture(v *UEContextResumeRequestInitiatingBinding) *func(s39.UEContextResumeRequest, aper.DecodeState) (s39.UEContextResumeRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeRequestInitiatingBindingFieldCompare(v *UEContextResumeRequestInitiatingBinding) *func(s39.UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeRequestInitiatingBindingFieldContext(v *UEContextResumeRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeRequestInitiatingBindingFieldDecode(v *UEContextResumeRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s39.UEContextResumeRequest, error) {
	return &v.decode
}
func BridgeUEContextResumeRequestInitiatingBindingFieldEncode(v *UEContextResumeRequestInitiatingBinding) *func(*s39.UEContextResumeRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeRequestInitiatingBindingFieldInfo(v *UEContextResumeRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeRequestInitiatingBindingFieldInject(v *UEContextResumeRequestInitiatingBinding) *func(s39.UEContextResumeRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextResumeRequestInitiatingBindingFieldValidate(v *UEContextResumeRequestInitiatingBinding) *func(*s39.UEContextResumeRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldCapture(v *UEContextSuspendRequestInitiatingBinding) *func(s47.UEContextSuspendRequest, aper.DecodeState) (s47.UEContextSuspendRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldCompare(v *UEContextSuspendRequestInitiatingBinding) *func(s47.UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldContext(v *UEContextSuspendRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldDecode(v *UEContextSuspendRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s47.UEContextSuspendRequest, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldEncode(v *UEContextSuspendRequestInitiatingBinding) *func(*s47.UEContextSuspendRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldInfo(v *UEContextSuspendRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldInject(v *UEContextSuspendRequestInitiatingBinding) *func(s47.UEContextSuspendRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldValidate(v *UEContextSuspendRequestInitiatingBinding) *func(*s47.UEContextSuspendRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEInformationTransferInitiatingBindingFieldCapture(v *UEInformationTransferInitiatingBinding) *func(s37.UEInformationTransfer, aper.DecodeState) (s37.UEInformationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferInitiatingBindingFieldCompare(v *UEInformationTransferInitiatingBinding) *func(s37.UEInformationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferInitiatingBindingFieldContext(v *UEInformationTransferInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferInitiatingBindingFieldDecode(v *UEInformationTransferInitiatingBinding) *func([]byte, aper.DecodeState) (s37.UEInformationTransfer, error) {
	return &v.decode
}
func BridgeUEInformationTransferInitiatingBindingFieldEncode(v *UEInformationTransferInitiatingBinding) *func(*s37.UEInformationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferInitiatingBindingFieldInfo(v *UEInformationTransferInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEInformationTransferInitiatingBindingFieldInject(v *UEInformationTransferInitiatingBinding) *func(s37.UEInformationTransfer) s52.InitiatingValue {
	return &v.inject
}
func BridgeUEInformationTransferInitiatingBindingFieldValidate(v *UEInformationTransferInitiatingBinding) *func(*s37.UEInformationTransfer, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldCapture(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s37.UERadioCapabilityIDMappingRequest, aper.DecodeState) (s37.UERadioCapabilityIDMappingRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldCompare(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s37.UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldContext(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldDecode(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s37.UERadioCapabilityIDMappingRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldEncode(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(*s37.UERadioCapabilityIDMappingRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldInfo(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldInject(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s37.UERadioCapabilityIDMappingRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldValidate(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(*s37.UERadioCapabilityIDMappingRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldCapture(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s37.UERadioCapabilityMatchRequest, aper.DecodeState) (s37.UERadioCapabilityMatchRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldCompare(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s37.UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldContext(v *UERadioCapabilityMatchRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldDecode(v *UERadioCapabilityMatchRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s37.UERadioCapabilityMatchRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldEncode(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(*s37.UERadioCapabilityMatchRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldInfo(v *UERadioCapabilityMatchRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldInject(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s37.UERadioCapabilityMatchRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldValidate(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(*s37.UERadioCapabilityMatchRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkNASTransportInitiatingBindingFieldCapture(v *UplinkNASTransportInitiatingBinding) *func(s45.UplinkNASTransport, aper.DecodeState) (s45.UplinkNASTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportInitiatingBindingFieldCompare(v *UplinkNASTransportInitiatingBinding) *func(s45.UplinkNASTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportInitiatingBindingFieldContext(v *UplinkNASTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportInitiatingBindingFieldDecode(v *UplinkNASTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s45.UplinkNASTransport, error) {
	return &v.decode
}
func BridgeUplinkNASTransportInitiatingBindingFieldEncode(v *UplinkNASTransportInitiatingBinding) *func(*s45.UplinkNASTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportInitiatingBindingFieldInfo(v *UplinkNASTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkNASTransportInitiatingBindingFieldInject(v *UplinkNASTransportInitiatingBinding) *func(s45.UplinkNASTransport) s52.InitiatingValue {
	return &v.inject
}
func BridgeUplinkNASTransportInitiatingBindingFieldValidate(v *UplinkNASTransportInitiatingBinding) *func(*s45.UplinkNASTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldCapture(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkNonUEAssociatedLPPaTransport, aper.DecodeState) (s45.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldCompare(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldContext(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldDecode(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s45.UplinkNonUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldEncode(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(*s45.UplinkNonUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldInfo(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldInject(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkNonUEAssociatedLPPaTransport) s52.InitiatingValue {
	return &v.inject
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldValidate(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(*s45.UplinkNonUEAssociatedLPPaTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldCapture(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s45.UplinkS1cdma2000tunnelling, aper.DecodeState) (s45.UplinkS1cdma2000tunnelling, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldCompare(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s45.UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldContext(v *UplinkS1cdma2000tunnellingInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldDecode(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func([]byte, aper.DecodeState) (s45.UplinkS1cdma2000tunnelling, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldEncode(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(*s45.UplinkS1cdma2000tunnelling, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldInfo(v *UplinkS1cdma2000tunnellingInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldInject(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s45.UplinkS1cdma2000tunnelling) s52.InitiatingValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldValidate(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(*s45.UplinkS1cdma2000tunnelling, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldCapture(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkUEAssociatedLPPaTransport, aper.DecodeState) (s45.UplinkUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldCompare(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldContext(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldDecode(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s45.UplinkUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldEncode(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(*s45.UplinkUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldInfo(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldInject(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s45.UplinkUEAssociatedLPPaTransport) s52.InitiatingValue {
	return &v.inject
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldValidate(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(*s45.UplinkUEAssociatedLPPaTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldCapture(v *WriteReplaceWarningRequestInitiatingBinding) *func(s51.WriteReplaceWarningRequest, aper.DecodeState) (s51.WriteReplaceWarningRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldCompare(v *WriteReplaceWarningRequestInitiatingBinding) *func(s51.WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldContext(v *WriteReplaceWarningRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldDecode(v *WriteReplaceWarningRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s51.WriteReplaceWarningRequest, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldEncode(v *WriteReplaceWarningRequestInitiatingBinding) *func(*s51.WriteReplaceWarningRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldInfo(v *WriteReplaceWarningRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldInject(v *WriteReplaceWarningRequestInitiatingBinding) *func(s51.WriteReplaceWarningRequest) s52.InitiatingValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldValidate(v *WriteReplaceWarningRequestInitiatingBinding) *func(*s51.WriteReplaceWarningRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
