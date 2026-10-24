// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s52 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s52

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewENBConfigurationTransfer(fields s50.ENBConfigurationTransferIEContainer, options ...aper.BuildOption) (s51.ENBConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.ENBConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	v := s51.ENBConfigurationTransfer{ProtocolIEs: make(s50.ENBConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationTransfer")
	}
	if _, err := s51.BridgeENBConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s51.ENBConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationTransfer.protocolIEs:", err), "ENBConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "ENBConfigurationTransfer")
}
func NewMMEConfigurationTransfer(fields s51.MMEConfigurationTransferIEContainer, options ...aper.BuildOption) (s51.MMEConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.MMEConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	v := s51.MMEConfigurationTransfer{ProtocolIEs: make(s51.MMEConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationTransfer")
	}
	if _, err := s51.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s51.MMEConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationTransfer.protocolIEs:", err), "MMEConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "MMEConfigurationTransfer")
}

// Initiating returns the typed binding for the initiating message of UplinkNASTransportDescriptor.
func (UplinkNASTransportDescriptor) Initiating() UplinkNASTransportInitiatingBinding {
	return UplinkNASTransportInitiatingBinding{info: UplinkNASTransportProcedure().Info(), validate: func(v *s44.UplinkNASTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUplinkNASTransportBudget(v, budget)
	}, encode: func(v *s44.UplinkNASTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.UplinkNASTransport, error) {
		var v s44.UplinkNASTransport
		err := s44.BridgeUplinkNASTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.UplinkNASTransport{}, err
		}
		*s44.BridgeUplinkNASTransportFieldReceived(&v) = true
		*s44.BridgeUplinkNASTransportFieldReceivedAbsolute(&v) = true
		*s44.BridgeUplinkNASTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.UplinkNASTransport) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(13)
			*s51.BridgeInitiatingValueFieldBodyUplinkNASTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.UplinkNASTransport, options aper.DecodeState) (s44.UplinkNASTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s44.BridgeCaptureS1APUplinkNASTransport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.UplinkNASTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APUplinkNASTransport(&v, &s)
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
		return s49.BridgeValidateResetBudget(v, budget)
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
	}, inject: func(v s36.Reset) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(14)
			*s51.BridgeInitiatingValueFieldBodyReset(&sealed) = &v
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
func (ResetDescriptor) Successful() s50.ResetAcknowledgeSuccessfulBinding {
	return func() s50.ResetAcknowledgeSuccessfulBinding {
		sealed := s50.ResetAcknowledgeSuccessfulBinding{}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldInfo(&sealed) = ResetProcedure().Info()
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s44.ResetAcknowledge, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateResetAcknowledgeBudget(v, budget)
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s44.ResetAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s44.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s44.ResetAcknowledge, error) {
			var v s44.ResetAcknowledge
			err := s44.BridgeResetAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s44.ResetAcknowledge{}, err
			}
			*s44.BridgeResetAcknowledgeFieldReceived(&v) = true
			*s44.BridgeResetAcknowledgeFieldReceivedAbsolute(&v) = true
			*s44.BridgeResetAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s44.ResetAcknowledge) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s50.BridgeSuccessfulValueFieldBodyResetAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s44.ResetAcknowledge, options aper.DecodeState) (s44.ResetAcknowledge, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s44.BridgeCaptureS1APResetAcknowledge(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s44.ResetAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s44.BridgeCompareS1APResetAcknowledge(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s50.BridgeResetAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return S1SetupRequestInitiatingBinding{info: S1SetupProcedure().Info(), validate: func(v *s43.S1SetupRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s49.BridgeValidateS1SetupRequestBudget(v, budget)
	}, encode: func(v *s43.S1SetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s43.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s43.S1SetupRequest, error) {
		var v s43.S1SetupRequest
		err := s43.BridgeS1SetupRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s43.S1SetupRequest{}, err
		}
		*s43.BridgeS1SetupRequestFieldReceived(&v) = true
		*s43.BridgeS1SetupRequestFieldReceivedAbsolute(&v) = true
		*s43.BridgeS1SetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s43.S1SetupRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(17)
			*s51.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s43.S1SetupRequest, options aper.DecodeState) (s43.S1SetupRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s43.BridgeCaptureS1APS1SetupRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s43.S1SetupRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s43.BridgeCompareS1APS1SetupRequest(&v, &s)
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
func (S1SetupDescriptor) Successful() s50.S1SetupResponseSuccessfulBinding {
	return func() s50.S1SetupResponseSuccessfulBinding {
		sealed := s50.S1SetupResponseSuccessfulBinding{}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s43.S1SetupResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s49.BridgeValidateS1SetupResponseBudget(v, budget)
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s43.S1SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s43.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.S1SetupResponse, error) {
			var v s43.S1SetupResponse
			err := s43.BridgeS1SetupResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s43.S1SetupResponse{}, err
			}
			*s43.BridgeS1SetupResponseFieldReceived(&v) = true
			*s43.BridgeS1SetupResponseFieldReceivedAbsolute(&v) = true
			*s43.BridgeS1SetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldInject(&sealed) = func(v s43.S1SetupResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s50.BridgeSuccessfulValueFieldBodyS1SetupResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldCapture(&sealed) = func(v s43.S1SetupResponse, options aper.DecodeState) (s43.S1SetupResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s43.BridgeCaptureS1APS1SetupResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldCompare(&sealed) = func(v s43.S1SetupResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s43.BridgeCompareS1APS1SetupResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s50.BridgeS1SetupResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1SetupResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1SetupDescriptor.
func (S1SetupDescriptor) Unsuccessful() s36.S1SetupFailureUnsuccessfulBinding {
	return func() s36.S1SetupFailureUnsuccessfulBinding {
		sealed := s36.S1SetupFailureUnsuccessfulBinding{}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s26.S1SetupFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s49.BridgeValidateS1SetupFailureBudget(v, budget)
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s26.S1SetupFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s26.BridgeS1SetupFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.S1SetupFailure, error) {
			var v s26.S1SetupFailure
			err := s26.BridgeS1SetupFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s26.S1SetupFailure{}, err
			}
			*s26.BridgeS1SetupFailureFieldReceived(&v) = true
			*s26.BridgeS1SetupFailureFieldReceivedAbsolute(&v) = true
			*s26.BridgeS1SetupFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s26.S1SetupFailure) s36.UnsuccessfulValue {
			return func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s36.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = &v
				return sealed
			}()
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s26.S1SetupFailure, options aper.DecodeState) (s26.S1SetupFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s26.BridgeCaptureS1APS1SetupFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s26.S1SetupFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APS1SetupFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeS1SetupFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextReleaseRequestInitiatingBinding{info: UEContextReleaseRequestProcedure().Info(), validate: func(v *s42.UEContextReleaseRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEContextReleaseRequestBudget(v, budget)
	}, encode: func(v *s42.UEContextReleaseRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s42.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s42.UEContextReleaseRequest, error) {
		var v s42.UEContextReleaseRequest
		err := s42.BridgeUEContextReleaseRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s42.UEContextReleaseRequest{}, err
		}
		*s42.BridgeUEContextReleaseRequestFieldReceived(&v) = true
		*s42.BridgeUEContextReleaseRequestFieldReceivedAbsolute(&v) = true
		*s42.BridgeUEContextReleaseRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s42.UEContextReleaseRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(18)
			*s51.BridgeInitiatingValueFieldBodyUEContextReleaseRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s42.UEContextReleaseRequest, options aper.DecodeState) (s42.UEContextReleaseRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s42.BridgeCaptureS1APUEContextReleaseRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s42.UEContextReleaseRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s42.BridgeCompareS1APUEContextReleaseRequest(&v, &s)
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
	return UplinkS1cdma2000tunnellingInitiatingBinding{info: UplinkS1cdma2000tunnellingProcedure().Info(), validate: func(v *s44.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	}, encode: func(v *s44.UplinkS1cdma2000tunnelling, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.UplinkS1cdma2000tunnelling, error) {
		var v s44.UplinkS1cdma2000tunnelling
		err := s44.BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.UplinkS1cdma2000tunnelling{}, err
		}
		*s44.BridgeUplinkS1cdma2000tunnellingFieldReceived(&v) = true
		*s44.BridgeUplinkS1cdma2000tunnellingFieldReceivedAbsolute(&v) = true
		*s44.BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.UplinkS1cdma2000tunnelling) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(20)
			*s51.BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.UplinkS1cdma2000tunnelling, options aper.DecodeState) (s44.UplinkS1cdma2000tunnelling, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s44.BridgeCaptureS1APUplinkS1cdma2000tunnelling(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s44.UplinkS1cdma2000tunnelling, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APUplinkS1cdma2000tunnelling(&v, &s)
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
	return UEContextModificationRequestInitiatingBinding{info: UEContextModificationProcedure().Info(), validate: func(v *s46.UEContextModificationRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEContextModificationRequestBudget(v, budget)
	}, encode: func(v *s46.UEContextModificationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UEContextModificationRequest, error) {
		var v s46.UEContextModificationRequest
		err := s46.BridgeUEContextModificationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UEContextModificationRequest{}, err
		}
		*s46.BridgeUEContextModificationRequestFieldReceived(&v) = true
		*s46.BridgeUEContextModificationRequestFieldReceivedAbsolute(&v) = true
		*s46.BridgeUEContextModificationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UEContextModificationRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(21)
			*s51.BridgeInitiatingValueFieldBodyUEContextModificationRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UEContextModificationRequest, options aper.DecodeState) (s46.UEContextModificationRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUEContextModificationRequest(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s46.UEContextModificationRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUEContextModificationRequest(&v, &s)
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
func (UEContextModificationDescriptor) Successful() s50.UEContextModificationResponseSuccessfulBinding {
	return func() s50.UEContextModificationResponseSuccessfulBinding {
		sealed := s50.UEContextModificationResponseSuccessfulBinding{}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextModificationResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextModificationResponseBudget(v, budget)
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextModificationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextModificationResponse, error) {
			var v s36.UEContextModificationResponse
			err := s36.BridgeUEContextModificationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UEContextModificationResponse{}, err
			}
			*s36.BridgeUEContextModificationResponseFieldReceived(&v) = true
			*s36.BridgeUEContextModificationResponseFieldReceivedAbsolute(&v) = true
			*s36.BridgeUEContextModificationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextModificationResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s50.BridgeSuccessfulValueFieldBodyUEContextModificationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextModificationResponse, options aper.DecodeState) (s36.UEContextModificationResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextModificationResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextModificationResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextModificationResponse(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUEContextModificationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Unsuccessful() s36.UEContextModificationFailureUnsuccessfulBinding {
	return func() s36.UEContextModificationFailureUnsuccessfulBinding {
		sealed := s36.UEContextModificationFailureUnsuccessfulBinding{}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextModificationFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextModificationFailureBudget(v, budget)
		}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextModificationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextModificationFailure, error) {
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
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextModificationFailure) s36.UnsuccessfulValue {
			return func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s36.BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextModificationFailure, options aper.DecodeState) (s36.UEContextModificationFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextModificationFailure(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextModificationFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextModificationFailure(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
		return s50.BridgeValidateUECapabilityInfoIndicationBudget(v, budget)
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
	}, inject: func(v s36.UECapabilityInfoIndication) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(22)
			*s51.BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(&sealed) = &v
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
		return s50.BridgeValidateUEContextReleaseCommandBudget(v, budget)
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
	}, inject: func(v s37.UEContextReleaseCommand) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(23)
			*s51.BridgeInitiatingValueFieldBodyUEContextReleaseCommand(&sealed) = &v
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
func (UEContextReleaseDescriptor) Successful() s50.UEContextReleaseCompleteSuccessfulBinding {
	return func() s50.UEContextReleaseCompleteSuccessfulBinding {
		sealed := s50.UEContextReleaseCompleteSuccessfulBinding{}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(&sealed) = UEContextReleaseProcedure().Info()
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(&sealed) = func(v *s46.UEContextReleaseComplete, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextReleaseCompleteBudget(v, budget)
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(&sealed) = func(v *s46.UEContextReleaseComplete, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseComplete, error) {
			var v s46.UEContextReleaseComplete
			err := s46.BridgeUEContextReleaseCompleteMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UEContextReleaseComplete{}, err
			}
			*s46.BridgeUEContextReleaseCompleteFieldReceived(&v) = true
			*s46.BridgeUEContextReleaseCompleteFieldReceivedAbsolute(&v) = true
			*s46.BridgeUEContextReleaseCompleteFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(&sealed) = func(v s46.UEContextReleaseComplete) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s50.BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(&sealed) = func(v s46.UEContextReleaseComplete, options aper.DecodeState) (s46.UEContextReleaseComplete, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUEContextReleaseComplete(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(&sealed) = func(v s46.UEContextReleaseComplete, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUEContextReleaseComplete(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return TraceStartInitiatingBinding{info: TraceStartProcedure().Info(), validate: func(v *s48.TraceStart, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateTraceStartBudget(v, budget)
	}, encode: func(v *s48.TraceStart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s48.BridgeTraceStartMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s48.TraceStart, error) {
		var v s48.TraceStart
		err := s48.BridgeTraceStartMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s48.TraceStart{}, err
		}
		*s48.BridgeTraceStartFieldReceived(&v) = true
		*s48.BridgeTraceStartFieldReceivedAbsolute(&v) = true
		*s48.BridgeTraceStartFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s48.TraceStart) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(27)
			*s51.BridgeInitiatingValueFieldBodyTraceStart(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s48.TraceStart, options aper.DecodeState) (s48.TraceStart, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s48.BridgeCaptureS1APTraceStart(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s48.TraceStart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s48.BridgeCompareS1APTraceStart(&v,
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
	return TraceFailureIndicationInitiatingBinding{info: TraceFailureIndicationProcedure().Info(), validate: func(v *s34.TraceFailureIndication, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s49.BridgeValidateTraceFailureIndicationBudget(v, budget)
	}, encode: func(v *s34.TraceFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s34.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s34.TraceFailureIndication, error) {
		var v s34.TraceFailureIndication
		err := s34.BridgeTraceFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s34.TraceFailureIndication{}, err
		}
		*s34.BridgeTraceFailureIndicationFieldReceived(&v) = true
		*s34.BridgeTraceFailureIndicationFieldReceivedAbsolute(&v) = true
		*s34.BridgeTraceFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s34.TraceFailureIndication) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(28)
			*s51.BridgeInitiatingValueFieldBodyTraceFailureIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s34.TraceFailureIndication, options aper.DecodeState) (s34.TraceFailureIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s34.BridgeCaptureS1APTraceFailureIndication(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s34.TraceFailureIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s34.BridgeCompareS1APTraceFailureIndication(&v, &s)
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
	return WriteReplaceWarningRequestInitiatingBinding{info: WriteReplaceWarningProcedure().Info(), validate: func(v *s50.WriteReplaceWarningRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	}, encode: func(v *s50.WriteReplaceWarningRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s50.BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s50.WriteReplaceWarningRequest, error) {
		var v s50.WriteReplaceWarningRequest
		err := s50.BridgeWriteReplaceWarningRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s50.WriteReplaceWarningRequest{}, err
		}
		*s50.BridgeWriteReplaceWarningRequestFieldReceived(&v) = true
		*s50.BridgeWriteReplaceWarningRequestFieldReceivedAbsolute(&v) = true
		*s50.BridgeWriteReplaceWarningRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s50.WriteReplaceWarningRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(36)
			*s51.BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s50.WriteReplaceWarningRequest, options aper.DecodeState) (s50.WriteReplaceWarningRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s50.BridgeCaptureS1APWriteReplaceWarningRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s50.WriteReplaceWarningRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s50.BridgeCompareS1APWriteReplaceWarningRequest(&v, &s)
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
func (WriteReplaceWarningDescriptor) Successful() s50.WriteReplaceWarningResponseSuccessfulBinding {
	return func() s50.WriteReplaceWarningResponseSuccessfulBinding {
		sealed := s50.WriteReplaceWarningResponseSuccessfulBinding{}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInfo(&sealed) = WriteReplaceWarningProcedure().Info()
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s50.WriteReplaceWarningResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateWriteReplaceWarningResponseBudget(v, budget)
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s50.WriteReplaceWarningResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s50.BridgeWriteReplaceWarningResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s50.WriteReplaceWarningResponse, error) {
			var v s50.WriteReplaceWarningResponse
			err := s50.BridgeWriteReplaceWarningResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s50.WriteReplaceWarningResponse{}, err
			}
			*s50.BridgeWriteReplaceWarningResponseFieldReceived(&v) = true
			*s50.BridgeWriteReplaceWarningResponseFieldReceivedAbsolute(&v) = true
			*s50.BridgeWriteReplaceWarningResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInject(&sealed) = func(v s50.WriteReplaceWarningResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s50.BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCapture(&sealed) = func(v s50.WriteReplaceWarningResponse, options aper.DecodeState) (s50.WriteReplaceWarningResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s50.BridgeCaptureS1APWriteReplaceWarningResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCompare(&sealed) = func(v s50.WriteReplaceWarningResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s50.BridgeCompareS1APWriteReplaceWarningResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WriteReplaceWarningResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of PrivateMessageDescriptor.
func (PrivateMessageDescriptor) Initiating() s51.PrivateMessageInitiatingBinding {
	return func() s51.PrivateMessageInitiatingBinding {
		sealed := s51.PrivateMessageInitiatingBinding{}
		*s51.BridgePrivateMessageInitiatingBindingFieldInfo(&sealed) = PrivateMessageProcedure().Info()
		*s51.BridgePrivateMessageInitiatingBindingFieldValidate(&sealed) = func(v *s26.PrivateMessage, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s47.BridgeValidatePrivateMessageBudget(v, budget)
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldEncode(&sealed) = func(v *s26.PrivateMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s26.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.PrivateMessage, error) {
			var v s26.PrivateMessage
			err := s26.BridgePrivateMessageMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s26.PrivateMessage{}, err
			}
			*s26.BridgePrivateMessageFieldReceived(&v) = true
			*s26.BridgePrivateMessageFieldReceivedAbsolute(&v) = true
			*s26.BridgePrivateMessageFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldInject(&sealed) = func(v s26.PrivateMessage) s51.InitiatingValue {
			return func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(39)
				*s51.BridgeInitiatingValueFieldBodyPrivateMessage(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldCapture(&sealed) = func(v s26.PrivateMessage, options aper.DecodeState) (s26.PrivateMessage, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s26.BridgeCaptureS1APPrivateMessage(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldCompare(&sealed) = func(v s26.PrivateMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APPrivateMessage(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgePrivateMessageInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateMessage"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of ENBConfigurationTransferDescriptor.
func (ENBConfigurationTransferDescriptor) Initiating() s51.ENBConfigurationTransferInitiatingBinding {
	return func() s51.ENBConfigurationTransferInitiatingBinding {
		sealed := s51.ENBConfigurationTransferInitiatingBinding{}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldInfo(&sealed) = ENBConfigurationTransferProcedure().Info()
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s51.ENBConfigurationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return BridgeValidateENBConfigurationTransferBudget(v, budget)
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s51.ENBConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s51.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.ENBConfigurationTransfer, error) {
			var v s51.ENBConfigurationTransfer
			err := s51.BridgeENBConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s51.ENBConfigurationTransfer{}, err
			}
			*s51.BridgeENBConfigurationTransferFieldReceived(&v) = true
			*s51.BridgeENBConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s51.BridgeENBConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s51.ENBConfigurationTransfer) s51.InitiatingValue {
			return func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(40)
				*s51.BridgeInitiatingValueFieldBodyENBConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s51.ENBConfigurationTransfer, options aper.DecodeState) (s51.ENBConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeCaptureS1APENBConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s51.ENBConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s51.BridgeCompareS1APENBConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeENBConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of MMEConfigurationTransferDescriptor.
func (MMEConfigurationTransferDescriptor) Initiating() s51.MMEConfigurationTransferInitiatingBinding {
	return func() s51.MMEConfigurationTransferInitiatingBinding {
		sealed := s51.MMEConfigurationTransferInitiatingBinding{}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldInfo(&sealed) = MMEConfigurationTransferProcedure().Info()
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s51.MMEConfigurationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return BridgeValidateMMEConfigurationTransferBudget(v, budget)
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s51.MMEConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s51.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.MMEConfigurationTransfer, error) {
			var v s51.MMEConfigurationTransfer
			err := s51.BridgeMMEConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s51.MMEConfigurationTransfer{}, err
			}
			*s51.BridgeMMEConfigurationTransferFieldReceived(&v) = true
			*s51.BridgeMMEConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s51.BridgeMMEConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s51.MMEConfigurationTransfer) s51.InitiatingValue {
			return func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(41)
				*s51.BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s51.MMEConfigurationTransfer, options aper.DecodeState) (s51.MMEConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeCaptureS1APMMEConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s51.MMEConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s51.BridgeCompareS1APMMEConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeMMEConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UplinkUEAssociatedLPPaTransportInitiatingBinding{info: UplinkUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s44.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s44.UplinkUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.UplinkUEAssociatedLPPaTransport, error) {
		var v s44.UplinkUEAssociatedLPPaTransport
		err := s44.BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.UplinkUEAssociatedLPPaTransport{}, err
		}
		*s44.BridgeUplinkUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s44.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s44.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.UplinkUEAssociatedLPPaTransport) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(45)
			*s51.BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.UplinkUEAssociatedLPPaTransport, options aper.DecodeState) (s44.UplinkUEAssociatedLPPaTransport, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s44.BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.UplinkUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APUplinkUEAssociatedLPPaTransport(&v, &s)
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
	return UplinkNonUEAssociatedLPPaTransportInitiatingBinding{info: UplinkNonUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s44.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s44.UplinkNonUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.UplinkNonUEAssociatedLPPaTransport, error) {
		var v s44.UplinkNonUEAssociatedLPPaTransport
		err := s44.BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.UplinkNonUEAssociatedLPPaTransport{}, err
		}
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.UplinkNonUEAssociatedLPPaTransport) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(47)
			*s51.BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.UplinkNonUEAssociatedLPPaTransport, options aper.DecodeState) (s44.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s44.BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.UplinkNonUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
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
	return UERadioCapabilityMatchRequestInitiatingBinding{info: UERadioCapabilityMatchProcedure().Info(), validate: func(v *s36.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	}, encode: func(v *s36.UERadioCapabilityMatchRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.UERadioCapabilityMatchRequest, error) {
		var v s36.UERadioCapabilityMatchRequest
		err := s36.BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.UERadioCapabilityMatchRequest{}, err
		}
		*s36.BridgeUERadioCapabilityMatchRequestFieldReceived(&v) = true
		*s36.BridgeUERadioCapabilityMatchRequestFieldReceivedAbsolute(&v) = true
		*s36.BridgeUERadioCapabilityMatchRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.UERadioCapabilityMatchRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(48)
			*s51.BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.UERadioCapabilityMatchRequest, options aper.DecodeState) (s36.UERadioCapabilityMatchRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APUERadioCapabilityMatchRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.UERadioCapabilityMatchRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APUERadioCapabilityMatchRequest(&v, &s)
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
func (UERadioCapabilityMatchDescriptor) Successful() s50.UERadioCapabilityMatchResponseSuccessfulBinding {
	return func() s50.UERadioCapabilityMatchResponseSuccessfulBinding {
		sealed := s50.UERadioCapabilityMatchResponseSuccessfulBinding{}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityMatchProcedure().Info()
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UERadioCapabilityMatchResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUERadioCapabilityMatchResponseBudget(v, budget)
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UERadioCapabilityMatchResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UERadioCapabilityMatchResponse, error) {
			var v s36.UERadioCapabilityMatchResponse
			err := s36.BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UERadioCapabilityMatchResponse{}, err
			}
			*s36.BridgeUERadioCapabilityMatchResponseFieldReceived(&v) = true
			*s36.BridgeUERadioCapabilityMatchResponseFieldReceivedAbsolute(&v) = true
			*s36.BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInject(&sealed) = func(v s36.UERadioCapabilityMatchResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s50.BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCapture(&sealed) = func(v s36.UERadioCapabilityMatchResponse, options aper.DecodeState) (s36.UERadioCapabilityMatchResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUERadioCapabilityMatchResponse(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCompare(&sealed) = func(v s36.UERadioCapabilityMatchResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUERadioCapabilityMatchResponse(&v, &s)
			s.End(f,
				root,
				false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return RerouteNASRequestInitiatingBinding{info: RerouteNASRequestProcedure().Info(), validate: func(v *s26.RerouteNASRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s49.BridgeValidateRerouteNASRequestBudget(v, budget)
	}, encode: func(v *s26.RerouteNASRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s26.BridgeRerouteNASRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s26.RerouteNASRequest, error) {
		var v s26.RerouteNASRequest
		err := s26.BridgeRerouteNASRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s26.RerouteNASRequest{}, err
		}
		*s26.BridgeRerouteNASRequestFieldReceived(&v) = true
		*s26.BridgeRerouteNASRequestFieldReceivedAbsolute(&v) = true
		*s26.BridgeRerouteNASRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s26.RerouteNASRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(52)
			*s51.BridgeInitiatingValueFieldBodyRerouteNASRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s26.RerouteNASRequest, options aper.DecodeState) (s26.RerouteNASRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s26.BridgeCaptureS1APRerouteNASRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s26.RerouteNASRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s26.BridgeCompareS1APRerouteNASRequest(&v, &s)
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
	return UEContextModificationIndicationInitiatingBinding{info: UEContextModificationIndicationProcedure().Info(), validate: func(v *s36.UEContextModificationIndication, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEContextModificationIndicationBudget(v, budget)
	}, encode: func(v *s36.UEContextModificationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.UEContextModificationIndication, error) {
		var v s36.UEContextModificationIndication
		err := s36.BridgeUEContextModificationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.UEContextModificationIndication{}, err
		}
		*s36.BridgeUEContextModificationIndicationFieldReceived(&v) = true
		*s36.BridgeUEContextModificationIndicationFieldReceivedAbsolute(&v) = true
		*s36.BridgeUEContextModificationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.UEContextModificationIndication) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(53)
			*s51.BridgeInitiatingValueFieldBodyUEContextModificationIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.UEContextModificationIndication, options aper.DecodeState) (s36.UEContextModificationIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APUEContextModificationIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.UEContextModificationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APUEContextModificationIndication(&v, &s)
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
func (UEContextModificationIndicationDescriptor) Successful() s50.UEContextModificationConfirmSuccessfulBinding {
	return func() s50.UEContextModificationConfirmSuccessfulBinding {
		sealed := s50.UEContextModificationConfirmSuccessfulBinding{}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldInfo(&sealed) = UEContextModificationIndicationProcedure().Info()
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextModificationConfirm, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextModificationConfirmBudget(v, budget)
		}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextModificationConfirm, error) {
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
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextModificationConfirm) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s50.BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextModificationConfirm, options aper.DecodeState) (s36.UEContextModificationConfirm, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextModificationConfirm(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextModificationConfirm, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextModificationConfirm(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUEContextModificationConfirmSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextSuspendRequestInitiatingBinding{info: UEContextSuspendProcedure().Info(), validate: func(v *s46.UEContextSuspendRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEContextSuspendRequestBudget(v, budget)
	}, encode: func(v *s46.UEContextSuspendRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UEContextSuspendRequest, error) {
		var v s46.UEContextSuspendRequest
		err := s46.BridgeUEContextSuspendRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UEContextSuspendRequest{}, err
		}
		*s46.BridgeUEContextSuspendRequestFieldReceived(&v) = true
		*s46.BridgeUEContextSuspendRequestFieldReceivedAbsolute(&v) = true
		*s46.BridgeUEContextSuspendRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UEContextSuspendRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(55)
			*s51.BridgeInitiatingValueFieldBodyUEContextSuspendRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UEContextSuspendRequest, options aper.DecodeState) (s46.UEContextSuspendRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUEContextSuspendRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s46.UEContextSuspendRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUEContextSuspendRequest(&v, &s)
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
func (UEContextSuspendDescriptor) Successful() s50.UEContextSuspendResponseSuccessfulBinding {
	return func() s50.UEContextSuspendResponseSuccessfulBinding {
		sealed := s50.UEContextSuspendResponseSuccessfulBinding{}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(&sealed) = UEContextSuspendProcedure().Info()
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextSuspendResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextSuspendResponseBudget(v, budget)
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextSuspendResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponse, error) {
			var v s36.UEContextSuspendResponse
			err := s36.BridgeUEContextSuspendResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UEContextSuspendResponse{}, err
			}
			*s36.BridgeUEContextSuspendResponseFieldReceived(&v) = true
			*s36.BridgeUEContextSuspendResponseFieldReceivedAbsolute(&v) = true
			*s36.BridgeUEContextSuspendResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextSuspendResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s50.BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextSuspendResponse, options aper.DecodeState) (s36.UEContextSuspendResponse, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextSuspendResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextSuspendResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextSuspendResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextResumeRequestInitiatingBinding{info: UEContextResumeProcedure().Info(), validate: func(v *s38.UEContextResumeRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEContextResumeRequestBudget(v, budget)
	}, encode: func(v *s38.UEContextResumeRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s38.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s38.UEContextResumeRequest, error) {
		var v s38.UEContextResumeRequest
		err := s38.BridgeUEContextResumeRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s38.UEContextResumeRequest{}, err
		}
		*s38.BridgeUEContextResumeRequestFieldReceived(&v) = true
		*s38.BridgeUEContextResumeRequestFieldReceivedAbsolute(&v) = true
		*s38.BridgeUEContextResumeRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s38.UEContextResumeRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(56)
			*s51.BridgeInitiatingValueFieldBodyUEContextResumeRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s38.UEContextResumeRequest, options aper.DecodeState) (s38.UEContextResumeRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s38.BridgeCaptureS1APUEContextResumeRequest(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s38.UEContextResumeRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s38.BridgeCompareS1APUEContextResumeRequest(&v, &s)
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
func (UEContextResumeDescriptor) Successful() s50.UEContextResumeResponseSuccessfulBinding {
	return func() s50.UEContextResumeResponseSuccessfulBinding {
		sealed := s50.UEContextResumeResponseSuccessfulBinding{}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s38.UEContextResumeResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextResumeResponseBudget(v, budget)
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s38.UEContextResumeResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s38.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.UEContextResumeResponse, error) {
			var v s38.UEContextResumeResponse
			err := s38.BridgeUEContextResumeResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s38.UEContextResumeResponse{}, err
			}
			*s38.BridgeUEContextResumeResponseFieldReceived(&v) = true
			*s38.BridgeUEContextResumeResponseFieldReceivedAbsolute(&v) = true
			*s38.BridgeUEContextResumeResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldInject(&sealed) = func(v s38.UEContextResumeResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s50.BridgeSuccessfulValueFieldBodyUEContextResumeResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(&sealed) = func(v s38.UEContextResumeResponse, options aper.DecodeState) (s38.UEContextResumeResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s38.BridgeCaptureS1APUEContextResumeResponse(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(&sealed) = func(v s38.UEContextResumeResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s38.BridgeCompareS1APUEContextResumeResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUEContextResumeResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextResumeResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Unsuccessful() s36.UEContextResumeFailureUnsuccessfulBinding {
	return func() s36.UEContextResumeFailureUnsuccessfulBinding {
		sealed := s36.UEContextResumeFailureUnsuccessfulBinding{}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s36.UEContextResumeFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUEContextResumeFailureBudget(v, budget)
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s36.UEContextResumeFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextResumeFailure, error) {
			var v s36.UEContextResumeFailure
			err := s36.BridgeUEContextResumeFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UEContextResumeFailure{}, err
			}
			*s36.BridgeUEContextResumeFailureFieldReceived(&v) = true
			*s36.BridgeUEContextResumeFailureFieldReceivedAbsolute(&v) = true
			*s36.BridgeUEContextResumeFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s36.UEContextResumeFailure) s36.UnsuccessfulValue {
			return func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s36.BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(&sealed) = &v
				return sealed
			}()
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s36.UEContextResumeFailure, options aper.DecodeState) (s36.UEContextResumeFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEContextResumeFailure(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s36.UEContextResumeFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEContextResumeFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextResumeFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
		return s49.BridgeValidateRetrieveUEInformationBudget(v, budget)
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
	}, inject: func(v s28.RetrieveUEInformation) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(58)
			*s51.BridgeInitiatingValueFieldBodyRetrieveUEInformation(&sealed) = &v
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
	return UEInformationTransferInitiatingBinding{info: UEInformationTransferProcedure().Info(), validate: func(v *s36.UEInformationTransfer, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUEInformationTransferBudget(v, budget)
	}, encode: func(v *s36.UEInformationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.UEInformationTransfer, error) {
		var v s36.UEInformationTransfer
		err := s36.BridgeUEInformationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.UEInformationTransfer{}, err
		}
		*s36.BridgeUEInformationTransferFieldReceived(&v) = true
		*s36.BridgeUEInformationTransferFieldReceivedAbsolute(&v) = true
		*s36.BridgeUEInformationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.UEInformationTransfer) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(59)
			*s51.BridgeInitiatingValueFieldBodyUEInformationTransfer(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.UEInformationTransfer, options aper.DecodeState) (s36.UEInformationTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APUEInformationTransfer(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.UEInformationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APUEInformationTransfer(&v, &s)
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
	return SecondaryRATDataUsageReportInitiatingBinding{info: SecondaryRATDataUsageReportProcedure().Info(), validate: func(v *s46.SecondaryRATDataUsageReport, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	}, encode: func(v *s46.SecondaryRATDataUsageReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.SecondaryRATDataUsageReport, error) {
		var v s46.SecondaryRATDataUsageReport
		err := s46.BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.SecondaryRATDataUsageReport{}, err
		}
		*s46.BridgeSecondaryRATDataUsageReportFieldReceived(&v) = true
		*s46.BridgeSecondaryRATDataUsageReportFieldReceivedAbsolute(&v) = true
		*s46.BridgeSecondaryRATDataUsageReportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.SecondaryRATDataUsageReport) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(62)
			*s51.BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.SecondaryRATDataUsageReport, options aper.DecodeState) (s46.SecondaryRATDataUsageReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APSecondaryRATDataUsageReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v s46.SecondaryRATDataUsageReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APSecondaryRATDataUsageReport(&v, &s)
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
	return UERadioCapabilityIDMappingRequestInitiatingBinding{info: UERadioCapabilityIDMappingProcedure().Info(), validate: func(v *s36.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s50.BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	}, encode: func(v *s36.UERadioCapabilityIDMappingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.UERadioCapabilityIDMappingRequest, error) {
		var v s36.UERadioCapabilityIDMappingRequest
		err := s36.BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.UERadioCapabilityIDMappingRequest{}, err
		}
		*s36.BridgeUERadioCapabilityIDMappingRequestFieldReceived(&v) = true
		*s36.BridgeUERadioCapabilityIDMappingRequestFieldReceivedAbsolute(&v) = true
		*s36.BridgeUERadioCapabilityIDMappingRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.UERadioCapabilityIDMappingRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(63)
			*s51.BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.UERadioCapabilityIDMappingRequest, options aper.DecodeState) (s36.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APUERadioCapabilityIDMappingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.UERadioCapabilityIDMappingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APUERadioCapabilityIDMappingRequest(&v, &s)
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
func (UERadioCapabilityIDMappingDescriptor) Successful() s50.UERadioCapabilityIDMappingResponseSuccessfulBinding {
	return func() s50.UERadioCapabilityIDMappingResponseSuccessfulBinding {
		sealed := s50.UERadioCapabilityIDMappingResponseSuccessfulBinding{}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityIDMappingProcedure().Info()
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s36.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s50.BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s36.UERadioCapabilityIDMappingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s36.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UERadioCapabilityIDMappingResponse, error) {
			var v s36.UERadioCapabilityIDMappingResponse
			err := s36.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s36.UERadioCapabilityIDMappingResponse{}, err
			}
			*s36.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&v) = true
			*s36.BridgeUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(&v) = true
			*s36.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(&sealed) = func(v s36.UERadioCapabilityIDMappingResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s50.BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(&sealed) = func(v s36.UERadioCapabilityIDMappingResponse, options aper.DecodeState) (s36.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(&sealed) = func(v s36.UERadioCapabilityIDMappingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUERadioCapabilityIDMappingResponse(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s50.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return S1RemovalRequestInitiatingBinding{info: S1RemovalProcedure().Info(), validate: func(v *s26.S1RemovalRequest, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
		return s49.BridgeValidateS1RemovalRequestBudget(v, budget)
	}, encode: func(v *s26.S1RemovalRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s26.BridgeS1RemovalRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s26.S1RemovalRequest, error) {
		var v s26.S1RemovalRequest
		err := s26.BridgeS1RemovalRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s26.S1RemovalRequest{}, err
		}
		*s26.BridgeS1RemovalRequestFieldReceived(&v) = true
		*s26.BridgeS1RemovalRequestFieldReceivedAbsolute(&v) = true
		*s26.BridgeS1RemovalRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s26.S1RemovalRequest) s51.InitiatingValue {
		return func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(67)
			*s51.BridgeInitiatingValueFieldBodyS1RemovalRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s26.S1RemovalRequest, options aper.DecodeState) (s26.S1RemovalRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s26.BridgeCaptureS1APS1RemovalRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s26.S1RemovalRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s26.BridgeCompareS1APS1RemovalRequest(&v, &s)
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
func (S1RemovalDescriptor) Successful() s50.S1RemovalResponseSuccessfulBinding {
	return func() s50.S1RemovalResponseSuccessfulBinding {
		sealed := s50.S1RemovalResponseSuccessfulBinding{}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s26.S1RemovalResponse, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s49.BridgeValidateS1RemovalResponseBudget(v, budget)
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s26.S1RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s26.BridgeS1RemovalResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.S1RemovalResponse, error) {
			var v s26.S1RemovalResponse
			err := s26.BridgeS1RemovalResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s26.S1RemovalResponse{}, err
			}
			*s26.BridgeS1RemovalResponseFieldReceived(&v) = true
			*s26.BridgeS1RemovalResponseFieldReceivedAbsolute(&v) = true
			*s26.BridgeS1RemovalResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldInject(&sealed) = func(v s26.S1RemovalResponse) s50.SuccessfulValue {
			return func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s50.BridgeSuccessfulValueFieldBodyS1RemovalResponse(&sealed) = &v
				return sealed
			}()
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldCapture(&sealed) = func(v s26.S1RemovalResponse, options aper.DecodeState) (s26.S1RemovalResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options,
			)
			f := s.Begin()
			s26.BridgeCaptureS1APS1RemovalResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldCompare(&sealed) = func(v s26.S1RemovalResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APS1RemovalResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s50.BridgeS1RemovalResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1RemovalDescriptor.
func (S1RemovalDescriptor) Unsuccessful() s36.S1RemovalFailureUnsuccessfulBinding {
	return func() s36.S1RemovalFailureUnsuccessfulBinding {
		sealed := s36.S1RemovalFailureUnsuccessfulBinding{}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s26.S1RemovalFailure, budget *aper.DecodeBudget) (s21.ValidationReport, error) {
			return s49.BridgeValidateS1RemovalFailureBudget(v, budget)
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s26.S1RemovalFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s26.BridgeS1RemovalFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.S1RemovalFailure, error) {
			var v s26.S1RemovalFailure
			err := s26.BridgeS1RemovalFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s26.S1RemovalFailure{}, err
			}
			*s26.BridgeS1RemovalFailureFieldReceived(&v) = true
			*s26.BridgeS1RemovalFailureFieldReceivedAbsolute(&v) = true
			*s26.BridgeS1RemovalFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s26.S1RemovalFailure) s36.UnsuccessfulValue {
			return func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s36.BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(&sealed) = &v
				return sealed
			}()
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s26.S1RemovalFailure, options aper.DecodeState) (s26.S1RemovalFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APS1RemovalFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s26.S1RemovalFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APS1RemovalFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s36.BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNASTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNASTransport].
type UplinkNASTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.UplinkNASTransport, aper.DecodeState,

	) (s44.UplinkNASTransport, aper.Snapshot,

	)
	compare func(s44.UplinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.UplinkNASTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.UplinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.UplinkNASTransport,

		error)
	inject func(s44.UplinkNASTransport,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportInitiatingBinding) Codec() s44.UplinkNASTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.UplinkNASTransportValueCodec{}
	}
	return func() s44.UplinkNASTransportValueCodec {
		sealed := s44.UplinkNASTransportValueCodec{}
		*s44.BridgeUplinkNASTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeUplinkNASTransportValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeUplinkNASTransportValueCodecFieldEncode(&sealed) = func(value s44.UplinkNASTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeUplinkNASTransportValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeUplinkNASTransportValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeUplinkNASTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNASTransportInitiatingBinding) Build(body s44.UplinkNASTransport,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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

	) s51.InitiatingValue
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

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1SetupRequestInitiatingBinding is the concrete InitiatingBinding[S1SetupRequest].
type S1SetupRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.S1SetupRequest, aper.DecodeState,

	) (s43.S1SetupRequest, aper.Snapshot,

	)
	compare func(s43.S1SetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.S1SetupRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s43.S1SetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.S1SetupRequest,

		error)
	inject func(s43.S1SetupRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestInitiatingBinding) Codec() s43.S1SetupRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.S1SetupRequestValueCodec{}
	}
	return func() s43.S1SetupRequestValueCodec {
		sealed := s43.S1SetupRequestValueCodec{}
		*s43.BridgeS1SetupRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeS1SetupRequestValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeS1SetupRequestValueCodecFieldEncode(&sealed) = func(value s43.S1SetupRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeS1SetupRequestValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeS1SetupRequestValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeS1SetupRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupRequestInitiatingBinding) Build(body s43.S1SetupRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseRequestInitiatingBinding is the concrete InitiatingBinding[UEContextReleaseRequest].
type UEContextReleaseRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s42.UEContextReleaseRequest, aper.DecodeState,

	) (s42.UEContextReleaseRequest, aper.Snapshot,

	)
	compare func(s42.UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s42.UEContextReleaseRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s42.UEContextReleaseRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s42.UEContextReleaseRequest,

		error)
	inject func(s42.UEContextReleaseRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Codec() s42.UEContextReleaseRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s42.UEContextReleaseRequestValueCodec{}
	}
	return func() s42.UEContextReleaseRequestValueCodec {
		sealed := s42.UEContextReleaseRequestValueCodec{}
		*s42.BridgeUEContextReleaseRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s42.BridgeUEContextReleaseRequestValueCodecFieldDecode(&sealed) = b.decode
		*s42.BridgeUEContextReleaseRequestValueCodecFieldEncode(&sealed) = func(value s42.UEContextReleaseRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s42.BridgeUEContextReleaseRequestValueCodecFieldCapture(&sealed) = b.capture
		*s42.BridgeUEContextReleaseRequestValueCodecFieldCompare(&sealed) = b.compare
		*s42.BridgeUEContextReleaseRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseRequestInitiatingBinding) Build(body s42.UEContextReleaseRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkS1cdma2000tunnellingInitiatingBinding is the concrete InitiatingBinding[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.UplinkS1cdma2000tunnelling, aper.DecodeState,

	) (s44.UplinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(s44.UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.UplinkS1cdma2000tunnelling,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.UplinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.UplinkS1cdma2000tunnelling,

		error)
	inject func(s44.UplinkS1cdma2000tunnelling,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Codec() s44.UplinkS1cdma2000tunnellingValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.UplinkS1cdma2000tunnellingValueCodec{}
	}
	return func() s44.UplinkS1cdma2000tunnellingValueCodec {
		sealed := s44.UplinkS1cdma2000tunnellingValueCodec{}
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldEncode(&sealed) = func(value s44.UplinkS1cdma2000tunnelling,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeUplinkS1cdma2000tunnellingValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Build(body s44.UplinkS1cdma2000tunnelling,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationRequestInitiatingBinding is the concrete InitiatingBinding[UEContextModificationRequest].
type UEContextModificationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UEContextModificationRequest, aper.DecodeState,

	) (s46.UEContextModificationRequest, aper.Snapshot,

	)
	compare func(s46.UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextModificationRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.UEContextModificationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextModificationRequest,

		error)
	inject func(s46.UEContextModificationRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestInitiatingBinding) Codec() s46.UEContextModificationRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextModificationRequestValueCodec{}
	}
	return func() s46.UEContextModificationRequestValueCodec {
		sealed := s46.UEContextModificationRequestValueCodec{}
		*s46.BridgeUEContextModificationRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextModificationRequestValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextModificationRequestValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextModificationRequestValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextModificationRequestValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextModificationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationRequestInitiatingBinding) Build(body s46.UEContextModificationRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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

	) s51.InitiatingValue
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

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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

	) s51.InitiatingValue
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

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceStartInitiatingBinding is the concrete InitiatingBinding[TraceStart].
type TraceStartInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s48.TraceStart, aper.DecodeState,

	) (s48.TraceStart, aper.Snapshot,

	)
	compare func(s48.TraceStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s48.TraceStart,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s48.TraceStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s48.TraceStart,

		error)
	inject func(s48.TraceStart,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceStartInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartInitiatingBinding) Codec() s48.TraceStartValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s48.TraceStartValueCodec{}
	}
	return func() s48.TraceStartValueCodec {
		sealed := s48.TraceStartValueCodec{}
		*s48.BridgeTraceStartValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s48.BridgeTraceStartValueCodecFieldDecode(&sealed) = b.decode
		*s48.BridgeTraceStartValueCodecFieldEncode(&sealed) = func(value s48.TraceStart,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s48.BridgeTraceStartValueCodecFieldCapture(&sealed) = b.capture
		*s48.BridgeTraceStartValueCodecFieldCompare(&sealed) = b.compare
		*s48.BridgeTraceStartValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceStartInitiatingBinding) Build(body s48.TraceStart,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceFailureIndicationInitiatingBinding is the concrete InitiatingBinding[TraceFailureIndication].
type TraceFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s34.TraceFailureIndication, aper.DecodeState,

	) (s34.TraceFailureIndication, aper.Snapshot,

	)
	compare func(s34.TraceFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s34.TraceFailureIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s34.TraceFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s34.TraceFailureIndication,

		error)
	inject func(s34.TraceFailureIndication,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationInitiatingBinding) Codec() s34.TraceFailureIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s34.TraceFailureIndicationValueCodec{}
	}
	return func() s34.TraceFailureIndicationValueCodec {
		sealed := s34.TraceFailureIndicationValueCodec{}
		*s34.BridgeTraceFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s34.BridgeTraceFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s34.BridgeTraceFailureIndicationValueCodecFieldEncode(&sealed) = func(value s34.TraceFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s34.BridgeTraceFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s34.BridgeTraceFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s34.BridgeTraceFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceFailureIndicationInitiatingBinding) Build(body s34.TraceFailureIndication,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// WriteReplaceWarningRequestInitiatingBinding is the concrete InitiatingBinding[WriteReplaceWarningRequest].
type WriteReplaceWarningRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s50.WriteReplaceWarningRequest, aper.DecodeState,

	) (s50.WriteReplaceWarningRequest, aper.Snapshot,

	)
	compare func(s50.WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s50.WriteReplaceWarningRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s50.WriteReplaceWarningRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s50.WriteReplaceWarningRequest,

		error)
	inject func(s50.WriteReplaceWarningRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Codec() s50.WriteReplaceWarningRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s50.WriteReplaceWarningRequestValueCodec{}
	}
	return func() s50.WriteReplaceWarningRequestValueCodec {
		sealed := s50.WriteReplaceWarningRequestValueCodec{}
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldDecode(&sealed) = b.decode
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldEncode(&sealed) = func(value s50.WriteReplaceWarningRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldCapture(&sealed) = b.capture
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldCompare(&sealed) = b.compare
		*s50.BridgeWriteReplaceWarningRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b WriteReplaceWarningRequestInitiatingBinding) Build(body s50.WriteReplaceWarningRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.UplinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (s44.UplinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s44.UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.UplinkUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.UplinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.UplinkUEAssociatedLPPaTransport,

		error)
	inject func(s44.UplinkUEAssociatedLPPaTransport,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Codec() s44.UplinkUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.UplinkUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s44.UplinkUEAssociatedLPPaTransportValueCodec {
		sealed := s44.UplinkUEAssociatedLPPaTransportValueCodec{}
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s44.UplinkUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Build(body s44.UplinkUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkNonUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.UplinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (s44.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s44.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.UplinkNonUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.UplinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.UplinkNonUEAssociatedLPPaTransport,

		error)
	inject func(s44.UplinkNonUEAssociatedLPPaTransport,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Codec() s44.UplinkNonUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.UplinkNonUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s44.UplinkNonUEAssociatedLPPaTransportValueCodec {
		sealed := s44.UplinkNonUEAssociatedLPPaTransportValueCodec{}
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s44.UplinkNonUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Build(body s44.UplinkNonUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityMatchRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityMatchRequest].
type UERadioCapabilityMatchRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UERadioCapabilityMatchRequest, aper.DecodeState,

	) (s36.UERadioCapabilityMatchRequest, aper.Snapshot,

	)
	compare func(s36.UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UERadioCapabilityMatchRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UERadioCapabilityMatchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UERadioCapabilityMatchRequest,

		error)
	inject func(s36.UERadioCapabilityMatchRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Codec() s36.UERadioCapabilityMatchRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UERadioCapabilityMatchRequestValueCodec{}
	}
	return func() s36.UERadioCapabilityMatchRequestValueCodec {
		sealed := s36.UERadioCapabilityMatchRequestValueCodec{}
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldEncode(&sealed) = func(value s36.UERadioCapabilityMatchRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUERadioCapabilityMatchRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Build(body s36.UERadioCapabilityMatchRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// RerouteNASRequestInitiatingBinding is the concrete InitiatingBinding[RerouteNASRequest].
type RerouteNASRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.RerouteNASRequest, aper.DecodeState,

	) (s26.RerouteNASRequest, aper.Snapshot,

	)
	compare func(s26.RerouteNASRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.RerouteNASRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.RerouteNASRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.RerouteNASRequest,

		error)
	inject func(s26.RerouteNASRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestInitiatingBinding) Codec() s26.RerouteNASRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.RerouteNASRequestValueCodec{}
	}
	return func() s26.RerouteNASRequestValueCodec {
		sealed := s26.RerouteNASRequestValueCodec{}
		*s26.BridgeRerouteNASRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeRerouteNASRequestValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeRerouteNASRequestValueCodecFieldEncode(&sealed) = func(value s26.RerouteNASRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeRerouteNASRequestValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeRerouteNASRequestValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeRerouteNASRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b RerouteNASRequestInitiatingBinding) Build(body s26.RerouteNASRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationIndicationInitiatingBinding is the concrete InitiatingBinding[UEContextModificationIndication].
type UEContextModificationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UEContextModificationIndication, aper.DecodeState,

	) (s36.UEContextModificationIndication, aper.Snapshot,

	)
	compare func(s36.UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEContextModificationIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEContextModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEContextModificationIndication,

		error)
	inject func(s36.UEContextModificationIndication,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Codec() s36.UEContextModificationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEContextModificationIndicationValueCodec{}
	}
	return func() s36.UEContextModificationIndicationValueCodec {
		sealed := s36.UEContextModificationIndicationValueCodec{}
		*s36.BridgeUEContextModificationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEContextModificationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEContextModificationIndicationValueCodecFieldEncode(&sealed) = func(value s36.UEContextModificationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEContextModificationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEContextModificationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEContextModificationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationIndicationInitiatingBinding) Build(body s36.UEContextModificationIndication,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextSuspendRequestInitiatingBinding is the concrete InitiatingBinding[UEContextSuspendRequest].
type UEContextSuspendRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UEContextSuspendRequest, aper.DecodeState,

	) (s46.UEContextSuspendRequest, aper.Snapshot,

	)
	compare func(s46.UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextSuspendRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.UEContextSuspendRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextSuspendRequest,

		error)
	inject func(s46.UEContextSuspendRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Codec() s46.UEContextSuspendRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextSuspendRequestValueCodec{}
	}
	return func() s46.UEContextSuspendRequestValueCodec {
		sealed := s46.UEContextSuspendRequestValueCodec{}
		*s46.BridgeUEContextSuspendRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextSuspendRequestValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextSuspendRequestValueCodecFieldEncode(&sealed) = func(value s46.UEContextSuspendRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextSuspendRequestValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextSuspendRequestValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextSuspendRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendRequestInitiatingBinding) Build(body s46.UEContextSuspendRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextResumeRequestInitiatingBinding is the concrete InitiatingBinding[UEContextResumeRequest].
type UEContextResumeRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s38.UEContextResumeRequest, aper.DecodeState,

	) (s38.UEContextResumeRequest, aper.Snapshot,

	)
	compare func(s38.UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s38.UEContextResumeRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s38.UEContextResumeRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s38.UEContextResumeRequest,

		error)
	inject func(s38.UEContextResumeRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestInitiatingBinding) Codec() s38.UEContextResumeRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s38.UEContextResumeRequestValueCodec{}
	}
	return func() s38.UEContextResumeRequestValueCodec {
		sealed := s38.UEContextResumeRequestValueCodec{}
		*s38.BridgeUEContextResumeRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s38.BridgeUEContextResumeRequestValueCodecFieldDecode(&sealed) = b.decode
		*s38.BridgeUEContextResumeRequestValueCodecFieldEncode(&sealed) = func(value s38.UEContextResumeRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s38.BridgeUEContextResumeRequestValueCodecFieldCapture(&sealed) = b.capture
		*s38.BridgeUEContextResumeRequestValueCodecFieldCompare(&sealed) = b.compare
		*s38.BridgeUEContextResumeRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeRequestInitiatingBinding) Build(body s38.UEContextResumeRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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

	) s51.InitiatingValue
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

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEInformationTransferInitiatingBinding is the concrete InitiatingBinding[UEInformationTransfer].
type UEInformationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UEInformationTransfer, aper.DecodeState,

	) (s36.UEInformationTransfer, aper.Snapshot,

	)
	compare func(s36.UEInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEInformationTransfer,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEInformationTransfer,

		error)
	inject func(s36.UEInformationTransfer,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferInitiatingBinding) Codec() s36.UEInformationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEInformationTransferValueCodec{}
	}
	return func() s36.UEInformationTransferValueCodec {
		sealed := s36.UEInformationTransferValueCodec{}
		*s36.BridgeUEInformationTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEInformationTransferValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEInformationTransferValueCodecFieldEncode(&sealed) = func(value s36.UEInformationTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEInformationTransferValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEInformationTransferValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEInformationTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEInformationTransferInitiatingBinding) Build(body s36.UEInformationTransfer,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// SecondaryRATDataUsageReportInitiatingBinding is the concrete InitiatingBinding[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.SecondaryRATDataUsageReport, aper.DecodeState,

	) (s46.SecondaryRATDataUsageReport, aper.Snapshot,

	)
	compare func(s46.SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.SecondaryRATDataUsageReport,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.SecondaryRATDataUsageReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.SecondaryRATDataUsageReport,

		error)
	inject func(s46.SecondaryRATDataUsageReport,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Codec() s46.SecondaryRATDataUsageReportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.SecondaryRATDataUsageReportValueCodec{}
	}
	return func() s46.SecondaryRATDataUsageReportValueCodec {
		sealed := s46.SecondaryRATDataUsageReportValueCodec{}
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldEncode(&sealed) = func(value s46.SecondaryRATDataUsageReport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeSecondaryRATDataUsageReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b SecondaryRATDataUsageReportInitiatingBinding) Build(body s46.SecondaryRATDataUsageReport,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityIDMappingRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityIDMappingRequest].
type UERadioCapabilityIDMappingRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UERadioCapabilityIDMappingRequest, aper.DecodeState,

	) (s36.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	)
	compare func(s36.UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UERadioCapabilityIDMappingRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UERadioCapabilityIDMappingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UERadioCapabilityIDMappingRequest,

		error)
	inject func(s36.UERadioCapabilityIDMappingRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Codec() s36.UERadioCapabilityIDMappingRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UERadioCapabilityIDMappingRequestValueCodec{}
	}
	return func() s36.UERadioCapabilityIDMappingRequestValueCodec {
		sealed := s36.UERadioCapabilityIDMappingRequestValueCodec{}
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldEncode(&sealed) = func(value s36.UERadioCapabilityIDMappingRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Build(body s36.UERadioCapabilityIDMappingRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1RemovalRequestInitiatingBinding is the concrete InitiatingBinding[S1RemovalRequest].
type S1RemovalRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.S1RemovalRequest, aper.DecodeState,

	) (s26.S1RemovalRequest, aper.Snapshot,

	)
	compare func(s26.S1RemovalRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.S1RemovalRequest,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.S1RemovalRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.S1RemovalRequest,

		error)
	inject func(s26.S1RemovalRequest,

	) s51.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalRequestInitiatingBinding) Codec() s26.S1RemovalRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.S1RemovalRequestValueCodec{}
	}
	return func() s26.S1RemovalRequestValueCodec {
		sealed := s26.S1RemovalRequestValueCodec{}
		*s26.BridgeS1RemovalRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeS1RemovalRequestValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeS1RemovalRequestValueCodecFieldEncode(&sealed) = func(value s26.S1RemovalRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeS1RemovalRequestValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeS1RemovalRequestValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeS1RemovalRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalRequestInitiatingBinding) Build(body s26.S1RemovalRequest,

	options ...aper.BuildOption) (s51.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s51.InitiatingMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.InitiatingMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s51.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s51.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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
func BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields s51.MMEConfigurationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s51.BridgeMMEConfigurationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s51.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s51.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields s50.SONConfigurationTransferExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.SONConfigurationTransferExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s50.SONConfigurationTransferExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields s38.X2TNLConfigurationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.X2TNLConfigurationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s38.X2TNLConfigurationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func MMEConfigurationTransferIEValueERABIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s51.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
	codec := s51.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s51.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s51.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
		sealed := s51.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
		*s51.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueERABIEContainerList, error) {
			value, err := (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s51.MMEConfigurationTransferIEValueERABIEContainerList(value), err
		}
		*s51.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s51.MMEConfigurationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s51.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s51.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s51.MMEConfigurationTransferIEValueERABIEContainerList, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeMMEConfigurationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s51.MMEConfigurationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := s51.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s51.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MMEConfigurationTransferIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable, bounds aper.ListBounds) s51.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
	codec := s51.MMEConfigurationTransferIEValueIETableCodec(table, bounds)
	if *s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s51.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s51.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s51.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s51.MMEConfigurationTransferIEValueProtocolIEContainerList(value), err
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s51.MMEConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s51.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s51.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s51.MMEConfigurationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s51.MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s51.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s51.MMEConfigurationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s51.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	captureSemantics(aper.SemanticCapture) s51.MMEConfigurationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s51.MMEConfigurationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// sONConfigurationTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SONConfigurationTransferExtIEsValue].
type SONConfigurationTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s50.SONConfigurationTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s50.SONConfigurationTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// x2TNLConfigurationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[X2TNLConfigurationInfoExtIEsValue].
type X2TNLConfigurationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s38.X2TNLConfigurationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s38.X2TNLConfigurationInfoExtIEsValue,

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
func BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(fields s50.SONConfigurationTransferExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s50.BridgeSONConfigurationTransferExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s50.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s50.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(fields s38.X2TNLConfigurationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s38.BridgeX2TNLConfigurationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s38.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s38.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(v *s51.MMEConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s51.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(v *s51.MMEConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(v *s51.MMEConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s51.BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(v, s)
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
				s51.BridgeCaptureS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s50.BridgeCaptureS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s36.BridgeCaptureS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
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
				s51.BridgeCompareS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s50.BridgeCompareS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s36.BridgeCompareS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
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
	InitiatingMessage   *s51.InitiatingMessage   `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *s50.SuccessfulOutcome   `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *s36.UnsuccessfulOutcome `json:"UnsuccessfulOutcome,omitempty"`
}

// NewS1APPDUInitiatingMessage creates a S1APPDU with the initiatingMessage alternative.
func BridgeNewS1APPDUInitiatingMessageLegacy(v s51.InitiatingMessage) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewS1APPDUSuccessfulOutcome creates a S1APPDU with the successfulOutcome alternative.
func BridgeNewS1APPDUSuccessfulOutcomeLegacy(v s50.SuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewS1APPDUUnsuccessfulOutcome creates a S1APPDU with the unsuccessfulOutcome alternative.
func BridgeNewS1APPDUUnsuccessfulOutcomeLegacy(v s36.UnsuccessfulOutcome) S1APPDU {
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
		if err := s51.BridgeInitiatingMessageMethodMarshalAPERTo(v.InitiatingMessage, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := s50.BridgeSuccessfulOutcomeMethodMarshalAPERTo(v.SuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := s36.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v.UnsuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		var dec_initiatingmessage s51.InitiatingMessage
		if err := s51.BridgeInitiatingMessageMethodUnmarshalAPERFrom(&dec_initiatingmessage, bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		if err := aper.ChargeValue(bb, dec_initiatingmessage); err != nil {
			return err
		}
		v.InitiatingMessage = &dec_initiatingmessage
		bb.LeaveComponent(toleranceMark_initiatingmessage)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		toleranceMark_successfuloutcome := bb.EnterComponent("SuccessfulOutcome")
		var dec_successfuloutcome s50.SuccessfulOutcome
		if err := s50.BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_successfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_successfuloutcome); err != nil {
			return err
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
		bb.LeaveComponent(toleranceMark_successfuloutcome)
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		toleranceMark_unsuccessfuloutcome := bb.EnterComponent("UnsuccessfulOutcome")
		var dec_unsuccessfuloutcome s36.UnsuccessfulOutcome
		if err := s36.BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_unsuccessfuloutcome, bb); err != nil {
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
func NewS1APPDUInitiatingMessage(v s51.InitiatingMessage, options ...aper.BuildOption) (S1APPDU, error) {
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
func NewS1APPDUSuccessfulOutcome(v s50.SuccessfulOutcome, options ...aper.BuildOption) (S1APPDU, error) {
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
func NewS1APPDUUnsuccessfulOutcome(v s36.UnsuccessfulOutcome, options ...aper.BuildOption) (S1APPDU, error) {
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
func ENBConfigurationTransferCodec() s51.ENBConfigurationTransferValueCodec {
	return ENBConfigurationTransferProcedure().Initiating().Codec()
}

// MMEConfigurationTransferCodec binds the complete APER value type.
func MMEConfigurationTransferCodec() s51.MMEConfigurationTransferValueCodec {
	return MMEConfigurationTransferProcedure().Initiating().Codec()
}

// PrivateMessageCodec binds the complete APER value type.
func PrivateMessageCodec() s26.PrivateMessageValueCodec {
	return PrivateMessageProcedure().Initiating().Codec()
}

// RerouteNASRequestCodec binds the complete APER value type.
func RerouteNASRequestCodec() s26.RerouteNASRequestValueCodec {
	return RerouteNASRequestProcedure().Initiating().Codec()
}

// ResetAcknowledgeCodec binds the complete APER value type.
func ResetAcknowledgeCodec() s44.ResetAcknowledgeValueCodec {
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
func S1RemovalFailureCodec() s26.S1RemovalFailureValueCodec {
	return S1RemovalProcedure().Unsuccessful().Codec()
}

// S1RemovalRequestCodec binds the complete APER value type.
func S1RemovalRequestCodec() s26.S1RemovalRequestValueCodec {
	return S1RemovalProcedure().Initiating().Codec()
}

// S1RemovalResponseCodec binds the complete APER value type.
func S1RemovalResponseCodec() s26.S1RemovalResponseValueCodec {
	return S1RemovalProcedure().Successful().Codec()
}

// S1SetupFailureCodec binds the complete APER value type.
func S1SetupFailureCodec() s26.S1SetupFailureValueCodec {
	return S1SetupProcedure().Unsuccessful().Codec()
}

// S1SetupRequestCodec binds the complete APER value type.
func S1SetupRequestCodec() s43.S1SetupRequestValueCodec {
	return S1SetupProcedure().Initiating().Codec()
}

// S1SetupResponseCodec binds the complete APER value type.
func S1SetupResponseCodec() s43.S1SetupResponseValueCodec {
	return S1SetupProcedure().Successful().Codec()
}

// SecondaryRATDataUsageReportCodec binds the complete APER value type.
func SecondaryRATDataUsageReportCodec() s46.SecondaryRATDataUsageReportValueCodec {
	return SecondaryRATDataUsageReportProcedure().Initiating().Codec()
}

// TraceFailureIndicationCodec binds the complete APER value type.
func TraceFailureIndicationCodec() s34.TraceFailureIndicationValueCodec {
	return TraceFailureIndicationProcedure().Initiating().Codec()
}

// TraceStartCodec binds the complete APER value type.
func TraceStartCodec() s48.TraceStartValueCodec { return TraceStartProcedure().Initiating().Codec() }

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
func UEContextModificationIndicationCodec() s36.UEContextModificationIndicationValueCodec {
	return UEContextModificationIndicationProcedure().Initiating().Codec()
}

// UEContextModificationRequestCodec binds the complete APER value type.
func UEContextModificationRequestCodec() s46.UEContextModificationRequestValueCodec {
	return UEContextModificationProcedure().Initiating().Codec()
}

// UEContextModificationResponseCodec binds the complete APER value type.
func UEContextModificationResponseCodec() s36.UEContextModificationResponseValueCodec {
	return UEContextModificationProcedure().Successful().Codec()
}

// UEContextReleaseCommandCodec binds the complete APER value type.
func UEContextReleaseCommandCodec() s37.UEContextReleaseCommandValueCodec {
	return UEContextReleaseProcedure().Initiating().Codec()
}

// UEContextReleaseCompleteCodec binds the complete APER value type.
func UEContextReleaseCompleteCodec() s46.UEContextReleaseCompleteValueCodec {
	return UEContextReleaseProcedure().Successful().Codec()
}

// UEContextReleaseRequestCodec binds the complete APER value type.
func UEContextReleaseRequestCodec() s42.UEContextReleaseRequestValueCodec {
	return UEContextReleaseRequestProcedure().Initiating().Codec()
}

// UEContextResumeFailureCodec binds the complete APER value type.
func UEContextResumeFailureCodec() s36.UEContextResumeFailureValueCodec {
	return UEContextResumeProcedure().Unsuccessful().Codec()
}

// UEContextResumeRequestCodec binds the complete APER value type.
func UEContextResumeRequestCodec() s38.UEContextResumeRequestValueCodec {
	return UEContextResumeProcedure().Initiating().Codec()
}

// UEContextResumeResponseCodec binds the complete APER value type.
func UEContextResumeResponseCodec() s38.UEContextResumeResponseValueCodec {
	return UEContextResumeProcedure().Successful().Codec()
}

// UEContextSuspendRequestCodec binds the complete APER value type.
func UEContextSuspendRequestCodec() s46.UEContextSuspendRequestValueCodec {
	return UEContextSuspendProcedure().Initiating().Codec()
}

// UEContextSuspendResponseCodec binds the complete APER value type.
func UEContextSuspendResponseCodec() s36.UEContextSuspendResponseValueCodec {
	return UEContextSuspendProcedure().Successful().Codec()
}

// UEInformationTransferCodec binds the complete APER value type.
func UEInformationTransferCodec() s36.UEInformationTransferValueCodec {
	return UEInformationTransferProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingRequestCodec binds the complete APER value type.
func UERadioCapabilityIDMappingRequestCodec() s36.UERadioCapabilityIDMappingRequestValueCodec {
	return UERadioCapabilityIDMappingProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingResponseCodec binds the complete APER value type.
func UERadioCapabilityIDMappingResponseCodec() s36.UERadioCapabilityIDMappingResponseValueCodec {
	return UERadioCapabilityIDMappingProcedure().Successful().Codec()
}

// UERadioCapabilityMatchRequestCodec binds the complete APER value type.
func UERadioCapabilityMatchRequestCodec() s36.UERadioCapabilityMatchRequestValueCodec {
	return UERadioCapabilityMatchProcedure().Initiating().Codec()
}

// UERadioCapabilityMatchResponseCodec binds the complete APER value type.
func UERadioCapabilityMatchResponseCodec() s36.UERadioCapabilityMatchResponseValueCodec {
	return UERadioCapabilityMatchProcedure().Successful().Codec()
}

// UplinkNASTransportCodec binds the complete APER value type.
func UplinkNASTransportCodec() s44.UplinkNASTransportValueCodec {
	return UplinkNASTransportProcedure().Initiating().Codec()
}

// UplinkNonUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkNonUEAssociatedLPPaTransportCodec() s44.UplinkNonUEAssociatedLPPaTransportValueCodec {
	return UplinkNonUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// UplinkS1cdma2000tunnellingCodec binds the complete APER value type.
func UplinkS1cdma2000tunnellingCodec() s44.UplinkS1cdma2000tunnellingValueCodec {
	return UplinkS1cdma2000tunnellingProcedure().Initiating().Codec()
}

// UplinkUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkUEAssociatedLPPaTransportCodec() s44.UplinkUEAssociatedLPPaTransportValueCodec {
	return UplinkUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// WriteReplaceWarningRequestCodec binds the complete APER value type.
func WriteReplaceWarningRequestCodec() s50.WriteReplaceWarningRequestValueCodec {
	return WriteReplaceWarningProcedure().Initiating().Codec()
}

// WriteReplaceWarningResponseCodec binds the complete APER value type.
func WriteReplaceWarningResponseCodec() s50.WriteReplaceWarningResponseValueCodec {
	return WriteReplaceWarningProcedure().Successful().Codec()
}
func BridgeValidateENBConfigurationTransferBudget(v *s51.ENBConfigurationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s51.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s51.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s51.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
	report := s51.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationTransfer(v, &report, "ENBConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateMMEConfigurationTransferBudget(v *s51.MMEConfigurationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s51.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s51.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s51.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
	report := BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationTransfer(v, &report, "MMEConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateInitiatingMessage(v *s51.InitiatingMessage, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitiatingMessage")
	}
	if *s51.BridgeInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
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
		report, err := s49.BridgeValidateHandoverRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverPreparationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateHandoverRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverResourceAllocationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverNotifyBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverNotificationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidatePathSwitchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PathSwitchRequestProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverCancelProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateERABSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABSetupProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateERABModifyRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABModifyProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateERABReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABReleaseProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateERABReleaseIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABReleaseIndicationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateInitialContextSetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.InitialContextSetupProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidatePagingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PagingProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateDownlinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.DownlinkNASTransportProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateInitialUEMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.InitialUEMessageProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUplinkNASTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkNASTransportProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateResetBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ResetProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ErrorIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateNASNonDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.NASNonDeliveryIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateS1SetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextReleaseRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseRequestProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateDownlinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.DownlinkS1cdma2000tunnellingProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUplinkS1cdma2000tunnellingBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkS1cdma2000tunnellingProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextModificationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUECapabilityInfoIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UECapabilityInfoIndicationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextReleaseCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateENBStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBStatusTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEStatusTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateDeactivateTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.DeactivateTraceProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateTraceStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{TraceStartProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateTraceFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{TraceFailureIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateENBConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBConfigurationUpdateProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEConfigurationUpdateProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateLocationReportingControlBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.LocationReportingControlProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateLocationReportingFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.LocationReportingFailureIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateLocationReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.LocationReportProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateOverloadStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.OverloadStartProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateOverloadStopBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.OverloadStopProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateWriteReplaceWarningRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{WriteReplaceWarningProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateENBDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBDirectInformationTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEDirectInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEDirectInformationTransferProcedure().Info().Rule}})
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
		report, err := s47.BridgeValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PrivateMessageProcedure().Info().Rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ENBConfigurationTransferProcedure().Info().Rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{MMEConfigurationTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateCellTrafficTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.CellTrafficTraceProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateKillRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.KillProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.DownlinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkUEAssociatedLPPaTransportProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.DownlinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UplinkNonUEAssociatedLPPaTransportProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUERadioCapabilityMatchRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityMatchProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidatePWSRestartIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PWSRestartIndicationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateERABModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABModificationIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidatePWSFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PWSFailureIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateRerouteNASRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{RerouteNASRequestProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextModificationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateConnectionEstablishmentIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ConnectionEstablishmentIndicationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextSuspendRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextSuspendProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextResumeRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateNASDeliveryIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.NASDeliveryIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateRetrieveUEInformationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{RetrieveUEInformationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEInformationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEInformationTransferProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateENBCPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBCPRelocationIndicationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMECPRelocationIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMECPRelocationIndicationProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateSecondaryRATDataUsageReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{SecondaryRATDataUsageReportProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUERadioCapabilityIDMappingRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverSuccessBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverSuccessProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateENBEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBEarlyStatusTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEEarlyStatusTransferProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateS1RemovalRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}
func BridgeValidateSuccessfulOutcome(v *s50.SuccessfulOutcome, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SuccessfulOutcome")
	}
	if *s50.BridgeSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
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
		report, err := s49.BridgeValidateHandoverCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverPreparationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidatePathSwitchRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PathSwitchRequestProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverCancelAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverCancelProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateERABSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABSetupProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateERABModifyResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABModifyProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateERABReleaseResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateInitialContextSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateResetAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateS1SetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextModificationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextReleaseCompleteBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateENBConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBConfigurationUpdateProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateWriteReplaceWarningResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{WriteReplaceWarningProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateKillResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.KillProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUERadioCapabilityMatchResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityMatchProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateERABModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ERABModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextSuspendResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextSuspendProcedure().Info().Rule}})
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
		report, err := s50.BridgeValidateUEContextResumeResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUERadioCapabilityIDMappingResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 64:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateS1RemovalResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s21.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateUnsuccessfulOutcome(v *s36.UnsuccessfulOutcome, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UnsuccessfulOutcome")
	}
	if *s36.BridgeUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
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
		report, err := s49.BridgeValidateHandoverPreparationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverPreparationProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateHandoverFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidatePathSwitchRequestFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 7:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 8:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateInitialContextSetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 15:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateS1SetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextModificationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 23:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 24:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateENBConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.ENBConfigurationUpdateProcedure().Info().Rule}})
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
		report, err := s49.BridgeValidateMMEConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s51.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 37:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 44:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 49:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 51:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 54:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 55:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s50.BridgeValidateUEContextResumeFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 63:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 64:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s26.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
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
		report, err := s49.BridgeValidateS1RemovalFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s21.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s21.ValidationReport {
			report := func() s21.ValidationReport {
				sealed := s21.ValidationReport{Complete: false}
				*s21.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s26.BridgeS1apValidationRule(s00.UnknownProcedure)})
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
func ValidateENBConfigurationTransfer(v *s51.ENBConfigurationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	report, err := BridgeValidateENBConfigurationTransferBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s51.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationTransfer")
}
func ValidateMMEConfigurationTransfer(v *s51.MMEConfigurationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	report, err := BridgeValidateMMEConfigurationTransferBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s51.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Message")
}
func BridgeWalkValidationENBConfigurationTransfer(v *s51.ENBConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s51.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s51.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s51.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
			s25.BridgeMergeNestedValidation(report, s51.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENDCSONConfigurationTransfer(v *s50.ENDCSONConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationENDCSONTransferType(&v.Transfertype, report, path+".transfertype", false)
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
				s25.BridgeMergeNestedValidation(report, s27.BridgeENDCSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationInitiatingMessage(v *s51.InitiatingMessage, report *s21.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationMMEConfigurationTransfer(v *s51.MMEConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s51.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s51.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s51.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
			s25.BridgeMergeNestedValidation(report, BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
		s50.BridgeWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
	}
	if v.Choice == s00.S1APPDUChoiceUnsuccessfulOutcome && v.UnsuccessfulOutcome != nil {
		s50.BridgeWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
	}
}
func BridgeWalkValidationSONConfigurationTransfer(v *s50.SONConfigurationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationTargeteNBID(&v.TargeteNBID, report, path+".targeteNB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationSourceeNBID(&v.SourceeNBID, report, path+".sourceeNB-ID", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s50.SONConfigurationTransferExtIEs().X2TNLConfigurationInfo().Info()), s00.FieldInfo(s50.SONConfigurationTransferExtIEs().SynchronisationInformation().Info()), s00.FieldInfo(s50.SONConfigurationTransferExtIEs().RequestedTNLInfo().Info())}
				s25.BridgeMergeNestedValidation(report, BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
						s49.BridgeWalkValidationSynchronisationInformation(value, report, fmt.Sprintf("%s[%d]{id=209}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(356):
					if value, ok := fields[i].ExtensionValue.AsRequestedTNLInfo(); ok {
						s49.BridgeWalkValidationRequestedTNLInfo(value, report, fmt.Sprintf("%s[%d]{id=356}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformation(v *s50.SONInformation, report *s21.ValidationReport, path string, skipRoot bool) {
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
		s49.BridgeWalkValidationSONInformationExtension(v.SONInformationExtension, report, path+".sONInformation-Extension", false)
	}
}
func BridgeWalkValidationSONInformationReply(v *s50.SONInformationReply, report *s21.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s34.SONInformationReplyExtIEs().TimeSynchronisationInfo().Info()), s00.FieldInfo(s34.SONInformationReplyExtIEs().MutingPatternInformation().Info())}
				s25.BridgeMergeNestedValidation(report, s34.BridgeSONInformationReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(149):
					if value, ok := fields[i].ExtensionValue.AsTimeSynchronisationInfo(); ok {
						s49.BridgeWalkValidationTimeSynchronisationInfo(value, report, fmt.Sprintf("%s[%d]{id=149}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(208):
					if value, ok := fields[i].ExtensionValue.AsMutingPatternInformation(); ok {
						s49.BridgeWalkValidationMutingPatternInformation(value, report, fmt.Sprintf("%s[%d]{id=208}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationX2TNLConfigurationInfo(v *s50.X2TNLConfigurationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationENBX2TLAs(&v.ENBX2TransportLayerAddresses, report, path+".eNBX2TransportLayerAddresses", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s38.X2TNLConfigurationInfoExtIEs().ENBX2ExtendedTransportLayerAddresses().Info()), s00.FieldInfo(s38.X2TNLConfigurationInfoExtIEs().ENBIndirectX2TransportLayerAddresses().Info())}
				s25.BridgeMergeNestedValidation(report, BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(153):
					if value, ok := fields[i].ExtensionValue.AsENBX2ExtendedTransportLayerAddresses(); ok {
						s49.BridgeWalkValidationENBX2ExtTLAs(value, report, fmt.Sprintf("%s[%d]{id=153}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(193):
					if value, ok := fields[i].ExtensionValue.AsENBIndirectX2TransportLayerAddresses(); ok {
						s49.BridgeWalkValidationENBIndirectX2TransportLayerAddresses(value, report, fmt.Sprintf("%s[%d]{id=193}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeRerouteNASRequestInitiatingBindingFieldCapture(v *RerouteNASRequestInitiatingBinding) *func(s26.RerouteNASRequest, aper.DecodeState) (s26.RerouteNASRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestInitiatingBindingFieldCompare(v *RerouteNASRequestInitiatingBinding) *func(s26.RerouteNASRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestInitiatingBindingFieldContext(v *RerouteNASRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestInitiatingBindingFieldDecode(v *RerouteNASRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s26.RerouteNASRequest, error) {
	return &v.decode
}
func BridgeRerouteNASRequestInitiatingBindingFieldEncode(v *RerouteNASRequestInitiatingBinding) *func(*s26.RerouteNASRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestInitiatingBindingFieldInfo(v *RerouteNASRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeRerouteNASRequestInitiatingBindingFieldInject(v *RerouteNASRequestInitiatingBinding) *func(s26.RerouteNASRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeRerouteNASRequestInitiatingBindingFieldValidate(v *RerouteNASRequestInitiatingBinding) *func(*s26.RerouteNASRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeResetInitiatingBindingFieldInject(v *ResetInitiatingBinding) *func(s36.Reset) s51.InitiatingValue {
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
func BridgeRetrieveUEInformationInitiatingBindingFieldInject(v *RetrieveUEInformationInitiatingBinding) *func(s28.RetrieveUEInformation) s51.InitiatingValue {
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
func BridgeS1RemovalRequestInitiatingBindingFieldCapture(v *S1RemovalRequestInitiatingBinding) *func(s26.S1RemovalRequest, aper.DecodeState) (s26.S1RemovalRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestInitiatingBindingFieldCompare(v *S1RemovalRequestInitiatingBinding) *func(s26.S1RemovalRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestInitiatingBindingFieldContext(v *S1RemovalRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestInitiatingBindingFieldDecode(v *S1RemovalRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s26.S1RemovalRequest, error) {
	return &v.decode
}
func BridgeS1RemovalRequestInitiatingBindingFieldEncode(v *S1RemovalRequestInitiatingBinding) *func(*s26.S1RemovalRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestInitiatingBindingFieldInfo(v *S1RemovalRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalRequestInitiatingBindingFieldInject(v *S1RemovalRequestInitiatingBinding) *func(s26.S1RemovalRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeS1RemovalRequestInitiatingBindingFieldValidate(v *S1RemovalRequestInitiatingBinding) *func(*s26.S1RemovalRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupRequestInitiatingBindingFieldCapture(v *S1SetupRequestInitiatingBinding) *func(s43.S1SetupRequest, aper.DecodeState) (s43.S1SetupRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestInitiatingBindingFieldCompare(v *S1SetupRequestInitiatingBinding) *func(s43.S1SetupRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestInitiatingBindingFieldContext(v *S1SetupRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestInitiatingBindingFieldDecode(v *S1SetupRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s43.S1SetupRequest, error) {
	return &v.decode
}
func BridgeS1SetupRequestInitiatingBindingFieldEncode(v *S1SetupRequestInitiatingBinding) *func(*s43.S1SetupRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestInitiatingBindingFieldInfo(v *S1SetupRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupRequestInitiatingBindingFieldInject(v *S1SetupRequestInitiatingBinding) *func(s43.S1SetupRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeS1SetupRequestInitiatingBindingFieldValidate(v *S1SetupRequestInitiatingBinding) *func(*s43.S1SetupRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldCapture(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s46.SecondaryRATDataUsageReport, aper.DecodeState) (s46.SecondaryRATDataUsageReport, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldCompare(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s46.SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldContext(v *SecondaryRATDataUsageReportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldDecode(v *SecondaryRATDataUsageReportInitiatingBinding) *func([]byte, aper.DecodeState) (s46.SecondaryRATDataUsageReport, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldEncode(v *SecondaryRATDataUsageReportInitiatingBinding) *func(*s46.SecondaryRATDataUsageReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldInfo(v *SecondaryRATDataUsageReportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldInject(v *SecondaryRATDataUsageReportInitiatingBinding) *func(s46.SecondaryRATDataUsageReport) s51.InitiatingValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportInitiatingBindingFieldValidate(v *SecondaryRATDataUsageReportInitiatingBinding) *func(*s46.SecondaryRATDataUsageReport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeTraceFailureIndicationInitiatingBindingFieldCapture(v *TraceFailureIndicationInitiatingBinding) *func(s34.TraceFailureIndication, aper.DecodeState) (s34.TraceFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationInitiatingBindingFieldCompare(v *TraceFailureIndicationInitiatingBinding) *func(s34.TraceFailureIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationInitiatingBindingFieldContext(v *TraceFailureIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationInitiatingBindingFieldDecode(v *TraceFailureIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s34.TraceFailureIndication, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationInitiatingBindingFieldEncode(v *TraceFailureIndicationInitiatingBinding) *func(*s34.TraceFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationInitiatingBindingFieldInfo(v *TraceFailureIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeTraceFailureIndicationInitiatingBindingFieldInject(v *TraceFailureIndicationInitiatingBinding) *func(s34.TraceFailureIndication) s51.InitiatingValue {
	return &v.inject
}
func BridgeTraceFailureIndicationInitiatingBindingFieldValidate(v *TraceFailureIndicationInitiatingBinding) *func(*s34.TraceFailureIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeTraceStartInitiatingBindingFieldCapture(v *TraceStartInitiatingBinding) *func(s48.TraceStart, aper.DecodeState) (s48.TraceStart, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartInitiatingBindingFieldCompare(v *TraceStartInitiatingBinding) *func(s48.TraceStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartInitiatingBindingFieldContext(v *TraceStartInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartInitiatingBindingFieldDecode(v *TraceStartInitiatingBinding) *func([]byte, aper.DecodeState) (s48.TraceStart, error) {
	return &v.decode
}
func BridgeTraceStartInitiatingBindingFieldEncode(v *TraceStartInitiatingBinding) *func(*s48.TraceStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartInitiatingBindingFieldInfo(v *TraceStartInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeTraceStartInitiatingBindingFieldInject(v *TraceStartInitiatingBinding) *func(s48.TraceStart) s51.InitiatingValue {
	return &v.inject
}
func BridgeTraceStartInitiatingBindingFieldValidate(v *TraceStartInitiatingBinding) *func(*s48.TraceStart, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldInject(v *UECapabilityInfoIndicationInitiatingBinding) *func(s36.UECapabilityInfoIndication) s51.InitiatingValue {
	return &v.inject
}
func BridgeUECapabilityInfoIndicationInitiatingBindingFieldValidate(v *UECapabilityInfoIndicationInitiatingBinding) *func(*s36.UECapabilityInfoIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldCapture(v *UEContextModificationIndicationInitiatingBinding) *func(s36.UEContextModificationIndication, aper.DecodeState) (s36.UEContextModificationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldCompare(v *UEContextModificationIndicationInitiatingBinding) *func(s36.UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldContext(v *UEContextModificationIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldDecode(v *UEContextModificationIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s36.UEContextModificationIndication, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldEncode(v *UEContextModificationIndicationInitiatingBinding) *func(*s36.UEContextModificationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldInfo(v *UEContextModificationIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldInject(v *UEContextModificationIndicationInitiatingBinding) *func(s36.UEContextModificationIndication) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextModificationIndicationInitiatingBindingFieldValidate(v *UEContextModificationIndicationInitiatingBinding) *func(*s36.UEContextModificationIndication, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationRequestInitiatingBindingFieldCapture(v *UEContextModificationRequestInitiatingBinding) *func(s46.UEContextModificationRequest, aper.DecodeState) (s46.UEContextModificationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestInitiatingBindingFieldCompare(v *UEContextModificationRequestInitiatingBinding) *func(s46.UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestInitiatingBindingFieldContext(v *UEContextModificationRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestInitiatingBindingFieldDecode(v *UEContextModificationRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s46.UEContextModificationRequest, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestInitiatingBindingFieldEncode(v *UEContextModificationRequestInitiatingBinding) *func(*s46.UEContextModificationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestInitiatingBindingFieldInfo(v *UEContextModificationRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationRequestInitiatingBindingFieldInject(v *UEContextModificationRequestInitiatingBinding) *func(s46.UEContextModificationRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextModificationRequestInitiatingBindingFieldValidate(v *UEContextModificationRequestInitiatingBinding) *func(*s46.UEContextModificationRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeUEContextReleaseCommandInitiatingBindingFieldInject(v *UEContextReleaseCommandInitiatingBinding) *func(s37.UEContextReleaseCommand) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandInitiatingBindingFieldValidate(v *UEContextReleaseCommandInitiatingBinding) *func(*s37.UEContextReleaseCommand, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldCapture(v *UEContextReleaseRequestInitiatingBinding) *func(s42.UEContextReleaseRequest, aper.DecodeState) (s42.UEContextReleaseRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldCompare(v *UEContextReleaseRequestInitiatingBinding) *func(s42.UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldContext(v *UEContextReleaseRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldDecode(v *UEContextReleaseRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s42.UEContextReleaseRequest, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldEncode(v *UEContextReleaseRequestInitiatingBinding) *func(*s42.UEContextReleaseRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldInfo(v *UEContextReleaseRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldInject(v *UEContextReleaseRequestInitiatingBinding) *func(s42.UEContextReleaseRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestInitiatingBindingFieldValidate(v *UEContextReleaseRequestInitiatingBinding) *func(*s42.UEContextReleaseRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeRequestInitiatingBindingFieldCapture(v *UEContextResumeRequestInitiatingBinding) *func(s38.UEContextResumeRequest, aper.DecodeState) (s38.UEContextResumeRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeRequestInitiatingBindingFieldCompare(v *UEContextResumeRequestInitiatingBinding) *func(s38.UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeRequestInitiatingBindingFieldContext(v *UEContextResumeRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeRequestInitiatingBindingFieldDecode(v *UEContextResumeRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s38.UEContextResumeRequest, error) {
	return &v.decode
}
func BridgeUEContextResumeRequestInitiatingBindingFieldEncode(v *UEContextResumeRequestInitiatingBinding) *func(*s38.UEContextResumeRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeRequestInitiatingBindingFieldInfo(v *UEContextResumeRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeRequestInitiatingBindingFieldInject(v *UEContextResumeRequestInitiatingBinding) *func(s38.UEContextResumeRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextResumeRequestInitiatingBindingFieldValidate(v *UEContextResumeRequestInitiatingBinding) *func(*s38.UEContextResumeRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldCapture(v *UEContextSuspendRequestInitiatingBinding) *func(s46.UEContextSuspendRequest, aper.DecodeState) (s46.UEContextSuspendRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldCompare(v *UEContextSuspendRequestInitiatingBinding) *func(s46.UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldContext(v *UEContextSuspendRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldDecode(v *UEContextSuspendRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s46.UEContextSuspendRequest, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldEncode(v *UEContextSuspendRequestInitiatingBinding) *func(*s46.UEContextSuspendRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldInfo(v *UEContextSuspendRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldInject(v *UEContextSuspendRequestInitiatingBinding) *func(s46.UEContextSuspendRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEContextSuspendRequestInitiatingBindingFieldValidate(v *UEContextSuspendRequestInitiatingBinding) *func(*s46.UEContextSuspendRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEInformationTransferInitiatingBindingFieldCapture(v *UEInformationTransferInitiatingBinding) *func(s36.UEInformationTransfer, aper.DecodeState) (s36.UEInformationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferInitiatingBindingFieldCompare(v *UEInformationTransferInitiatingBinding) *func(s36.UEInformationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferInitiatingBindingFieldContext(v *UEInformationTransferInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferInitiatingBindingFieldDecode(v *UEInformationTransferInitiatingBinding) *func([]byte, aper.DecodeState) (s36.UEInformationTransfer, error) {
	return &v.decode
}
func BridgeUEInformationTransferInitiatingBindingFieldEncode(v *UEInformationTransferInitiatingBinding) *func(*s36.UEInformationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferInitiatingBindingFieldInfo(v *UEInformationTransferInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEInformationTransferInitiatingBindingFieldInject(v *UEInformationTransferInitiatingBinding) *func(s36.UEInformationTransfer) s51.InitiatingValue {
	return &v.inject
}
func BridgeUEInformationTransferInitiatingBindingFieldValidate(v *UEInformationTransferInitiatingBinding) *func(*s36.UEInformationTransfer, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldCapture(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s36.UERadioCapabilityIDMappingRequest, aper.DecodeState) (s36.UERadioCapabilityIDMappingRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldCompare(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s36.UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldContext(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldDecode(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s36.UERadioCapabilityIDMappingRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldEncode(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(*s36.UERadioCapabilityIDMappingRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldInfo(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldInject(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(s36.UERadioCapabilityIDMappingRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingRequestInitiatingBindingFieldValidate(v *UERadioCapabilityIDMappingRequestInitiatingBinding) *func(*s36.UERadioCapabilityIDMappingRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldCapture(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s36.UERadioCapabilityMatchRequest, aper.DecodeState) (s36.UERadioCapabilityMatchRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldCompare(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s36.UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldContext(v *UERadioCapabilityMatchRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldDecode(v *UERadioCapabilityMatchRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s36.UERadioCapabilityMatchRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldEncode(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(*s36.UERadioCapabilityMatchRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldInfo(v *UERadioCapabilityMatchRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldInject(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(s36.UERadioCapabilityMatchRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchRequestInitiatingBindingFieldValidate(v *UERadioCapabilityMatchRequestInitiatingBinding) *func(*s36.UERadioCapabilityMatchRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkNASTransportInitiatingBindingFieldCapture(v *UplinkNASTransportInitiatingBinding) *func(s44.UplinkNASTransport, aper.DecodeState) (s44.UplinkNASTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportInitiatingBindingFieldCompare(v *UplinkNASTransportInitiatingBinding) *func(s44.UplinkNASTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportInitiatingBindingFieldContext(v *UplinkNASTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportInitiatingBindingFieldDecode(v *UplinkNASTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s44.UplinkNASTransport, error) {
	return &v.decode
}
func BridgeUplinkNASTransportInitiatingBindingFieldEncode(v *UplinkNASTransportInitiatingBinding) *func(*s44.UplinkNASTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportInitiatingBindingFieldInfo(v *UplinkNASTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkNASTransportInitiatingBindingFieldInject(v *UplinkNASTransportInitiatingBinding) *func(s44.UplinkNASTransport) s51.InitiatingValue {
	return &v.inject
}
func BridgeUplinkNASTransportInitiatingBindingFieldValidate(v *UplinkNASTransportInitiatingBinding) *func(*s44.UplinkNASTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldCapture(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkNonUEAssociatedLPPaTransport, aper.DecodeState) (s44.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldCompare(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldContext(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldDecode(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s44.UplinkNonUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldEncode(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(*s44.UplinkNonUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldInfo(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldInject(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkNonUEAssociatedLPPaTransport) s51.InitiatingValue {
	return &v.inject
}
func BridgeUplinkNonUEAssociatedLPPaTransportInitiatingBindingFieldValidate(v *UplinkNonUEAssociatedLPPaTransportInitiatingBinding) *func(*s44.UplinkNonUEAssociatedLPPaTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldCapture(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s44.UplinkS1cdma2000tunnelling, aper.DecodeState) (s44.UplinkS1cdma2000tunnelling, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldCompare(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s44.UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldContext(v *UplinkS1cdma2000tunnellingInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldDecode(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func([]byte, aper.DecodeState) (s44.UplinkS1cdma2000tunnelling, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldEncode(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(*s44.UplinkS1cdma2000tunnelling, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldInfo(v *UplinkS1cdma2000tunnellingInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldInject(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(s44.UplinkS1cdma2000tunnelling) s51.InitiatingValue {
	return &v.inject
}
func BridgeUplinkS1cdma2000tunnellingInitiatingBindingFieldValidate(v *UplinkS1cdma2000tunnellingInitiatingBinding) *func(*s44.UplinkS1cdma2000tunnelling, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldCapture(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkUEAssociatedLPPaTransport, aper.DecodeState) (s44.UplinkUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldCompare(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldContext(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldDecode(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func([]byte, aper.DecodeState) (s44.UplinkUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldEncode(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(*s44.UplinkUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldInfo(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldInject(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(s44.UplinkUEAssociatedLPPaTransport) s51.InitiatingValue {
	return &v.inject
}
func BridgeUplinkUEAssociatedLPPaTransportInitiatingBindingFieldValidate(v *UplinkUEAssociatedLPPaTransportInitiatingBinding) *func(*s44.UplinkUEAssociatedLPPaTransport, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldCapture(v *WriteReplaceWarningRequestInitiatingBinding) *func(s50.WriteReplaceWarningRequest, aper.DecodeState) (s50.WriteReplaceWarningRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldCompare(v *WriteReplaceWarningRequestInitiatingBinding) *func(s50.WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldContext(v *WriteReplaceWarningRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldDecode(v *WriteReplaceWarningRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s50.WriteReplaceWarningRequest, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldEncode(v *WriteReplaceWarningRequestInitiatingBinding) *func(*s50.WriteReplaceWarningRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldInfo(v *WriteReplaceWarningRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldInject(v *WriteReplaceWarningRequestInitiatingBinding) *func(s50.WriteReplaceWarningRequest) s51.InitiatingValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestInitiatingBindingFieldValidate(v *WriteReplaceWarningRequestInitiatingBinding) *func(*s50.WriteReplaceWarningRequest, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
