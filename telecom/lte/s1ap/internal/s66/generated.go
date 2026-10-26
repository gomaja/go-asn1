// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s66 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s66

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewENBConfigurationTransfer(fields s64.ENBConfigurationTransferIEContainer, options ...aper.BuildOption) (s65.ENBConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s64.ENBConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	v := s65.ENBConfigurationTransfer{ProtocolIEs: make(s64.ENBConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBConfigurationTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBConfigurationTransfer")
	}
	if _, err := s65.BridgeENBConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s65.ENBConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationTransfer.protocolIEs:", err), "ENBConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "ENBConfigurationTransfer")
}
func NewMMEConfigurationTransfer(fields s64.MMEConfigurationTransferIEContainer, options ...aper.BuildOption) (s65.MMEConfigurationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s64.MMEConfigurationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	v := s65.MMEConfigurationTransfer{ProtocolIEs: make(s64.MMEConfigurationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationTransferBudget(&v, budget)
	if err != nil {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEConfigurationTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEConfigurationTransfer")
	}
	if _, err := s65.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s65.MMEConfigurationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationTransfer.protocolIEs:", err), "MMEConfigurationTransfer")
	}
	return v, aper.OperationError(nil, "MMEConfigurationTransfer")
}

// Initiating returns the typed binding for the initiating message of PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Initiating() PathSwitchRequestInitiatingBinding {
	return PathSwitchRequestInitiatingBinding{info: PathSwitchRequestProcedure().Info(), validate: func(v *s51.PathSwitchRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidatePathSwitchRequestBudget(v, budget)
	}, encode: func(v *s51.PathSwitchRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s51.BridgePathSwitchRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s51.PathSwitchRequest, error) {
		var v s51.PathSwitchRequest
		err := s51.BridgePathSwitchRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s51.PathSwitchRequest{}, err
		}
		*s51.BridgePathSwitchRequestFieldReceived(&v) = true
		*s51.BridgePathSwitchRequestFieldReceivedAbsolute(&v) = true
		*s51.BridgePathSwitchRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s51.PathSwitchRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(3)
			*s65.BridgeInitiatingValueFieldBodyPathSwitchRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s51.PathSwitchRequest, options aper.DecodeState) (s51.PathSwitchRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s51.BridgeCaptureS1APPathSwitchRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s51.PathSwitchRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s51.BridgeCompareS1APPathSwitchRequest(&v, &s)
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
func (PathSwitchRequestDescriptor) Successful() s64.PathSwitchRequestAcknowledgeSuccessfulBinding {
	return func() s64.PathSwitchRequestAcknowledgeSuccessfulBinding {
		sealed := s64.PathSwitchRequestAcknowledgeSuccessfulBinding{}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInfo(&sealed) = PathSwitchRequestProcedure().Info()
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s58.PathSwitchRequestAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidatePathSwitchRequestAcknowledgeBudget(v, budget)
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s58.PathSwitchRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s58.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s58.PathSwitchRequestAcknowledge, error) {
			var v s58.PathSwitchRequestAcknowledge
			err := s58.BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s58.PathSwitchRequestAcknowledge{}, err
			}
			*s58.BridgePathSwitchRequestAcknowledgeFieldReceived(&v) = true
			*s58.BridgePathSwitchRequestAcknowledgeFieldReceivedAbsolute(&v) = true
			*s58.BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s58.PathSwitchRequestAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s64.BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s58.PathSwitchRequestAcknowledge, options aper.DecodeState) (s58.PathSwitchRequestAcknowledge, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s58.BridgeCaptureS1APPathSwitchRequestAcknowledge(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s58.PathSwitchRequestAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s58.BridgeCompareS1APPathSwitchRequestAcknowledge(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PathSwitchRequestAcknowledge"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of PathSwitchRequestDescriptor.
func (PathSwitchRequestDescriptor) Unsuccessful() s46.PathSwitchRequestFailureUnsuccessfulBinding {
	return func() s46.PathSwitchRequestFailureUnsuccessfulBinding {
		sealed := s46.PathSwitchRequestFailureUnsuccessfulBinding{}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInfo(&sealed) = PathSwitchRequestProcedure().Info()
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s30.PathSwitchRequestFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidatePathSwitchRequestFailureBudget(v, budget)
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s30.PathSwitchRequestFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s30.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.PathSwitchRequestFailure, error) {
			var v s30.PathSwitchRequestFailure
			err := s30.BridgePathSwitchRequestFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s30.PathSwitchRequestFailure{}, err
			}
			*s30.BridgePathSwitchRequestFailureFieldReceived(&v) = true
			*s30.BridgePathSwitchRequestFailureFieldReceivedAbsolute(&v) = true
			*s30.BridgePathSwitchRequestFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s30.PathSwitchRequestFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s46.BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s30.PathSwitchRequestFailure, options aper.DecodeState) (s30.PathSwitchRequestFailure, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APPathSwitchRequestFailure(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s30.PathSwitchRequestFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APPathSwitchRequestFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgePathSwitchRequestFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PathSwitchRequestFailure"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of PagingDescriptor.
func (PagingDescriptor) Initiating() PagingInitiatingBinding {
	return PagingInitiatingBinding{info: PagingProcedure().Info(), validate: func(v *s61.Paging, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidatePagingBudget(v, budget)
	}, encode: func(v *s61.Paging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s61.BridgePagingMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s61.Paging, error) {
		var v s61.Paging
		err := s61.BridgePagingMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s61.Paging{}, err
		}
		*s61.BridgePagingFieldReceived(&v) = true
		*s61.BridgePagingFieldReceivedAbsolute(&v) = true
		*s61.BridgePagingFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s61.Paging) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(10)
			*s65.BridgeInitiatingValueFieldBodyPaging(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s61.Paging, options aper.DecodeState) (s61.Paging, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.
				Begin()
		s61.BridgeCaptureS1APPaging(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v s61.Paging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s61.BridgeCompareS1APPaging(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Paging"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of UplinkNASTransportDescriptor.
func (UplinkNASTransportDescriptor) Initiating() UplinkNASTransportInitiatingBinding {
	return UplinkNASTransportInitiatingBinding{info: UplinkNASTransportProcedure().Info(), validate: func(v *s55.UplinkNASTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUplinkNASTransportBudget(v, budget)
	}, encode: func(v *s55.UplinkNASTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s55.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s55.UplinkNASTransport, error) {
		var v s55.UplinkNASTransport
		err := s55.BridgeUplinkNASTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s55.UplinkNASTransport{}, err
		}
		*s55.BridgeUplinkNASTransportFieldReceived(&v) = true
		*s55.BridgeUplinkNASTransportFieldReceivedAbsolute(&v) = true
		*s55.BridgeUplinkNASTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s55.UplinkNASTransport) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(13)
			*s65.BridgeInitiatingValueFieldBodyUplinkNASTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s55.UplinkNASTransport, options aper.DecodeState) (s55.UplinkNASTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s55.BridgeCaptureS1APUplinkNASTransport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s55.UplinkNASTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s55.BridgeCompareS1APUplinkNASTransport(&v, &s)
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
	return ResetInitiatingBinding{info: ResetProcedure().Info(), validate: func(v *s45.Reset, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateResetBudget(v, budget)
	}, encode: func(v *s45.Reset, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeResetMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.Reset, error) {
		var v s45.Reset
		err := s45.BridgeResetMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.Reset{}, err
		}
		*s45.BridgeResetFieldReceived(&v) = true
		*s45.BridgeResetFieldReceivedAbsolute(&v) = true
		*s45.BridgeResetFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.Reset) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(14)
			*s65.BridgeInitiatingValueFieldBodyReset(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.Reset, options aper.DecodeState) (s45.Reset, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.
			Begin()
		s45.BridgeCaptureS1APReset(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s45.Reset, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APReset(&v, &s)
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
func (ResetDescriptor) Successful() s64.ResetAcknowledgeSuccessfulBinding {
	return func() s64.ResetAcknowledgeSuccessfulBinding {
		sealed := s64.ResetAcknowledgeSuccessfulBinding{}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldInfo(&sealed) = ResetProcedure().Info()
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldValidate(&sealed) = func(v *s55.ResetAcknowledge, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateResetAcknowledgeBudget(v, budget)
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldEncode(&sealed) = func(v *s55.ResetAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s55.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s55.ResetAcknowledge, error) {
			var v s55.ResetAcknowledge
			err := s55.BridgeResetAcknowledgeMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s55.ResetAcknowledge{}, err
			}
			*s55.BridgeResetAcknowledgeFieldReceived(&v) = true
			*s55.BridgeResetAcknowledgeFieldReceivedAbsolute(&v) = true
			*s55.BridgeResetAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldInject(&sealed) = func(v s55.ResetAcknowledge) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s64.BridgeSuccessfulValueFieldBodyResetAcknowledge(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldCapture(&sealed) = func(v s55.ResetAcknowledge, options aper.DecodeState) (s55.ResetAcknowledge, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s55.BridgeCaptureS1APResetAcknowledge(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldCompare(&sealed) = func(v s55.ResetAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s55.BridgeCompareS1APResetAcknowledge(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s64.BridgeResetAcknowledgeSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return S1SetupRequestInitiatingBinding{info: S1SetupProcedure().Info(), validate: func(v *s54.S1SetupRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateS1SetupRequestBudget(v, budget)
	}, encode: func(v *s54.S1SetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s54.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s54.S1SetupRequest, error) {
		var v s54.S1SetupRequest
		err := s54.BridgeS1SetupRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s54.S1SetupRequest{}, err
		}
		*s54.BridgeS1SetupRequestFieldReceived(&v) = true
		*s54.BridgeS1SetupRequestFieldReceivedAbsolute(&v) = true
		*s54.BridgeS1SetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s54.S1SetupRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(17)
			*s65.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s54.S1SetupRequest, options aper.DecodeState) (s54.S1SetupRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s54.BridgeCaptureS1APS1SetupRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s54.S1SetupRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s54.BridgeCompareS1APS1SetupRequest(&v, &s)
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
func (S1SetupDescriptor) Successful() s64.S1SetupResponseSuccessfulBinding {
	return func() s64.S1SetupResponseSuccessfulBinding {
		sealed := s64.S1SetupResponseSuccessfulBinding{}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s54.S1SetupResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateS1SetupResponseBudget(v, budget)
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s54.S1SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s54.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s54.S1SetupResponse, error) {
			var v s54.S1SetupResponse
			err := s54.BridgeS1SetupResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s54.S1SetupResponse{}, err
			}
			*s54.BridgeS1SetupResponseFieldReceived(&v) = true
			*s54.BridgeS1SetupResponseFieldReceivedAbsolute(&v) = true
			*s54.BridgeS1SetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldInject(&sealed) = func(v s54.S1SetupResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s64.BridgeSuccessfulValueFieldBodyS1SetupResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldCapture(&sealed) = func(v s54.S1SetupResponse, options aper.DecodeState) (s54.S1SetupResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s54.BridgeCaptureS1APS1SetupResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldCompare(&sealed) = func(v s54.S1SetupResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s54.BridgeCompareS1APS1SetupResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s64.BridgeS1SetupResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1SetupResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1SetupDescriptor.
func (S1SetupDescriptor) Unsuccessful() s46.S1SetupFailureUnsuccessfulBinding {
	return func() s46.S1SetupFailureUnsuccessfulBinding {
		sealed := s46.S1SetupFailureUnsuccessfulBinding{}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(&sealed) = S1SetupProcedure().Info()
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s31.S1SetupFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateS1SetupFailureBudget(v, budget)
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s31.S1SetupFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s31.BridgeS1SetupFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.S1SetupFailure, error) {
			var v s31.S1SetupFailure
			err := s31.BridgeS1SetupFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s31.S1SetupFailure{}, err
			}
			*s31.BridgeS1SetupFailureFieldReceived(&v) = true
			*s31.BridgeS1SetupFailureFieldReceivedAbsolute(&v) = true
			*s31.BridgeS1SetupFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s31.S1SetupFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s46.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s31.S1SetupFailure, options aper.DecodeState) (s31.S1SetupFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s31.BridgeCaptureS1APS1SetupFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s31.S1SetupFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APS1SetupFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeS1SetupFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextReleaseRequestInitiatingBinding{info: UEContextReleaseRequestProcedure().Info(), validate: func(v *s53.UEContextReleaseRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEContextReleaseRequestBudget(v, budget)
	}, encode: func(v *s53.UEContextReleaseRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s53.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s53.UEContextReleaseRequest, error) {
		var v s53.UEContextReleaseRequest
		err := s53.BridgeUEContextReleaseRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s53.UEContextReleaseRequest{}, err
		}
		*s53.BridgeUEContextReleaseRequestFieldReceived(&v) = true
		*s53.BridgeUEContextReleaseRequestFieldReceivedAbsolute(&v) = true
		*s53.BridgeUEContextReleaseRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s53.UEContextReleaseRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(18)
			*s65.BridgeInitiatingValueFieldBodyUEContextReleaseRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s53.UEContextReleaseRequest, options aper.DecodeState) (s53.UEContextReleaseRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s53.BridgeCaptureS1APUEContextReleaseRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s53.UEContextReleaseRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s53.BridgeCompareS1APUEContextReleaseRequest(&v, &s)
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
	return UplinkS1cdma2000tunnellingInitiatingBinding{info: UplinkS1cdma2000tunnellingProcedure().Info(), validate: func(v *s55.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	}, encode: func(v *s55.UplinkS1cdma2000tunnelling, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s55.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s55.UplinkS1cdma2000tunnelling, error) {
		var v s55.UplinkS1cdma2000tunnelling
		err := s55.BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s55.UplinkS1cdma2000tunnelling{}, err
		}
		*s55.BridgeUplinkS1cdma2000tunnellingFieldReceived(&v) = true
		*s55.BridgeUplinkS1cdma2000tunnellingFieldReceivedAbsolute(&v) = true
		*s55.BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s55.UplinkS1cdma2000tunnelling) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(20)
			*s65.BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s55.UplinkS1cdma2000tunnelling, options aper.DecodeState) (s55.UplinkS1cdma2000tunnelling, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s55.BridgeCaptureS1APUplinkS1cdma2000tunnelling(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s55.UplinkS1cdma2000tunnelling, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s55.BridgeCompareS1APUplinkS1cdma2000tunnelling(&v, &s)
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
	return UEContextModificationRequestInitiatingBinding{info: UEContextModificationProcedure().Info(), validate: func(v *s58.UEContextModificationRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateUEContextModificationRequestBudget(v, budget)
	}, encode: func(v *s58.UEContextModificationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s58.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s58.UEContextModificationRequest, error) {
		var v s58.UEContextModificationRequest
		err := s58.BridgeUEContextModificationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s58.UEContextModificationRequest{}, err
		}
		*s58.BridgeUEContextModificationRequestFieldReceived(&v) = true
		*s58.BridgeUEContextModificationRequestFieldReceivedAbsolute(&v) = true
		*s58.BridgeUEContextModificationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s58.UEContextModificationRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(21)
			*s65.BridgeInitiatingValueFieldBodyUEContextModificationRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s58.UEContextModificationRequest, options aper.DecodeState) (s58.UEContextModificationRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s58.BridgeCaptureS1APUEContextModificationRequest(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s58.UEContextModificationRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s58.BridgeCompareS1APUEContextModificationRequest(&v, &s)
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
func (UEContextModificationDescriptor) Successful() s64.UEContextModificationResponseSuccessfulBinding {
	return func() s64.UEContextModificationResponseSuccessfulBinding {
		sealed := s64.UEContextModificationResponseSuccessfulBinding{}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s46.UEContextModificationResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextModificationResponseBudget(v, budget)
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s46.UEContextModificationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextModificationResponse, error) {
			var v s46.UEContextModificationResponse
			err := s46.BridgeUEContextModificationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UEContextModificationResponse{}, err
			}
			*s46.BridgeUEContextModificationResponseFieldReceived(&v) = true
			*s46.BridgeUEContextModificationResponseFieldReceivedAbsolute(&v) = true
			*s46.BridgeUEContextModificationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldInject(&sealed) = func(v s46.UEContextModificationResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s64.BridgeSuccessfulValueFieldBodyUEContextModificationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s46.UEContextModificationResponse, options aper.DecodeState) (s46.UEContextModificationResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUEContextModificationResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s46.UEContextModificationResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUEContextModificationResponse(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUEContextModificationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextModificationResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextModificationDescriptor.
func (UEContextModificationDescriptor) Unsuccessful() s46.UEContextModificationFailureUnsuccessfulBinding {
	return func() s46.UEContextModificationFailureUnsuccessfulBinding {
		sealed := s46.UEContextModificationFailureUnsuccessfulBinding{}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextModificationProcedure().Info()
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s45.UEContextModificationFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextModificationFailureBudget(v, budget)
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s45.UEContextModificationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s45.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextModificationFailure, error) {
			var v s45.UEContextModificationFailure
			err := s45.BridgeUEContextModificationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s45.UEContextModificationFailure{}, err
			}
			*s45.BridgeUEContextModificationFailureFieldReceived(&v) = true
			*s45.BridgeUEContextModificationFailureFieldReceivedAbsolute(&v) = true
			*s45.BridgeUEContextModificationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s45.UEContextModificationFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s46.BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s45.UEContextModificationFailure, options aper.DecodeState) (s45.UEContextModificationFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEContextModificationFailure(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s45.UEContextModificationFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEContextModificationFailure(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UECapabilityInfoIndicationInitiatingBinding{info: UECapabilityInfoIndicationProcedure().Info(), validate: func(v *s45.UECapabilityInfoIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUECapabilityInfoIndicationBudget(v, budget)
	}, encode: func(v *s45.UECapabilityInfoIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s45.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s45.UECapabilityInfoIndication, error) {
		var v s45.UECapabilityInfoIndication
		err := s45.BridgeUECapabilityInfoIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s45.UECapabilityInfoIndication{}, err
		}
		*s45.BridgeUECapabilityInfoIndicationFieldReceived(&v) = true
		*s45.BridgeUECapabilityInfoIndicationFieldReceivedAbsolute(&v) = true
		*s45.BridgeUECapabilityInfoIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s45.UECapabilityInfoIndication) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(22)
			*s65.BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s45.UECapabilityInfoIndication, options aper.DecodeState) (s45.UECapabilityInfoIndication, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s45.BridgeCaptureS1APUECapabilityInfoIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s45.UECapabilityInfoIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s45.BridgeCompareS1APUECapabilityInfoIndication(&v, &s)
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
	return UEContextReleaseCommandInitiatingBinding{info: UEContextReleaseProcedure().Info(), validate: func(v *s47.UEContextReleaseCommand, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEContextReleaseCommandBudget(v, budget)
	}, encode: func(v *s47.UEContextReleaseCommand, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s47.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s47.UEContextReleaseCommand, error) {
		var v s47.UEContextReleaseCommand
		err := s47.BridgeUEContextReleaseCommandMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s47.UEContextReleaseCommand{}, err
		}
		*s47.BridgeUEContextReleaseCommandFieldReceived(&v) = true
		*s47.BridgeUEContextReleaseCommandFieldReceivedAbsolute(&v) = true
		*s47.BridgeUEContextReleaseCommandFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s47.UEContextReleaseCommand) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(23)
			*s65.BridgeInitiatingValueFieldBodyUEContextReleaseCommand(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s47.UEContextReleaseCommand, options aper.DecodeState) (s47.UEContextReleaseCommand, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s47.BridgeCaptureS1APUEContextReleaseCommand(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s47.UEContextReleaseCommand, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s47.BridgeCompareS1APUEContextReleaseCommand(&v, &s)
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
func (UEContextReleaseDescriptor) Successful() s64.UEContextReleaseCompleteSuccessfulBinding {
	return func() s64.UEContextReleaseCompleteSuccessfulBinding {
		sealed := s64.UEContextReleaseCompleteSuccessfulBinding{}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(&sealed) = UEContextReleaseProcedure().Info()
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(&sealed) = func(v *s57.UEContextReleaseComplete, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextReleaseCompleteBudget(v, budget)
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(&sealed) = func(v *s57.UEContextReleaseComplete, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s57.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s57.UEContextReleaseComplete, error) {
			var v s57.UEContextReleaseComplete
			err := s57.BridgeUEContextReleaseCompleteMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s57.UEContextReleaseComplete{}, err
			}
			*s57.BridgeUEContextReleaseCompleteFieldReceived(&v) = true
			*s57.BridgeUEContextReleaseCompleteFieldReceivedAbsolute(&v) = true
			*s57.BridgeUEContextReleaseCompleteFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(&sealed) = func(v s57.UEContextReleaseComplete) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s64.BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(&sealed) = func(v s57.UEContextReleaseComplete, options aper.DecodeState) (s57.UEContextReleaseComplete, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeCaptureS1APUEContextReleaseComplete(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(&sealed) = func(v s57.UEContextReleaseComplete, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APUEContextReleaseComplete(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return TraceStartInitiatingBinding{info: TraceStartProcedure().Info(), validate: func(v *s61.TraceStart, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateTraceStartBudget(v, budget)
	}, encode: func(v *s61.TraceStart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s61.BridgeTraceStartMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s61.TraceStart, error) {
		var v s61.TraceStart
		err := s61.BridgeTraceStartMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s61.TraceStart{}, err
		}
		*s61.BridgeTraceStartFieldReceived(&v) = true
		*s61.BridgeTraceStartFieldReceivedAbsolute(&v) = true
		*s61.BridgeTraceStartFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s61.TraceStart) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(27)
			*s65.BridgeInitiatingValueFieldBodyTraceStart(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s61.TraceStart, options aper.DecodeState) (s61.TraceStart, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s61.BridgeCaptureS1APTraceStart(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v s61.TraceStart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s61.BridgeCompareS1APTraceStart(&v,
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
	return TraceFailureIndicationInitiatingBinding{info: TraceFailureIndicationProcedure().Info(), validate: func(v *s44.TraceFailureIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateTraceFailureIndicationBudget(v, budget)
	}, encode: func(v *s44.TraceFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s44.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s44.TraceFailureIndication, error) {
		var v s44.TraceFailureIndication
		err := s44.BridgeTraceFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s44.TraceFailureIndication{}, err
		}
		*s44.BridgeTraceFailureIndicationFieldReceived(&v) = true
		*s44.BridgeTraceFailureIndicationFieldReceivedAbsolute(&v) = true
		*s44.BridgeTraceFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s44.TraceFailureIndication) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(28)
			*s65.BridgeInitiatingValueFieldBodyTraceFailureIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s44.TraceFailureIndication, options aper.DecodeState) (s44.TraceFailureIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s44.BridgeCaptureS1APTraceFailureIndication(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s44.TraceFailureIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s44.BridgeCompareS1APTraceFailureIndication(&v, &s)
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

// Initiating returns the typed binding for the initiating message of OverloadStartDescriptor.
func (OverloadStartDescriptor) Initiating() OverloadStartInitiatingBinding {
	return OverloadStartInitiatingBinding{info: OverloadStartProcedure().Info(), validate: func(v *s52.OverloadStart, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateOverloadStartBudget(v, budget)
	}, encode: func(v *s52.OverloadStart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s52.BridgeOverloadStartMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s52.OverloadStart, error) {
		var v s52.OverloadStart
		err := s52.BridgeOverloadStartMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s52.OverloadStart{}, err
		}
		*s52.BridgeOverloadStartFieldReceived(&v) = true
		*s52.BridgeOverloadStartFieldReceivedAbsolute(&v) = true
		*s52.BridgeOverloadStartFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s52.OverloadStart) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(34)
			*s65.BridgeInitiatingValueFieldBodyOverloadStart(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s52.OverloadStart, options aper.DecodeState) (s52.OverloadStart, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s52.BridgeCaptureS1APOverloadStart(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s52.OverloadStart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s52.BridgeCompareS1APOverloadStart(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OverloadStart"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of OverloadStopDescriptor.
func (OverloadStopDescriptor) Initiating() OverloadStopInitiatingBinding {
	return OverloadStopInitiatingBinding{info: OverloadStopProcedure().Info(), validate: func(v *s52.OverloadStop, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateOverloadStopBudget(v, budget)
	}, encode: func(v *s52.OverloadStop, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s52.BridgeOverloadStopMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s52.OverloadStop, error) {
		var v s52.OverloadStop
		err := s52.BridgeOverloadStopMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s52.OverloadStop{}, err
		}
		*s52.BridgeOverloadStopFieldReceived(&v) = true
		*s52.BridgeOverloadStopFieldReceivedAbsolute(&v) = true
		*s52.BridgeOverloadStopFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s52.OverloadStop) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(35)
			*s65.BridgeInitiatingValueFieldBodyOverloadStop(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s52.OverloadStop, options aper.DecodeState) (s52.OverloadStop, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s52.BridgeCaptureS1APOverloadStop(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v s52.OverloadStop, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s52.BridgeCompareS1APOverloadStop(
			&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OverloadStop"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of WriteReplaceWarningDescriptor.
func (WriteReplaceWarningDescriptor) Initiating() WriteReplaceWarningRequestInitiatingBinding {
	return WriteReplaceWarningRequestInitiatingBinding{info: WriteReplaceWarningProcedure().Info(), validate: func(v *s64.WriteReplaceWarningRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s64.BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	}, encode: func(v *s64.WriteReplaceWarningRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s64.BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s64.WriteReplaceWarningRequest, error) {
		var v s64.WriteReplaceWarningRequest
		err := s64.BridgeWriteReplaceWarningRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s64.WriteReplaceWarningRequest{}, err
		}
		*s64.BridgeWriteReplaceWarningRequestFieldReceived(&v) = true
		*s64.BridgeWriteReplaceWarningRequestFieldReceivedAbsolute(&v) = true
		*s64.BridgeWriteReplaceWarningRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s64.WriteReplaceWarningRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(36)
			*s65.BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s64.WriteReplaceWarningRequest, options aper.DecodeState) (s64.WriteReplaceWarningRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s64.BridgeCaptureS1APWriteReplaceWarningRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s64.WriteReplaceWarningRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s64.BridgeCompareS1APWriteReplaceWarningRequest(&v, &s)
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
func (WriteReplaceWarningDescriptor) Successful() s64.WriteReplaceWarningResponseSuccessfulBinding {
	return func() s64.WriteReplaceWarningResponseSuccessfulBinding {
		sealed := s64.WriteReplaceWarningResponseSuccessfulBinding{}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInfo(&sealed) = WriteReplaceWarningProcedure().Info()
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s64.WriteReplaceWarningResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s64.BridgeValidateWriteReplaceWarningResponseBudget(v, budget)
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s64.WriteReplaceWarningResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s64.BridgeWriteReplaceWarningResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.WriteReplaceWarningResponse, error) {
			var v s64.WriteReplaceWarningResponse
			err := s64.BridgeWriteReplaceWarningResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s64.WriteReplaceWarningResponse{}, err
			}
			*s64.BridgeWriteReplaceWarningResponseFieldReceived(&v) = true
			*s64.BridgeWriteReplaceWarningResponseFieldReceivedAbsolute(&v) = true
			*s64.BridgeWriteReplaceWarningResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInject(&sealed) = func(v s64.WriteReplaceWarningResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s64.BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCapture(&sealed) = func(v s64.WriteReplaceWarningResponse, options aper.DecodeState) (s64.WriteReplaceWarningResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s64.BridgeCaptureS1APWriteReplaceWarningResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCompare(&sealed) = func(v s64.WriteReplaceWarningResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s64.BridgeCompareS1APWriteReplaceWarningResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeWriteReplaceWarningResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return PrivateMessageInitiatingBinding{info: PrivateMessageProcedure().Info(), validate: func(v *s30.PrivateMessage, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s58.BridgeValidatePrivateMessageBudget(v, budget)
	}, encode: func(v *s30.PrivateMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s30.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s30.PrivateMessage, error) {
		var v s30.PrivateMessage
		err := s30.BridgePrivateMessageMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s30.PrivateMessage{}, err
		}
		*s30.BridgePrivateMessageFieldReceived(&v) = true
		*s30.BridgePrivateMessageFieldReceivedAbsolute(&v) = true
		*s30.BridgePrivateMessageFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s30.PrivateMessage) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(39)
			*s65.BridgeInitiatingValueFieldBodyPrivateMessage(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s30.PrivateMessage, options aper.DecodeState) (s30.PrivateMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s30.BridgeCaptureS1APPrivateMessage(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s30.PrivateMessage, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s30.BridgeCompareS1APPrivateMessage(&v, &s)
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
func (ENBConfigurationTransferDescriptor) Initiating() s65.ENBConfigurationTransferInitiatingBinding {
	return func() s65.ENBConfigurationTransferInitiatingBinding {
		sealed := s65.ENBConfigurationTransferInitiatingBinding{}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldInfo(&sealed) = ENBConfigurationTransferProcedure().Info()
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s65.ENBConfigurationTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return BridgeValidateENBConfigurationTransferBudget(v, budget)
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s65.ENBConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s65.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s65.ENBConfigurationTransfer, error) {
			var v s65.ENBConfigurationTransfer
			err := s65.BridgeENBConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s65.ENBConfigurationTransfer{}, err
			}
			*s65.BridgeENBConfigurationTransferFieldReceived(&v) = true
			*s65.BridgeENBConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s65.BridgeENBConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s65.ENBConfigurationTransfer) s65.InitiatingValue {
			return func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(40)
				*s65.BridgeInitiatingValueFieldBodyENBConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s65.ENBConfigurationTransfer, options aper.DecodeState) (s65.ENBConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s65.BridgeCaptureS1APENBConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s65.ENBConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s65.BridgeCompareS1APENBConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s65.BridgeENBConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBConfigurationTransfer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of MMEConfigurationTransferDescriptor.
func (MMEConfigurationTransferDescriptor) Initiating() s65.MMEConfigurationTransferInitiatingBinding {
	return func() s65.MMEConfigurationTransferInitiatingBinding {
		sealed := s65.MMEConfigurationTransferInitiatingBinding{}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldInfo(&sealed) = MMEConfigurationTransferProcedure().Info()
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldValidate(&sealed) = func(v *s65.MMEConfigurationTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return BridgeValidateMMEConfigurationTransferBudget(v, budget)
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldEncode(&sealed) = func(v *s65.MMEConfigurationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s65.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s65.MMEConfigurationTransfer, error) {
			var v s65.MMEConfigurationTransfer
			err := s65.BridgeMMEConfigurationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s65.MMEConfigurationTransfer{}, err
			}
			*s65.BridgeMMEConfigurationTransferFieldReceived(&v) = true
			*s65.BridgeMMEConfigurationTransferFieldReceivedAbsolute(&v) = true
			*s65.BridgeMMEConfigurationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldInject(&sealed) = func(v s65.MMEConfigurationTransfer) s65.InitiatingValue {
			return func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(41)
				*s65.BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(&sealed) = &v
				return sealed
			}()
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldCapture(&sealed) = func(v s65.MMEConfigurationTransfer, options aper.DecodeState) (s65.MMEConfigurationTransfer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s65.BridgeCaptureS1APMMEConfigurationTransfer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldCompare(&sealed) = func(v s65.MMEConfigurationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s65.BridgeCompareS1APMMEConfigurationTransfer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s65.BridgeMMEConfigurationTransferInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UplinkUEAssociatedLPPaTransportInitiatingBinding{info: UplinkUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s55.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s55.UplinkUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s55.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s55.UplinkUEAssociatedLPPaTransport, error) {
		var v s55.UplinkUEAssociatedLPPaTransport
		err := s55.BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s55.UplinkUEAssociatedLPPaTransport{}, err
		}
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s55.BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s55.UplinkUEAssociatedLPPaTransport) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(45)
			*s65.BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s55.UplinkUEAssociatedLPPaTransport, options aper.DecodeState) (s55.UplinkUEAssociatedLPPaTransport, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s55.BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s55.UplinkUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s55.BridgeCompareS1APUplinkUEAssociatedLPPaTransport(&v, &s)
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
	return UplinkNonUEAssociatedLPPaTransportInitiatingBinding{info: UplinkNonUEAssociatedLPPaTransportProcedure().Info(), validate: func(v *s55.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	}, encode: func(v *s55.UplinkNonUEAssociatedLPPaTransport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s55.UplinkNonUEAssociatedLPPaTransport, error) {
		var v s55.UplinkNonUEAssociatedLPPaTransport
		err := s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s55.UplinkNonUEAssociatedLPPaTransport{}, err
		}
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(&v) = true
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(&v) = true
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s55.UplinkNonUEAssociatedLPPaTransport) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(47)
			*s65.BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s55.UplinkNonUEAssociatedLPPaTransport, options aper.DecodeState) (s55.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s55.BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s55.UplinkNonUEAssociatedLPPaTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s55.BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(&v, &s)
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
	return UERadioCapabilityMatchRequestInitiatingBinding{info: UERadioCapabilityMatchProcedure().Info(), validate: func(v *s46.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	}, encode: func(v *s46.UERadioCapabilityMatchRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UERadioCapabilityMatchRequest, error) {
		var v s46.UERadioCapabilityMatchRequest
		err := s46.BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UERadioCapabilityMatchRequest{}, err
		}
		*s46.BridgeUERadioCapabilityMatchRequestFieldReceived(&v) = true
		*s46.BridgeUERadioCapabilityMatchRequestFieldReceivedAbsolute(&v) = true
		*s46.BridgeUERadioCapabilityMatchRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UERadioCapabilityMatchRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(48)
			*s65.BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UERadioCapabilityMatchRequest, options aper.DecodeState) (s46.UERadioCapabilityMatchRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUERadioCapabilityMatchRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s46.UERadioCapabilityMatchRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUERadioCapabilityMatchRequest(&v, &s)
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
func (UERadioCapabilityMatchDescriptor) Successful() s64.UERadioCapabilityMatchResponseSuccessfulBinding {
	return func() s64.UERadioCapabilityMatchResponseSuccessfulBinding {
		sealed := s64.UERadioCapabilityMatchResponseSuccessfulBinding{}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityMatchProcedure().Info()
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s46.UERadioCapabilityMatchResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUERadioCapabilityMatchResponseBudget(v, budget)
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s46.UERadioCapabilityMatchResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UERadioCapabilityMatchResponse, error) {
			var v s46.UERadioCapabilityMatchResponse
			err := s46.BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UERadioCapabilityMatchResponse{}, err
			}
			*s46.BridgeUERadioCapabilityMatchResponseFieldReceived(&v) = true
			*s46.BridgeUERadioCapabilityMatchResponseFieldReceivedAbsolute(&v) = true
			*s46.BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInject(&sealed) = func(v s46.UERadioCapabilityMatchResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s64.BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCapture(&sealed) = func(v s46.UERadioCapabilityMatchResponse, options aper.DecodeState) (s46.UERadioCapabilityMatchResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUERadioCapabilityMatchResponse(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCompare(&sealed) = func(v s46.UERadioCapabilityMatchResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUERadioCapabilityMatchResponse(&v, &s)
			s.End(f,
				root,
				false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityMatchResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the typed binding for the initiating message of PWSRestartIndicationDescriptor.
func (PWSRestartIndicationDescriptor) Initiating() PWSRestartIndicationInitiatingBinding {
	return PWSRestartIndicationInitiatingBinding{info: PWSRestartIndicationProcedure().Info(), validate: func(v *s55.PWSRestartIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidatePWSRestartIndicationBudget(v, budget)
	}, encode: func(v *s55.PWSRestartIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s55.BridgePWSRestartIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s55.PWSRestartIndication, error) {
		var v s55.PWSRestartIndication
		err := s55.BridgePWSRestartIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s55.PWSRestartIndication{}, err
		}
		*s55.BridgePWSRestartIndicationFieldReceived(&v) = true
		*s55.BridgePWSRestartIndicationFieldReceivedAbsolute(&v) = true
		*s55.BridgePWSRestartIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s55.PWSRestartIndication) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(49)
			*s65.BridgeInitiatingValueFieldBodyPWSRestartIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s55.PWSRestartIndication, options aper.DecodeState) (s55.PWSRestartIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s55.BridgeCaptureS1APPWSRestartIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v s55.PWSRestartIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s55.BridgeCompareS1APPWSRestartIndication(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PWSRestartIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of PWSFailureIndicationDescriptor.
func (PWSFailureIndicationDescriptor) Initiating() PWSFailureIndicationInitiatingBinding {
	return PWSFailureIndicationInitiatingBinding{info: PWSFailureIndicationProcedure().Info(), validate: func(v *s52.PWSFailureIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidatePWSFailureIndicationBudget(v, budget)
	}, encode: func(v *s52.PWSFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s52.BridgePWSFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s52.PWSFailureIndication, error) {
		var v s52.PWSFailureIndication
		err := s52.BridgePWSFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s52.PWSFailureIndication{}, err
		}
		*s52.BridgePWSFailureIndicationFieldReceived(&v) = true
		*s52.BridgePWSFailureIndicationFieldReceivedAbsolute(&v) = true
		*s52.BridgePWSFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s52.PWSFailureIndication) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(51)
			*s65.BridgeInitiatingValueFieldBodyPWSFailureIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s52.PWSFailureIndication, options aper.DecodeState) (s52.PWSFailureIndication, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s52.BridgeCaptureS1APPWSFailureIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v s52.PWSFailureIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s52.BridgeCompareS1APPWSFailureIndication(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PWSFailureIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// Initiating returns the typed binding for the initiating message of RerouteNASRequestDescriptor.
func (RerouteNASRequestDescriptor) Initiating() RerouteNASRequestInitiatingBinding {
	return RerouteNASRequestInitiatingBinding{info: RerouteNASRequestProcedure().Info(), validate: func(v *s31.RerouteNASRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateRerouteNASRequestBudget(v, budget)
	}, encode: func(v *s31.RerouteNASRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s31.BridgeRerouteNASRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s31.RerouteNASRequest, error) {
		var v s31.RerouteNASRequest
		err := s31.BridgeRerouteNASRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s31.RerouteNASRequest{}, err
		}
		*s31.BridgeRerouteNASRequestFieldReceived(&v) = true
		*s31.BridgeRerouteNASRequestFieldReceivedAbsolute(&v) = true
		*s31.BridgeRerouteNASRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s31.RerouteNASRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(52)
			*s65.BridgeInitiatingValueFieldBodyRerouteNASRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s31.RerouteNASRequest, options aper.DecodeState) (s31.RerouteNASRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s31.BridgeCaptureS1APRerouteNASRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s31.RerouteNASRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s31.BridgeCompareS1APRerouteNASRequest(&v, &s)
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
	return UEContextModificationIndicationInitiatingBinding{info: UEContextModificationIndicationProcedure().Info(), validate: func(v *s46.UEContextModificationIndication, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEContextModificationIndicationBudget(v, budget)
	}, encode: func(v *s46.UEContextModificationIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UEContextModificationIndication, error) {
		var v s46.UEContextModificationIndication
		err := s46.BridgeUEContextModificationIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UEContextModificationIndication{}, err
		}
		*s46.BridgeUEContextModificationIndicationFieldReceived(&v) = true
		*s46.BridgeUEContextModificationIndicationFieldReceivedAbsolute(&v) = true
		*s46.BridgeUEContextModificationIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UEContextModificationIndication) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(53)
			*s65.BridgeInitiatingValueFieldBodyUEContextModificationIndication(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UEContextModificationIndication, options aper.DecodeState) (s46.UEContextModificationIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUEContextModificationIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s46.UEContextModificationIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUEContextModificationIndication(&v, &s)
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
func (UEContextModificationIndicationDescriptor) Successful() s64.UEContextModificationConfirmSuccessfulBinding {
	return func() s64.UEContextModificationConfirmSuccessfulBinding {
		sealed := s64.UEContextModificationConfirmSuccessfulBinding{}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldInfo(&sealed) = UEContextModificationIndicationProcedure().Info()
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldValidate(&sealed) = func(v *s45.UEContextModificationConfirm, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextModificationConfirmBudget(v, budget)
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldEncode(&sealed) = func(v *s45.UEContextModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s45.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextModificationConfirm, error) {
			var v s45.UEContextModificationConfirm
			err := s45.BridgeUEContextModificationConfirmMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s45.UEContextModificationConfirm{}, err
			}
			*s45.BridgeUEContextModificationConfirmFieldReceived(&v) = true
			*s45.BridgeUEContextModificationConfirmFieldReceivedAbsolute(&v) = true
			*s45.BridgeUEContextModificationConfirmFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldInject(&sealed) = func(v s45.UEContextModificationConfirm) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s64.BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldCapture(&sealed) = func(v s45.UEContextModificationConfirm, options aper.DecodeState) (s45.UEContextModificationConfirm, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEContextModificationConfirm(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldCompare(&sealed) = func(v s45.UEContextModificationConfirm, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEContextModificationConfirm(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUEContextModificationConfirmSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextSuspendRequestInitiatingBinding{info: UEContextSuspendProcedure().Info(), validate: func(v *s57.UEContextSuspendRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEContextSuspendRequestBudget(v, budget)
	}, encode: func(v *s57.UEContextSuspendRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s57.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s57.UEContextSuspendRequest, error) {
		var v s57.UEContextSuspendRequest
		err := s57.BridgeUEContextSuspendRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s57.UEContextSuspendRequest{}, err
		}
		*s57.BridgeUEContextSuspendRequestFieldReceived(&v) = true
		*s57.BridgeUEContextSuspendRequestFieldReceivedAbsolute(&v) = true
		*s57.BridgeUEContextSuspendRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s57.UEContextSuspendRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(55)
			*s65.BridgeInitiatingValueFieldBodyUEContextSuspendRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s57.UEContextSuspendRequest, options aper.DecodeState) (s57.UEContextSuspendRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s57.BridgeCaptureS1APUEContextSuspendRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s57.UEContextSuspendRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s57.BridgeCompareS1APUEContextSuspendRequest(&v, &s)
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
func (UEContextSuspendDescriptor) Successful() s64.UEContextSuspendResponseSuccessfulBinding {
	return func() s64.UEContextSuspendResponseSuccessfulBinding {
		sealed := s64.UEContextSuspendResponseSuccessfulBinding{}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(&sealed) = UEContextSuspendProcedure().Info()
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s46.UEContextSuspendResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextSuspendResponseBudget(v, budget)
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s46.UEContextSuspendResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextSuspendResponse, error) {
			var v s46.UEContextSuspendResponse
			err := s46.BridgeUEContextSuspendResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UEContextSuspendResponse{}, err
			}
			*s46.BridgeUEContextSuspendResponseFieldReceived(&v) = true
			*s46.BridgeUEContextSuspendResponseFieldReceivedAbsolute(&v) = true
			*s46.BridgeUEContextSuspendResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(&sealed) = func(v s46.UEContextSuspendResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s64.BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(&sealed) = func(v s46.UEContextSuspendResponse, options aper.DecodeState) (s46.UEContextSuspendResponse, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUEContextSuspendResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(&sealed) = func(v s46.UEContextSuspendResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUEContextSuspendResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return UEContextResumeRequestInitiatingBinding{info: UEContextResumeProcedure().Info(), validate: func(v *s48.UEContextResumeRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEContextResumeRequestBudget(v, budget)
	}, encode: func(v *s48.UEContextResumeRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s48.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s48.UEContextResumeRequest, error) {
		var v s48.UEContextResumeRequest
		err := s48.BridgeUEContextResumeRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s48.UEContextResumeRequest{}, err
		}
		*s48.BridgeUEContextResumeRequestFieldReceived(&v) = true
		*s48.BridgeUEContextResumeRequestFieldReceivedAbsolute(&v) = true
		*s48.BridgeUEContextResumeRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s48.UEContextResumeRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(56)
			*s65.BridgeInitiatingValueFieldBodyUEContextResumeRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s48.UEContextResumeRequest, options aper.DecodeState) (s48.UEContextResumeRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s48.BridgeCaptureS1APUEContextResumeRequest(
			&v,

			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s48.UEContextResumeRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s48.BridgeCompareS1APUEContextResumeRequest(&v, &s)
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
func (UEContextResumeDescriptor) Successful() s64.UEContextResumeResponseSuccessfulBinding {
	return func() s64.UEContextResumeResponseSuccessfulBinding {
		sealed := s64.UEContextResumeResponseSuccessfulBinding{}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s49.UEContextResumeResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextResumeResponseBudget(v, budget)
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s49.UEContextResumeResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s49.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s49.UEContextResumeResponse, error) {
			var v s49.UEContextResumeResponse
			err := s49.BridgeUEContextResumeResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s49.UEContextResumeResponse{}, err
			}
			*s49.BridgeUEContextResumeResponseFieldReceived(&v) = true
			*s49.BridgeUEContextResumeResponseFieldReceivedAbsolute(&v) = true
			*s49.BridgeUEContextResumeResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldInject(&sealed) = func(v s49.UEContextResumeResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s64.BridgeSuccessfulValueFieldBodyUEContextResumeResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(&sealed) = func(v s49.UEContextResumeResponse, options aper.DecodeState) (s49.UEContextResumeResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s49.BridgeCaptureS1APUEContextResumeResponse(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(&sealed) = func(v s49.UEContextResumeResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s49.BridgeCompareS1APUEContextResumeResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUEContextResumeResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEContextResumeResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of UEContextResumeDescriptor.
func (UEContextResumeDescriptor) Unsuccessful() s46.UEContextResumeFailureUnsuccessfulBinding {
	return func() s46.UEContextResumeFailureUnsuccessfulBinding {
		sealed := s46.UEContextResumeFailureUnsuccessfulBinding{}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInfo(&sealed) = UEContextResumeProcedure().Info()
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s46.UEContextResumeFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUEContextResumeFailureBudget(v, budget)
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s46.UEContextResumeFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextResumeFailure, error) {
			var v s46.UEContextResumeFailure
			err := s46.BridgeUEContextResumeFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UEContextResumeFailure{}, err
			}
			*s46.BridgeUEContextResumeFailureFieldReceived(&v) = true
			*s46.BridgeUEContextResumeFailureFieldReceivedAbsolute(&v) = true
			*s46.BridgeUEContextResumeFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s46.UEContextResumeFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s46.BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s46.UEContextResumeFailure, options aper.DecodeState) (s46.UEContextResumeFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUEContextResumeFailure(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s46.UEContextResumeFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUEContextResumeFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextResumeFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return RetrieveUEInformationInitiatingBinding{info: RetrieveUEInformationProcedure().Info(), validate: func(v *s36.RetrieveUEInformation, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateRetrieveUEInformationBudget(v, budget)
	}, encode: func(v *s36.RetrieveUEInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s36.BridgeRetrieveUEInformationMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s36.RetrieveUEInformation, error) {
		var v s36.RetrieveUEInformation
		err := s36.BridgeRetrieveUEInformationMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s36.RetrieveUEInformation{}, err
		}
		*s36.BridgeRetrieveUEInformationFieldReceived(&v) = true
		*s36.BridgeRetrieveUEInformationFieldReceivedAbsolute(&v) = true
		*s36.BridgeRetrieveUEInformationFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s36.RetrieveUEInformation) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(58)
			*s65.BridgeInitiatingValueFieldBodyRetrieveUEInformation(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s36.RetrieveUEInformation, options aper.DecodeState) (s36.RetrieveUEInformation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s36.BridgeCaptureS1APRetrieveUEInformation(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s36.RetrieveUEInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s36.BridgeCompareS1APRetrieveUEInformation(&v, &s)
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
	return UEInformationTransferInitiatingBinding{info: UEInformationTransferProcedure().Info(), validate: func(v *s46.UEInformationTransfer, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUEInformationTransferBudget(v, budget)
	}, encode: func(v *s46.UEInformationTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UEInformationTransfer, error) {
		var v s46.UEInformationTransfer
		err := s46.BridgeUEInformationTransferMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UEInformationTransfer{}, err
		}
		*s46.BridgeUEInformationTransferFieldReceived(&v) = true
		*s46.BridgeUEInformationTransferFieldReceivedAbsolute(&v) = true
		*s46.BridgeUEInformationTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UEInformationTransfer) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(59)
			*s65.BridgeInitiatingValueFieldBodyUEInformationTransfer(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UEInformationTransfer, options aper.DecodeState) (s46.UEInformationTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUEInformationTransfer(&v,
			&s,
		)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s46.UEInformationTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUEInformationTransfer(&v, &s)
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
	return SecondaryRATDataUsageReportInitiatingBinding{info: SecondaryRATDataUsageReportProcedure().Info(), validate: func(v *s57.SecondaryRATDataUsageReport, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	}, encode: func(v *s57.SecondaryRATDataUsageReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s57.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s57.SecondaryRATDataUsageReport, error) {
		var v s57.SecondaryRATDataUsageReport
		err := s57.BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s57.SecondaryRATDataUsageReport{}, err
		}
		*s57.BridgeSecondaryRATDataUsageReportFieldReceived(&v) = true
		*s57.BridgeSecondaryRATDataUsageReportFieldReceivedAbsolute(&v) = true
		*s57.BridgeSecondaryRATDataUsageReportFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s57.SecondaryRATDataUsageReport) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(62)
			*s65.BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s57.SecondaryRATDataUsageReport, options aper.DecodeState) (s57.SecondaryRATDataUsageReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s57.BridgeCaptureS1APSecondaryRATDataUsageReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v s57.SecondaryRATDataUsageReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s57.BridgeCompareS1APSecondaryRATDataUsageReport(&v, &s)
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
	return UERadioCapabilityIDMappingRequestInitiatingBinding{info: UERadioCapabilityIDMappingProcedure().Info(), validate: func(v *s46.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s63.BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	}, encode: func(v *s46.UERadioCapabilityIDMappingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s46.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s46.UERadioCapabilityIDMappingRequest, error) {
		var v s46.UERadioCapabilityIDMappingRequest
		err := s46.BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s46.UERadioCapabilityIDMappingRequest{}, err
		}
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldReceived(&v) = true
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldReceivedAbsolute(&v) = true
		*s46.BridgeUERadioCapabilityIDMappingRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s46.UERadioCapabilityIDMappingRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(63)
			*s65.BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s46.UERadioCapabilityIDMappingRequest, options aper.DecodeState) (s46.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s46.BridgeCaptureS1APUERadioCapabilityIDMappingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s46.UERadioCapabilityIDMappingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s46.BridgeCompareS1APUERadioCapabilityIDMappingRequest(&v, &s)
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
func (UERadioCapabilityIDMappingDescriptor) Successful() s64.UERadioCapabilityIDMappingResponseSuccessfulBinding {
	return func() s64.UERadioCapabilityIDMappingResponseSuccessfulBinding {
		sealed := s64.UERadioCapabilityIDMappingResponseSuccessfulBinding{}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(&sealed) = UERadioCapabilityIDMappingProcedure().Info()
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s46.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s63.BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s46.UERadioCapabilityIDMappingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s46.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UERadioCapabilityIDMappingResponse, error) {
			var v s46.UERadioCapabilityIDMappingResponse
			err := s46.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s46.UERadioCapabilityIDMappingResponse{}, err
			}
			*s46.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&v) = true
			*s46.BridgeUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(&v) = true
			*s46.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(&sealed) = func(v s46.UERadioCapabilityIDMappingResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s64.BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(&sealed) = func(v s46.UERadioCapabilityIDMappingResponse, options aper.DecodeState) (s46.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(&sealed) = func(v s46.UERadioCapabilityIDMappingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s46.BridgeCompareS1APUERadioCapabilityIDMappingResponse(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return S1RemovalRequestInitiatingBinding{info: S1RemovalProcedure().Info(), validate: func(v *s31.S1RemovalRequest, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
		return s62.BridgeValidateS1RemovalRequestBudget(v, budget)
	}, encode: func(v *s31.S1RemovalRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s31.BridgeS1RemovalRequestMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s31.S1RemovalRequest, error) {
		var v s31.S1RemovalRequest
		err := s31.BridgeS1RemovalRequestMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s31.S1RemovalRequest{}, err
		}
		*s31.BridgeS1RemovalRequestFieldReceived(&v) = true
		*s31.BridgeS1RemovalRequestFieldReceivedAbsolute(&v) = true
		*s31.BridgeS1RemovalRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s31.S1RemovalRequest) s65.InitiatingValue {
		return func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(67)
			*s65.BridgeInitiatingValueFieldBodyS1RemovalRequest(&sealed) = &v
			return sealed
		}()
	}, capture: func(v s31.S1RemovalRequest, options aper.DecodeState) (s31.S1RemovalRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s31.BridgeCaptureS1APS1RemovalRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s31.S1RemovalRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s31.BridgeCompareS1APS1RemovalRequest(&v, &s)
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
func (S1RemovalDescriptor) Successful() s64.S1RemovalResponseSuccessfulBinding {
	return func() s64.S1RemovalResponseSuccessfulBinding {
		sealed := s64.S1RemovalResponseSuccessfulBinding{}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s31.S1RemovalResponse, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateS1RemovalResponseBudget(v, budget)
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s31.S1RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s31.BridgeS1RemovalResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.S1RemovalResponse, error) {
			var v s31.S1RemovalResponse
			err := s31.BridgeS1RemovalResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s31.S1RemovalResponse{}, err
			}
			*s31.BridgeS1RemovalResponseFieldReceived(&v) = true
			*s31.BridgeS1RemovalResponseFieldReceivedAbsolute(&v) = true
			*s31.BridgeS1RemovalResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldInject(&sealed) = func(v s31.S1RemovalResponse) s64.SuccessfulValue {
			return func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s64.BridgeSuccessfulValueFieldBodyS1RemovalResponse(&sealed) = &v
				return sealed
			}()
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldCapture(&sealed) = func(v s31.S1RemovalResponse, options aper.DecodeState) (s31.S1RemovalResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options,
			)
			f := s.Begin()
			s31.BridgeCaptureS1APS1RemovalResponse(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldCompare(&sealed) = func(v s31.S1RemovalResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APS1RemovalResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.BudgetValue()
		}
		*s64.BridgeS1RemovalResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1RemovalResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of S1RemovalDescriptor.
func (S1RemovalDescriptor) Unsuccessful() s46.S1RemovalFailureUnsuccessfulBinding {
	return func() s46.S1RemovalFailureUnsuccessfulBinding {
		sealed := s46.S1RemovalFailureUnsuccessfulBinding{}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(&sealed) = S1RemovalProcedure().Info()
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s31.S1RemovalFailure, budget *aper.DecodeBudget) (s25.ValidationReport, error) {
			return s62.BridgeValidateS1RemovalFailureBudget(v, budget)
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s31.S1RemovalFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s31.BridgeS1RemovalFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.S1RemovalFailure, error) {
			var v s31.S1RemovalFailure
			err := s31.BridgeS1RemovalFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s31.S1RemovalFailure{}, err
			}
			*s31.BridgeS1RemovalFailureFieldReceived(&v) = true
			*s31.BridgeS1RemovalFailureFieldReceivedAbsolute(&v) = true
			*s31.BridgeS1RemovalFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s31.S1RemovalFailure) s46.UnsuccessfulValue {
			return func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s46.BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(&sealed) = &v
				return sealed
			}()
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s31.S1RemovalFailure, options aper.DecodeState) (s31.S1RemovalFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APS1RemovalFailure(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s31.S1RemovalFailure, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APS1RemovalFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s46.BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	capture func(s51.PathSwitchRequest, aper.DecodeState,

	) (s51.PathSwitchRequest, aper.Snapshot,

	)
	compare func(s51.PathSwitchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s51.PathSwitchRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s51.PathSwitchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s51.PathSwitchRequest,

		error)
	inject func(s51.PathSwitchRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestInitiatingBinding) Codec() s51.PathSwitchRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s51.PathSwitchRequestValueCodec{}
	}
	return func() s51.PathSwitchRequestValueCodec {
		sealed := s51.PathSwitchRequestValueCodec{}
		*s51.BridgePathSwitchRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s51.BridgePathSwitchRequestValueCodecFieldDecode(&sealed) = b.decode
		*s51.BridgePathSwitchRequestValueCodecFieldEncode(&sealed) = func(value s51.PathSwitchRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s51.BridgePathSwitchRequestValueCodecFieldCapture(&sealed) = b.capture
		*s51.BridgePathSwitchRequestValueCodecFieldCompare(&sealed) = b.compare
		*s51.BridgePathSwitchRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestInitiatingBinding) Build(body s51.PathSwitchRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PagingInitiatingBinding is the concrete InitiatingBinding[Paging].
type PagingInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s61.Paging, aper.DecodeState,

	) (s61.Paging, aper.Snapshot,

	)
	compare func(s61.Paging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s61.Paging,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s61.Paging,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s61.Paging,

		error)
	inject func(s61.Paging,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PagingInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingInitiatingBinding) Codec() s61.PagingValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s61.PagingValueCodec{}
	}
	return func() s61.PagingValueCodec {
		sealed := s61.PagingValueCodec{}
		*s61.BridgePagingValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s61.BridgePagingValueCodecFieldDecode(&sealed) = b.decode
		*s61.BridgePagingValueCodecFieldEncode(&sealed) = func(value s61.Paging,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s61.BridgePagingValueCodecFieldCapture(&sealed) = b.capture
		*s61.BridgePagingValueCodecFieldCompare(&sealed) = b.compare
		*s61.BridgePagingValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PagingInitiatingBinding) Build(body s61.Paging,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkNASTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNASTransport].
type UplinkNASTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s55.UplinkNASTransport, aper.DecodeState,

	) (s55.UplinkNASTransport, aper.Snapshot,

	)
	compare func(s55.UplinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.UplinkNASTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.UplinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.UplinkNASTransport,

		error)
	inject func(s55.UplinkNASTransport,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNASTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNASTransportInitiatingBinding) Codec() s55.UplinkNASTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.UplinkNASTransportValueCodec{}
	}
	return func() s55.UplinkNASTransportValueCodec {
		sealed := s55.UplinkNASTransportValueCodec{}
		*s55.BridgeUplinkNASTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgeUplinkNASTransportValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgeUplinkNASTransportValueCodecFieldEncode(&sealed) = func(value s55.UplinkNASTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgeUplinkNASTransportValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgeUplinkNASTransportValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgeUplinkNASTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNASTransportInitiatingBinding) Build(body s55.UplinkNASTransport,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ResetInitiatingBinding is the concrete InitiatingBinding[Reset].
type ResetInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.Reset, aper.DecodeState,

	) (s45.Reset, aper.Snapshot,

	)
	compare func(s45.Reset, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.Reset,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s45.Reset,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.Reset,

		error)
	inject func(s45.Reset,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b ResetInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetInitiatingBinding) Codec() s45.ResetValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.ResetValueCodec{}
	}
	return func() s45.ResetValueCodec {
		sealed := s45.ResetValueCodec{}
		*s45.BridgeResetValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeResetValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeResetValueCodecFieldEncode(&sealed) = func(value s45.Reset,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeResetValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeResetValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeResetValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ResetInitiatingBinding) Build(body s45.Reset,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1SetupRequestInitiatingBinding is the concrete InitiatingBinding[S1SetupRequest].
type S1SetupRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s54.S1SetupRequest, aper.DecodeState,

	) (s54.S1SetupRequest, aper.Snapshot,

	)
	compare func(s54.S1SetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s54.S1SetupRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s54.S1SetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s54.S1SetupRequest,

		error)
	inject func(s54.S1SetupRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupRequestInitiatingBinding) Codec() s54.S1SetupRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s54.S1SetupRequestValueCodec{}
	}
	return func() s54.S1SetupRequestValueCodec {
		sealed := s54.S1SetupRequestValueCodec{}
		*s54.BridgeS1SetupRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s54.BridgeS1SetupRequestValueCodecFieldDecode(&sealed) = b.decode
		*s54.BridgeS1SetupRequestValueCodecFieldEncode(&sealed) = func(value s54.S1SetupRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s54.BridgeS1SetupRequestValueCodecFieldCapture(&sealed) = b.capture
		*s54.BridgeS1SetupRequestValueCodecFieldCompare(&sealed) = b.compare
		*s54.BridgeS1SetupRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupRequestInitiatingBinding) Build(body s54.S1SetupRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseRequestInitiatingBinding is the concrete InitiatingBinding[UEContextReleaseRequest].
type UEContextReleaseRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s53.UEContextReleaseRequest, aper.DecodeState,

	) (s53.UEContextReleaseRequest, aper.Snapshot,

	)
	compare func(s53.UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s53.UEContextReleaseRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s53.UEContextReleaseRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s53.UEContextReleaseRequest,

		error)
	inject func(s53.UEContextReleaseRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestInitiatingBinding) Codec() s53.UEContextReleaseRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s53.UEContextReleaseRequestValueCodec{}
	}
	return func() s53.UEContextReleaseRequestValueCodec {
		sealed := s53.UEContextReleaseRequestValueCodec{}
		*s53.BridgeUEContextReleaseRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s53.BridgeUEContextReleaseRequestValueCodecFieldDecode(&sealed) = b.decode
		*s53.BridgeUEContextReleaseRequestValueCodecFieldEncode(&sealed) = func(value s53.UEContextReleaseRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s53.BridgeUEContextReleaseRequestValueCodecFieldCapture(&sealed) = b.capture
		*s53.BridgeUEContextReleaseRequestValueCodecFieldCompare(&sealed) = b.compare
		*s53.BridgeUEContextReleaseRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseRequestInitiatingBinding) Build(body s53.UEContextReleaseRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkS1cdma2000tunnellingInitiatingBinding is the concrete InitiatingBinding[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s55.UplinkS1cdma2000tunnelling, aper.DecodeState,

	) (s55.UplinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(s55.UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.UplinkS1cdma2000tunnelling,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.UplinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.UplinkS1cdma2000tunnelling,

		error)
	inject func(s55.UplinkS1cdma2000tunnelling,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Codec() s55.UplinkS1cdma2000tunnellingValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.UplinkS1cdma2000tunnellingValueCodec{}
	}
	return func() s55.UplinkS1cdma2000tunnellingValueCodec {
		sealed := s55.UplinkS1cdma2000tunnellingValueCodec{}
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldEncode(&sealed) = func(value s55.UplinkS1cdma2000tunnelling,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgeUplinkS1cdma2000tunnellingValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkS1cdma2000tunnellingInitiatingBinding) Build(body s55.UplinkS1cdma2000tunnelling,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationRequestInitiatingBinding is the concrete InitiatingBinding[UEContextModificationRequest].
type UEContextModificationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s58.UEContextModificationRequest, aper.DecodeState,

	) (s58.UEContextModificationRequest, aper.Snapshot,

	)
	compare func(s58.UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s58.UEContextModificationRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s58.UEContextModificationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s58.UEContextModificationRequest,

		error)
	inject func(s58.UEContextModificationRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestInitiatingBinding) Codec() s58.UEContextModificationRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s58.UEContextModificationRequestValueCodec{}
	}
	return func() s58.UEContextModificationRequestValueCodec {
		sealed := s58.UEContextModificationRequestValueCodec{}
		*s58.BridgeUEContextModificationRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s58.BridgeUEContextModificationRequestValueCodecFieldDecode(&sealed) = b.decode
		*s58.BridgeUEContextModificationRequestValueCodecFieldEncode(&sealed) = func(value s58.UEContextModificationRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s58.BridgeUEContextModificationRequestValueCodecFieldCapture(&sealed) = b.capture
		*s58.BridgeUEContextModificationRequestValueCodecFieldCompare(&sealed) = b.compare
		*s58.BridgeUEContextModificationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationRequestInitiatingBinding) Build(body s58.UEContextModificationRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UECapabilityInfoIndicationInitiatingBinding is the concrete InitiatingBinding[UECapabilityInfoIndication].
type UECapabilityInfoIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s45.UECapabilityInfoIndication, aper.DecodeState,

	) (s45.UECapabilityInfoIndication, aper.Snapshot,

	)
	compare func(s45.UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UECapabilityInfoIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s45.UECapabilityInfoIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UECapabilityInfoIndication,

		error)
	inject func(s45.UECapabilityInfoIndication,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UECapabilityInfoIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UECapabilityInfoIndicationInitiatingBinding) Codec() s45.UECapabilityInfoIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UECapabilityInfoIndicationValueCodec{}
	}
	return func() s45.UECapabilityInfoIndicationValueCodec {
		sealed := s45.UECapabilityInfoIndicationValueCodec{}
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldEncode(&sealed) = func(value s45.UECapabilityInfoIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUECapabilityInfoIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UECapabilityInfoIndicationInitiatingBinding) Build(body s45.UECapabilityInfoIndication,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseCommandInitiatingBinding is the concrete InitiatingBinding[UEContextReleaseCommand].
type UEContextReleaseCommandInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.UEContextReleaseCommand, aper.DecodeState,

	) (s47.UEContextReleaseCommand, aper.Snapshot,

	)
	compare func(s47.UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.UEContextReleaseCommand,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s47.UEContextReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.UEContextReleaseCommand,

		error)
	inject func(s47.UEContextReleaseCommand,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandInitiatingBinding) Codec() s47.UEContextReleaseCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.UEContextReleaseCommandValueCodec{}
	}
	return func() s47.UEContextReleaseCommandValueCodec {
		sealed := s47.UEContextReleaseCommandValueCodec{}
		*s47.BridgeUEContextReleaseCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeUEContextReleaseCommandValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeUEContextReleaseCommandValueCodecFieldEncode(&sealed) = func(value s47.UEContextReleaseCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeUEContextReleaseCommandValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeUEContextReleaseCommandValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeUEContextReleaseCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseCommandInitiatingBinding) Build(body s47.UEContextReleaseCommand,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceStartInitiatingBinding is the concrete InitiatingBinding[TraceStart].
type TraceStartInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s61.TraceStart, aper.DecodeState,

	) (s61.TraceStart, aper.Snapshot,

	)
	compare func(s61.TraceStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s61.TraceStart,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s61.TraceStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s61.TraceStart,

		error)
	inject func(s61.TraceStart,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceStartInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartInitiatingBinding) Codec() s61.TraceStartValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s61.TraceStartValueCodec{}
	}
	return func() s61.TraceStartValueCodec {
		sealed := s61.TraceStartValueCodec{}
		*s61.BridgeTraceStartValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s61.BridgeTraceStartValueCodecFieldDecode(&sealed) = b.decode
		*s61.BridgeTraceStartValueCodecFieldEncode(&sealed) = func(value s61.TraceStart,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s61.BridgeTraceStartValueCodecFieldCapture(&sealed) = b.capture
		*s61.BridgeTraceStartValueCodecFieldCompare(&sealed) = b.compare
		*s61.BridgeTraceStartValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceStartInitiatingBinding) Build(body s61.TraceStart,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// TraceFailureIndicationInitiatingBinding is the concrete InitiatingBinding[TraceFailureIndication].
type TraceFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.TraceFailureIndication, aper.DecodeState,

	) (s44.TraceFailureIndication, aper.Snapshot,

	)
	compare func(s44.TraceFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.TraceFailureIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s44.TraceFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.TraceFailureIndication,

		error)
	inject func(s44.TraceFailureIndication,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b TraceFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceFailureIndicationInitiatingBinding) Codec() s44.TraceFailureIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.TraceFailureIndicationValueCodec{}
	}
	return func() s44.TraceFailureIndicationValueCodec {
		sealed := s44.TraceFailureIndicationValueCodec{}
		*s44.BridgeTraceFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeTraceFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeTraceFailureIndicationValueCodecFieldEncode(&sealed) = func(value s44.TraceFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeTraceFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeTraceFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeTraceFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b TraceFailureIndicationInitiatingBinding) Build(body s44.TraceFailureIndication,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// OverloadStartInitiatingBinding is the concrete InitiatingBinding[OverloadStart].
type OverloadStartInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s52.OverloadStart, aper.DecodeState,

	) (s52.OverloadStart, aper.Snapshot,

	)
	compare func(s52.OverloadStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s52.OverloadStart,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s52.OverloadStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s52.OverloadStart,

		error)
	inject func(s52.OverloadStart,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b OverloadStartInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStartInitiatingBinding) Codec() s52.OverloadStartValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.OverloadStartValueCodec{}
	}
	return func() s52.OverloadStartValueCodec {
		sealed := s52.OverloadStartValueCodec{}
		*s52.BridgeOverloadStartValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s52.BridgeOverloadStartValueCodecFieldDecode(&sealed) = b.decode
		*s52.BridgeOverloadStartValueCodecFieldEncode(&sealed) = func(value s52.OverloadStart,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s52.BridgeOverloadStartValueCodecFieldCapture(&sealed) = b.capture
		*s52.BridgeOverloadStartValueCodecFieldCompare(&sealed) = b.compare
		*s52.BridgeOverloadStartValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b OverloadStartInitiatingBinding) Build(body s52.OverloadStart,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// OverloadStopInitiatingBinding is the concrete InitiatingBinding[OverloadStop].
type OverloadStopInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s52.OverloadStop, aper.DecodeState,

	) (s52.OverloadStop, aper.Snapshot,

	)
	compare func(s52.OverloadStop, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s52.OverloadStop,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s52.OverloadStop,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s52.OverloadStop,

		error)
	inject func(s52.OverloadStop,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b OverloadStopInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b OverloadStopInitiatingBinding) Codec() s52.OverloadStopValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.OverloadStopValueCodec{}
	}
	return func() s52.OverloadStopValueCodec {
		sealed := s52.OverloadStopValueCodec{}
		*s52.BridgeOverloadStopValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s52.BridgeOverloadStopValueCodecFieldDecode(&sealed) = b.decode
		*s52.BridgeOverloadStopValueCodecFieldEncode(&sealed) = func(value s52.OverloadStop,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s52.BridgeOverloadStopValueCodecFieldCapture(&sealed) = b.capture
		*s52.BridgeOverloadStopValueCodecFieldCompare(&sealed) = b.compare
		*s52.BridgeOverloadStopValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b OverloadStopInitiatingBinding) Build(body s52.OverloadStop,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// WriteReplaceWarningRequestInitiatingBinding is the concrete InitiatingBinding[WriteReplaceWarningRequest].
type WriteReplaceWarningRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s64.WriteReplaceWarningRequest, aper.DecodeState,

	) (s64.WriteReplaceWarningRequest, aper.Snapshot,

	)
	compare func(s64.WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s64.WriteReplaceWarningRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s64.WriteReplaceWarningRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s64.WriteReplaceWarningRequest,

		error)
	inject func(s64.WriteReplaceWarningRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestInitiatingBinding) Codec() s64.WriteReplaceWarningRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s64.WriteReplaceWarningRequestValueCodec{}
	}
	return func() s64.WriteReplaceWarningRequestValueCodec {
		sealed := s64.WriteReplaceWarningRequestValueCodec{}
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldDecode(&sealed) = b.decode
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldEncode(&sealed) = func(value s64.WriteReplaceWarningRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldCapture(&sealed) = b.capture
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldCompare(&sealed) = b.compare
		*s64.BridgeWriteReplaceWarningRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b WriteReplaceWarningRequestInitiatingBinding) Build(body s64.WriteReplaceWarningRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s30.PrivateMessage, aper.DecodeState,

	) (s30.PrivateMessage, aper.Snapshot,

	)
	compare func(s30.PrivateMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.PrivateMessage,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.PrivateMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.PrivateMessage,

		error)
	inject func(s30.PrivateMessage,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PrivateMessageInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PrivateMessageInitiatingBinding) Codec() s30.PrivateMessageValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.PrivateMessageValueCodec{}
	}
	return func() s30.PrivateMessageValueCodec {
		sealed := s30.PrivateMessageValueCodec{}
		*s30.BridgePrivateMessageValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgePrivateMessageValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgePrivateMessageValueCodecFieldEncode(&sealed) = func(value s30.PrivateMessage,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgePrivateMessageValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgePrivateMessageValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgePrivateMessageValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PrivateMessageInitiatingBinding) Build(body s30.PrivateMessage,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s55.UplinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (s55.UplinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s55.UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.UplinkUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.UplinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.UplinkUEAssociatedLPPaTransport,

		error)
	inject func(s55.UplinkUEAssociatedLPPaTransport,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Codec() s55.UplinkUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.UplinkUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s55.UplinkUEAssociatedLPPaTransportValueCodec {
		sealed := s55.UplinkUEAssociatedLPPaTransportValueCodec{}
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s55.UplinkUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkUEAssociatedLPPaTransportInitiatingBinding) Build(body s55.UplinkUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UplinkNonUEAssociatedLPPaTransportInitiatingBinding is the concrete InitiatingBinding[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s55.UplinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (s55.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(s55.UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.UplinkNonUEAssociatedLPPaTransport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.UplinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.UplinkNonUEAssociatedLPPaTransport,

		error)
	inject func(s55.UplinkNonUEAssociatedLPPaTransport,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Codec() s55.UplinkNonUEAssociatedLPPaTransportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.UplinkNonUEAssociatedLPPaTransportValueCodec{}
	}
	return func() s55.UplinkNonUEAssociatedLPPaTransportValueCodec {
		sealed := s55.UplinkNonUEAssociatedLPPaTransportValueCodec{}
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(&sealed) = func(value s55.UplinkNonUEAssociatedLPPaTransport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UplinkNonUEAssociatedLPPaTransportInitiatingBinding) Build(body s55.UplinkNonUEAssociatedLPPaTransport,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityMatchRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityMatchRequest].
type UERadioCapabilityMatchRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UERadioCapabilityMatchRequest, aper.DecodeState,

	) (s46.UERadioCapabilityMatchRequest, aper.Snapshot,

	)
	compare func(s46.UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UERadioCapabilityMatchRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UERadioCapabilityMatchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UERadioCapabilityMatchRequest,

		error)
	inject func(s46.UERadioCapabilityMatchRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Codec() s46.UERadioCapabilityMatchRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UERadioCapabilityMatchRequestValueCodec{}
	}
	return func() s46.UERadioCapabilityMatchRequestValueCodec {
		sealed := s46.UERadioCapabilityMatchRequestValueCodec{}
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldEncode(&sealed) = func(value s46.UERadioCapabilityMatchRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUERadioCapabilityMatchRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityMatchRequestInitiatingBinding) Build(body s46.UERadioCapabilityMatchRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PWSRestartIndicationInitiatingBinding is the concrete InitiatingBinding[PWSRestartIndication].
type PWSRestartIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s55.PWSRestartIndication, aper.DecodeState,

	) (s55.PWSRestartIndication, aper.Snapshot,

	)
	compare func(s55.PWSRestartIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.PWSRestartIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.PWSRestartIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.PWSRestartIndication,

		error)
	inject func(s55.PWSRestartIndication,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationInitiatingBinding) Codec() s55.PWSRestartIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.PWSRestartIndicationValueCodec{}
	}
	return func() s55.PWSRestartIndicationValueCodec {
		sealed := s55.PWSRestartIndicationValueCodec{}
		*s55.BridgePWSRestartIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgePWSRestartIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgePWSRestartIndicationValueCodecFieldEncode(&sealed) = func(value s55.PWSRestartIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgePWSRestartIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgePWSRestartIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgePWSRestartIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PWSRestartIndicationInitiatingBinding) Build(body s55.PWSRestartIndication,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PWSFailureIndicationInitiatingBinding is the concrete InitiatingBinding[PWSFailureIndication].
type PWSFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s52.PWSFailureIndication, aper.DecodeState,

	) (s52.PWSFailureIndication, aper.Snapshot,

	)
	compare func(s52.PWSFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s52.PWSFailureIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s52.PWSFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s52.PWSFailureIndication,

		error)
	inject func(s52.PWSFailureIndication,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b PWSFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSFailureIndicationInitiatingBinding) Codec() s52.PWSFailureIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s52.PWSFailureIndicationValueCodec{}
	}
	return func() s52.PWSFailureIndicationValueCodec {
		sealed := s52.PWSFailureIndicationValueCodec{}
		*s52.BridgePWSFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s52.BridgePWSFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s52.BridgePWSFailureIndicationValueCodecFieldEncode(&sealed) = func(value s52.PWSFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s52.BridgePWSFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s52.BridgePWSFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s52.BridgePWSFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PWSFailureIndicationInitiatingBinding) Build(body s52.PWSFailureIndication,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// RerouteNASRequestInitiatingBinding is the concrete InitiatingBinding[RerouteNASRequest].
type RerouteNASRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s31.RerouteNASRequest, aper.DecodeState,

	) (s31.RerouteNASRequest, aper.Snapshot,

	)
	compare func(s31.RerouteNASRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.RerouteNASRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.RerouteNASRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.RerouteNASRequest,

		error)
	inject func(s31.RerouteNASRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestInitiatingBinding) Codec() s31.RerouteNASRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.RerouteNASRequestValueCodec{}
	}
	return func() s31.RerouteNASRequestValueCodec {
		sealed := s31.RerouteNASRequestValueCodec{}
		*s31.BridgeRerouteNASRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeRerouteNASRequestValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeRerouteNASRequestValueCodecFieldEncode(&sealed) = func(value s31.RerouteNASRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeRerouteNASRequestValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeRerouteNASRequestValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeRerouteNASRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b RerouteNASRequestInitiatingBinding) Build(body s31.RerouteNASRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationIndicationInitiatingBinding is the concrete InitiatingBinding[UEContextModificationIndication].
type UEContextModificationIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UEContextModificationIndication, aper.DecodeState,

	) (s46.UEContextModificationIndication, aper.Snapshot,

	)
	compare func(s46.UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextModificationIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UEContextModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextModificationIndication,

		error)
	inject func(s46.UEContextModificationIndication,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationIndicationInitiatingBinding) Codec() s46.UEContextModificationIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextModificationIndicationValueCodec{}
	}
	return func() s46.UEContextModificationIndicationValueCodec {
		sealed := s46.UEContextModificationIndicationValueCodec{}
		*s46.BridgeUEContextModificationIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextModificationIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextModificationIndicationValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextModificationIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextModificationIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextModificationIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationIndicationInitiatingBinding) Build(body s46.UEContextModificationIndication,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextSuspendRequestInitiatingBinding is the concrete InitiatingBinding[UEContextSuspendRequest].
type UEContextSuspendRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s57.UEContextSuspendRequest, aper.DecodeState,

	) (s57.UEContextSuspendRequest, aper.Snapshot,

	)
	compare func(s57.UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.UEContextSuspendRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.UEContextSuspendRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.UEContextSuspendRequest,

		error)
	inject func(s57.UEContextSuspendRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendRequestInitiatingBinding) Codec() s57.UEContextSuspendRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.UEContextSuspendRequestValueCodec{}
	}
	return func() s57.UEContextSuspendRequestValueCodec {
		sealed := s57.UEContextSuspendRequestValueCodec{}
		*s57.BridgeUEContextSuspendRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeUEContextSuspendRequestValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeUEContextSuspendRequestValueCodecFieldEncode(&sealed) = func(value s57.UEContextSuspendRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeUEContextSuspendRequestValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeUEContextSuspendRequestValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeUEContextSuspendRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendRequestInitiatingBinding) Build(body s57.UEContextSuspendRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextResumeRequestInitiatingBinding is the concrete InitiatingBinding[UEContextResumeRequest].
type UEContextResumeRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s48.UEContextResumeRequest, aper.DecodeState,

	) (s48.UEContextResumeRequest, aper.Snapshot,

	)
	compare func(s48.UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s48.UEContextResumeRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s48.UEContextResumeRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s48.UEContextResumeRequest,

		error)
	inject func(s48.UEContextResumeRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestInitiatingBinding) Codec() s48.UEContextResumeRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s48.UEContextResumeRequestValueCodec{}
	}
	return func() s48.UEContextResumeRequestValueCodec {
		sealed := s48.UEContextResumeRequestValueCodec{}
		*s48.BridgeUEContextResumeRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s48.BridgeUEContextResumeRequestValueCodecFieldDecode(&sealed) = b.decode
		*s48.BridgeUEContextResumeRequestValueCodecFieldEncode(&sealed) = func(value s48.UEContextResumeRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s48.BridgeUEContextResumeRequestValueCodecFieldCapture(&sealed) = b.capture
		*s48.BridgeUEContextResumeRequestValueCodecFieldCompare(&sealed) = b.compare
		*s48.BridgeUEContextResumeRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeRequestInitiatingBinding) Build(body s48.UEContextResumeRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// RetrieveUEInformationInitiatingBinding is the concrete InitiatingBinding[RetrieveUEInformation].
type RetrieveUEInformationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.RetrieveUEInformation, aper.DecodeState,

	) (s36.RetrieveUEInformation, aper.Snapshot,

	)
	compare func(s36.RetrieveUEInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.RetrieveUEInformation,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s36.RetrieveUEInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.RetrieveUEInformation,

		error)
	inject func(s36.RetrieveUEInformation,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b RetrieveUEInformationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RetrieveUEInformationInitiatingBinding) Codec() s36.RetrieveUEInformationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.RetrieveUEInformationValueCodec{}
	}
	return func() s36.RetrieveUEInformationValueCodec {
		sealed := s36.RetrieveUEInformationValueCodec{}
		*s36.BridgeRetrieveUEInformationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeRetrieveUEInformationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeRetrieveUEInformationValueCodecFieldEncode(&sealed) = func(value s36.RetrieveUEInformation,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeRetrieveUEInformationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeRetrieveUEInformationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeRetrieveUEInformationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b RetrieveUEInformationInitiatingBinding) Build(body s36.RetrieveUEInformation,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEInformationTransferInitiatingBinding is the concrete InitiatingBinding[UEInformationTransfer].
type UEInformationTransferInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UEInformationTransfer, aper.DecodeState,

	) (s46.UEInformationTransfer, aper.Snapshot,

	)
	compare func(s46.UEInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEInformationTransfer,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UEInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEInformationTransfer,

		error)
	inject func(s46.UEInformationTransfer,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UEInformationTransferInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEInformationTransferInitiatingBinding) Codec() s46.UEInformationTransferValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEInformationTransferValueCodec{}
	}
	return func() s46.UEInformationTransferValueCodec {
		sealed := s46.UEInformationTransferValueCodec{}
		*s46.BridgeUEInformationTransferValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEInformationTransferValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEInformationTransferValueCodecFieldEncode(&sealed) = func(value s46.UEInformationTransfer,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEInformationTransferValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEInformationTransferValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEInformationTransferValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEInformationTransferInitiatingBinding) Build(body s46.UEInformationTransfer,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// SecondaryRATDataUsageReportInitiatingBinding is the concrete InitiatingBinding[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s57.SecondaryRATDataUsageReport, aper.DecodeState,

	) (s57.SecondaryRATDataUsageReport, aper.Snapshot,

	)
	compare func(s57.SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.SecondaryRATDataUsageReport,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.SecondaryRATDataUsageReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.SecondaryRATDataUsageReport,

		error)
	inject func(s57.SecondaryRATDataUsageReport,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SecondaryRATDataUsageReportInitiatingBinding) Codec() s57.SecondaryRATDataUsageReportValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.SecondaryRATDataUsageReportValueCodec{}
	}
	return func() s57.SecondaryRATDataUsageReportValueCodec {
		sealed := s57.SecondaryRATDataUsageReportValueCodec{}
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldEncode(&sealed) = func(value s57.SecondaryRATDataUsageReport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeSecondaryRATDataUsageReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b SecondaryRATDataUsageReportInitiatingBinding) Build(body s57.SecondaryRATDataUsageReport,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityIDMappingRequestInitiatingBinding is the concrete InitiatingBinding[UERadioCapabilityIDMappingRequest].
type UERadioCapabilityIDMappingRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UERadioCapabilityIDMappingRequest, aper.DecodeState,

	) (s46.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	)
	compare func(s46.UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UERadioCapabilityIDMappingRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UERadioCapabilityIDMappingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UERadioCapabilityIDMappingRequest,

		error)
	inject func(s46.UERadioCapabilityIDMappingRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Codec() s46.UERadioCapabilityIDMappingRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UERadioCapabilityIDMappingRequestValueCodec{}
	}
	return func() s46.UERadioCapabilityIDMappingRequestValueCodec {
		sealed := s46.UERadioCapabilityIDMappingRequestValueCodec{}
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldEncode(&sealed) = func(value s46.UERadioCapabilityIDMappingRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUERadioCapabilityIDMappingRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingRequestInitiatingBinding) Build(body s46.UERadioCapabilityIDMappingRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1RemovalRequestInitiatingBinding is the concrete InitiatingBinding[S1RemovalRequest].
type S1RemovalRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s31.S1RemovalRequest, aper.DecodeState,

	) (s31.S1RemovalRequest, aper.Snapshot,

	)
	compare func(s31.S1RemovalRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.S1RemovalRequest,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.S1RemovalRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.S1RemovalRequest,

		error)
	inject func(s31.S1RemovalRequest,

	) s65.InitiatingValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalRequestInitiatingBinding) Codec() s31.S1RemovalRequestValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.S1RemovalRequestValueCodec{}
	}
	return func() s31.S1RemovalRequestValueCodec {
		sealed := s31.S1RemovalRequestValueCodec{}
		*s31.BridgeS1RemovalRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeS1RemovalRequestValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeS1RemovalRequestValueCodecFieldEncode(&sealed) = func(value s31.S1RemovalRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeS1RemovalRequestValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeS1RemovalRequestValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeS1RemovalRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalRequestInitiatingBinding) Build(body s31.S1RemovalRequest,

	options ...aper.BuildOption) (s65.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s65.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s65.InitiatingMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s65.InitiatingMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s65.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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
func BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields s64.MMEConfigurationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s64.BridgeMMEConfigurationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s64.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s64.BridgeMMEConfigurationTransferIEValueMethodRule(field.Value).Assignment
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
func BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields s64.SONConfigurationTransferExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s64.SONConfigurationTransferExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s64.SONConfigurationTransferExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields s48.X2TNLConfigurationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.X2TNLConfigurationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s48.X2TNLConfigurationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// MMEConfigurationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueERABIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s64.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
	codec := s65.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s64.MMEConfigurationTransferIEValueERABIEContainerListValueCodec {
		sealed := s64.MMEConfigurationTransferIEValueERABIEContainerListValueCodec{}
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationTransferIEValueERABIEContainerList"
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.MMEConfigurationTransferIEValueERABIEContainerList
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.MMEConfigurationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.MMEConfigurationTransferIEValueERABIEContainerList, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s65.BridgeMMEConfigurationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.MMEConfigurationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEConfigurationTransferIEs}} codec of TS 36.413.
func MMEConfigurationTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable) s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := s65.MMEConfigurationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationTransferIEValueProtocolErrorIEContainerList"
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s65.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMEConfigurationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEConfigurationTransferIEValueProtocolIEContainerListCodec(table s00.MMEConfigurationTransferIEValueIETable, bounds aper.ListBounds) s64.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
	codec := s65.MMEConfigurationTransferIEValueIETableCodec(table, bounds)
	if *s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s64.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s64.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s64.MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec{}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMEConfigurationTransferIEValueProtocolIEContainerList"
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s64.MMEConfigurationTransferIEValueProtocolIEContainerList
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
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEConfigurationTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEConfigurationTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s64.MMEConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s64.BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(&codec))(s64.MMEConfigurationTransferIEContainer(value), fresh, budget)
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s64.MMEConfigurationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s64.MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s65.BridgeMMEConfigurationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s64.MMEConfigurationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s64.BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	captureSemantics(aper.SemanticCapture) s64.MMEConfigurationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s64.MMEConfigurationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// sONConfigurationTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SONConfigurationTransferExtIEsValue].
type SONConfigurationTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s64.SONConfigurationTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s64.SONConfigurationTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// x2TNLConfigurationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[X2TNLConfigurationInfoExtIEsValue].
type X2TNLConfigurationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s48.X2TNLConfigurationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s48.X2TNLConfigurationInfoExtIEsValue,

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
func BridgeSONConfigurationTransferExtIEsValueValidateS1APIEContainer(fields s64.SONConfigurationTransferExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s64.BridgeSONConfigurationTransferExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s64.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s64.BridgeSONConfigurationTransferExtIEsValueMethodRule(field.Value).Assignment
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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APIEContainer(fields s48.X2TNLConfigurationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s48.BridgeX2TNLConfigurationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s48.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s48.BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeMMEConfigurationTransferIEValueCompareS1APERABIEContainerList(v *s64.MMEConfigurationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s64.MMEConfigurationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEContainerList(v *s64.MMEConfigurationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIESingleContainer(v *s64.MMEConfigurationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s65.BridgeMMEConfigurationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func NewOpaqueInitiatingMessage(code s00.ProcedureCode, criticality s00.Criticality, data []byte) (s65.InitiatingMessage, error) {
	switch code {
	case s00.ProcedureCode(0):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-HandoverPreparation requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(1):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-HandoverResourceAllocation requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(2):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-HandoverNotification requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(3):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-PathSwitchRequest requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(4):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-HandoverCancel requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(5):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-E-RABSetup requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(6):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-E-RABModify requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(7):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-E-RABRelease requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(8):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-E-RABReleaseIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(9):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-InitialContextSetup requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(10):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-Paging requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(11):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-downlinkNASTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(12):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-initialUEMessage requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(13):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-uplinkNASTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(14):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-Reset requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(15):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-ErrorIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(16):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-NASNonDeliveryIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(17):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-S1Setup requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(18):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextReleaseRequest requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(19):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-DownlinkS1cdma2000tunnelling requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(20):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UplinkS1cdma2000tunnelling requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(21):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextModification requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(22):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UECapabilityInfoIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(23):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextRelease requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(24):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-eNBStatusTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(25):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMEStatusTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(26):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-DeactivateTrace requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(27):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-TraceStart requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(28):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-TraceFailureIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(29):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-ENBConfigurationUpdate requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(30):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMEConfigurationUpdate requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(31):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-LocationReportingControl requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(32):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-LocationReportingFailureIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(33):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-LocationReport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(34):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-OverloadStart requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(35):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-OverloadStop requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(36):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-WriteReplaceWarning requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(37):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-eNBDirectInformationTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(38):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMEDirectInformationTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(39):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-PrivateMessage requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(40):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-eNBConfigurationTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(41):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMEConfigurationTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(42):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-CellTrafficTrace requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(43):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-Kill requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(44):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-downlinkUEAssociatedLPPaTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(45):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-uplinkUEAssociatedLPPaTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(46):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-downlinkNonUEAssociatedLPPaTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(47):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-uplinkNonUEAssociatedLPPaTransport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(48):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UERadioCapabilityMatch requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(49):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-PWSRestartIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(50):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-E-RABModificationIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(51):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-PWSFailureIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(52):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-RerouteNASRequest requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(53):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextModificationIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(54):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-ConnectionEstablishmentIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(55):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextSuspend requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(56):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEContextResume requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(57):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-NASDeliveryIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(58):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-RetrieveUEInformation requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(59):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UEInformationTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(60):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-eNBCPRelocationIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(61):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMECPRelocationIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(62):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-SecondaryRATDataUsageReport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(63):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-UERadioCapabilityIDMapping requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(64):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-HandoverSuccess requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(65):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-eNBEarlyStatusTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(66):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-MMEEarlyStatusTransfer requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(67):
		return s65.InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-S1Removal requires its typed binding"), "OpaqueInitiatingMessage")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	message := s65.InitiatingMessage{ProcedureCode: code, Criticality: criticality, Value: func() s65.InitiatingValue {
		sealed := s65.InitiatingValue{}
		*s65.BridgeInitiatingValueFieldCode(&sealed) = code
		*s65.BridgeInitiatingValueFieldOpaque(&sealed) = opaque
		*s65.BridgeInitiatingValueFieldIsOpaque(&sealed) = true
		return sealed
	}()}
	if _, err := s65.BridgeInitiatingMessageMethodMarshalAPERBudget(&message, budget, false); err != nil {
		return s65.InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	return message, aper.OperationError(nil, "OpaqueInitiatingMessage")
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
				s65.BridgeCaptureS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s64.BridgeCaptureS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s46.BridgeCaptureS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
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
				s65.BridgeCompareS1APInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s64.BridgeCompareS1APSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s46.BridgeCompareS1APUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
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
	InitiatingMessage   *s65.InitiatingMessage   `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *s64.SuccessfulOutcome   `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *s46.UnsuccessfulOutcome `json:"UnsuccessfulOutcome,omitempty"`
}

// NewS1APPDUInitiatingMessage creates a S1APPDU with the initiatingMessage alternative.
func BridgeNewS1APPDUInitiatingMessageLegacy(v s65.InitiatingMessage) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewS1APPDUSuccessfulOutcome creates a S1APPDU with the successfulOutcome alternative.
func BridgeNewS1APPDUSuccessfulOutcomeLegacy(v s64.SuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:            s00.S1APPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewS1APPDUUnsuccessfulOutcome creates a S1APPDU with the unsuccessfulOutcome alternative.
func BridgeNewS1APPDUUnsuccessfulOutcomeLegacy(v s46.UnsuccessfulOutcome) S1APPDU {
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
		if err := s65.BridgeInitiatingMessageMethodMarshalAPERTo(v.InitiatingMessage, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case s00.S1APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := s64.BridgeSuccessfulOutcomeMethodMarshalAPERTo(v.SuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := s46.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v.UnsuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		var dec_initiatingmessage s65.InitiatingMessage
		if err := s65.BridgeInitiatingMessageMethodUnmarshalAPERFrom(&dec_initiatingmessage, bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		if err := aper.ChargeValue(bb, dec_initiatingmessage); err != nil {
			return err
		}
		v.InitiatingMessage = &dec_initiatingmessage
		bb.LeaveComponent(toleranceMark_initiatingmessage)
	case s00.S1APPDUChoiceSuccessfulOutcome:
		toleranceMark_successfuloutcome := bb.EnterComponent("SuccessfulOutcome")
		var dec_successfuloutcome s64.SuccessfulOutcome
		if err := s64.BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_successfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_successfuloutcome); err != nil {
			return err
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
		bb.LeaveComponent(toleranceMark_successfuloutcome)
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		toleranceMark_unsuccessfuloutcome := bb.EnterComponent("UnsuccessfulOutcome")
		var dec_unsuccessfuloutcome s46.UnsuccessfulOutcome
		if err := s46.BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_unsuccessfuloutcome, bb); err != nil {
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1APPDU", v.receivedLocation, v.perPadding)
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

type PagingDescriptor struct{}

func PagingProcedure() PagingDescriptor { return PagingDescriptor{} }

// Info returns the source-derived procedure metadata for PagingDescriptor.
func (PagingDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(10), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-Paging"}}}
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

type OverloadStartDescriptor struct{}

func OverloadStartProcedure() OverloadStartDescriptor { return OverloadStartDescriptor{} }

// Info returns the source-derived procedure metadata for OverloadStartDescriptor.
func (OverloadStartDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(34), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-OverloadStart"}}}
}

type OverloadStopDescriptor struct{}

func OverloadStopProcedure() OverloadStopDescriptor { return OverloadStopDescriptor{} }

// Info returns the source-derived procedure metadata for OverloadStopDescriptor.
func (OverloadStopDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(35), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-OverloadStop"}}}
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

type PWSRestartIndicationDescriptor struct{}

func PWSRestartIndicationProcedure() PWSRestartIndicationDescriptor {
	return PWSRestartIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for PWSRestartIndicationDescriptor.
func (PWSRestartIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(49), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-PWSRestartIndication"}}}
}

type PWSFailureIndicationDescriptor struct{}

func PWSFailureIndicationProcedure() PWSFailureIndicationDescriptor {
	return PWSFailureIndicationDescriptor{}
}

// Info returns the source-derived procedure metadata for PWSFailureIndicationDescriptor.
func (PWSFailureIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(51), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "id-PWSFailureIndication"}}}
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
func ENBConfigurationTransferCodec() s65.ENBConfigurationTransferValueCodec {
	return ENBConfigurationTransferProcedure().Initiating().Codec()
}

// MMEConfigurationTransferCodec binds the complete APER value type.
func MMEConfigurationTransferCodec() s65.MMEConfigurationTransferValueCodec {
	return MMEConfigurationTransferProcedure().Initiating().Codec()
}

// OverloadStartCodec binds the complete APER value type.
func OverloadStartCodec() s52.OverloadStartValueCodec {
	return OverloadStartProcedure().Initiating().Codec()
}

// OverloadStopCodec binds the complete APER value type.
func OverloadStopCodec() s52.OverloadStopValueCodec {
	return OverloadStopProcedure().Initiating().Codec()
}

// PWSFailureIndicationCodec binds the complete APER value type.
func PWSFailureIndicationCodec() s52.PWSFailureIndicationValueCodec {
	return PWSFailureIndicationProcedure().Initiating().Codec()
}

// PWSRestartIndicationCodec binds the complete APER value type.
func PWSRestartIndicationCodec() s55.PWSRestartIndicationValueCodec {
	return PWSRestartIndicationProcedure().Initiating().Codec()
}

// PagingCodec binds the complete APER value type.
func PagingCodec() s61.PagingValueCodec { return PagingProcedure().Initiating().Codec() }

// PathSwitchRequestAcknowledgeCodec binds the complete APER value type.
func PathSwitchRequestAcknowledgeCodec() s58.PathSwitchRequestAcknowledgeValueCodec {
	return PathSwitchRequestProcedure().Successful().Codec()
}

// PathSwitchRequestCodec binds the complete APER value type.
func PathSwitchRequestCodec() s51.PathSwitchRequestValueCodec {
	return PathSwitchRequestProcedure().Initiating().Codec()
}

// PathSwitchRequestFailureCodec binds the complete APER value type.
func PathSwitchRequestFailureCodec() s30.PathSwitchRequestFailureValueCodec {
	return PathSwitchRequestProcedure().Unsuccessful().Codec()
}

// PrivateMessageCodec binds the complete APER value type.
func PrivateMessageCodec() s30.PrivateMessageValueCodec {
	return PrivateMessageProcedure().Initiating().Codec()
}

// RerouteNASRequestCodec binds the complete APER value type.
func RerouteNASRequestCodec() s31.RerouteNASRequestValueCodec {
	return RerouteNASRequestProcedure().Initiating().Codec()
}

// ResetAcknowledgeCodec binds the complete APER value type.
func ResetAcknowledgeCodec() s55.ResetAcknowledgeValueCodec {
	return ResetProcedure().Successful().Codec()
}

// ResetCodec binds the complete APER value type.
func ResetCodec() s45.ResetValueCodec { return ResetProcedure().Initiating().Codec() }

// RetrieveUEInformationCodec binds the complete APER value type.
func RetrieveUEInformationCodec() s36.RetrieveUEInformationValueCodec {
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
func S1RemovalFailureCodec() s31.S1RemovalFailureValueCodec {
	return S1RemovalProcedure().Unsuccessful().Codec()
}

// S1RemovalRequestCodec binds the complete APER value type.
func S1RemovalRequestCodec() s31.S1RemovalRequestValueCodec {
	return S1RemovalProcedure().Initiating().Codec()
}

// S1RemovalResponseCodec binds the complete APER value type.
func S1RemovalResponseCodec() s31.S1RemovalResponseValueCodec {
	return S1RemovalProcedure().Successful().Codec()
}

// S1SetupFailureCodec binds the complete APER value type.
func S1SetupFailureCodec() s31.S1SetupFailureValueCodec {
	return S1SetupProcedure().Unsuccessful().Codec()
}

// S1SetupRequestCodec binds the complete APER value type.
func S1SetupRequestCodec() s54.S1SetupRequestValueCodec {
	return S1SetupProcedure().Initiating().Codec()
}

// S1SetupResponseCodec binds the complete APER value type.
func S1SetupResponseCodec() s54.S1SetupResponseValueCodec {
	return S1SetupProcedure().Successful().Codec()
}

// SecondaryRATDataUsageReportCodec binds the complete APER value type.
func SecondaryRATDataUsageReportCodec() s57.SecondaryRATDataUsageReportValueCodec {
	return SecondaryRATDataUsageReportProcedure().Initiating().Codec()
}

// TraceFailureIndicationCodec binds the complete APER value type.
func TraceFailureIndicationCodec() s44.TraceFailureIndicationValueCodec {
	return TraceFailureIndicationProcedure().Initiating().Codec()
}

// TraceStartCodec binds the complete APER value type.
func TraceStartCodec() s61.TraceStartValueCodec { return TraceStartProcedure().Initiating().Codec() }

// UECapabilityInfoIndicationCodec binds the complete APER value type.
func UECapabilityInfoIndicationCodec() s45.UECapabilityInfoIndicationValueCodec {
	return UECapabilityInfoIndicationProcedure().Initiating().Codec()
}

// UEContextModificationConfirmCodec binds the complete APER value type.
func UEContextModificationConfirmCodec() s45.UEContextModificationConfirmValueCodec {
	return UEContextModificationIndicationProcedure().Successful().Codec()
}

// UEContextModificationFailureCodec binds the complete APER value type.
func UEContextModificationFailureCodec() s46.UEContextModificationFailureValueCodec {
	return UEContextModificationProcedure().Unsuccessful().Codec()
}

// UEContextModificationIndicationCodec binds the complete APER value type.
func UEContextModificationIndicationCodec() s46.UEContextModificationIndicationValueCodec {
	return UEContextModificationIndicationProcedure().Initiating().Codec()
}

// UEContextModificationRequestCodec binds the complete APER value type.
func UEContextModificationRequestCodec() s58.UEContextModificationRequestValueCodec {
	return UEContextModificationProcedure().Initiating().Codec()
}

// UEContextModificationResponseCodec binds the complete APER value type.
func UEContextModificationResponseCodec() s46.UEContextModificationResponseValueCodec {
	return UEContextModificationProcedure().Successful().Codec()
}

// UEContextReleaseCommandCodec binds the complete APER value type.
func UEContextReleaseCommandCodec() s47.UEContextReleaseCommandValueCodec {
	return UEContextReleaseProcedure().Initiating().Codec()
}

// UEContextReleaseCompleteCodec binds the complete APER value type.
func UEContextReleaseCompleteCodec() s57.UEContextReleaseCompleteValueCodec {
	return UEContextReleaseProcedure().Successful().Codec()
}

// UEContextReleaseRequestCodec binds the complete APER value type.
func UEContextReleaseRequestCodec() s53.UEContextReleaseRequestValueCodec {
	return UEContextReleaseRequestProcedure().Initiating().Codec()
}

// UEContextResumeFailureCodec binds the complete APER value type.
func UEContextResumeFailureCodec() s46.UEContextResumeFailureValueCodec {
	return UEContextResumeProcedure().Unsuccessful().Codec()
}

// UEContextResumeRequestCodec binds the complete APER value type.
func UEContextResumeRequestCodec() s48.UEContextResumeRequestValueCodec {
	return UEContextResumeProcedure().Initiating().Codec()
}

// UEContextResumeResponseCodec binds the complete APER value type.
func UEContextResumeResponseCodec() s49.UEContextResumeResponseValueCodec {
	return UEContextResumeProcedure().Successful().Codec()
}

// UEContextSuspendRequestCodec binds the complete APER value type.
func UEContextSuspendRequestCodec() s57.UEContextSuspendRequestValueCodec {
	return UEContextSuspendProcedure().Initiating().Codec()
}

// UEContextSuspendResponseCodec binds the complete APER value type.
func UEContextSuspendResponseCodec() s46.UEContextSuspendResponseValueCodec {
	return UEContextSuspendProcedure().Successful().Codec()
}

// UEInformationTransferCodec binds the complete APER value type.
func UEInformationTransferCodec() s46.UEInformationTransferValueCodec {
	return UEInformationTransferProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingRequestCodec binds the complete APER value type.
func UERadioCapabilityIDMappingRequestCodec() s46.UERadioCapabilityIDMappingRequestValueCodec {
	return UERadioCapabilityIDMappingProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingResponseCodec binds the complete APER value type.
func UERadioCapabilityIDMappingResponseCodec() s46.UERadioCapabilityIDMappingResponseValueCodec {
	return UERadioCapabilityIDMappingProcedure().Successful().Codec()
}

// UERadioCapabilityMatchRequestCodec binds the complete APER value type.
func UERadioCapabilityMatchRequestCodec() s46.UERadioCapabilityMatchRequestValueCodec {
	return UERadioCapabilityMatchProcedure().Initiating().Codec()
}

// UERadioCapabilityMatchResponseCodec binds the complete APER value type.
func UERadioCapabilityMatchResponseCodec() s46.UERadioCapabilityMatchResponseValueCodec {
	return UERadioCapabilityMatchProcedure().Successful().Codec()
}

// UplinkNASTransportCodec binds the complete APER value type.
func UplinkNASTransportCodec() s55.UplinkNASTransportValueCodec {
	return UplinkNASTransportProcedure().Initiating().Codec()
}

// UplinkNonUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkNonUEAssociatedLPPaTransportCodec() s55.UplinkNonUEAssociatedLPPaTransportValueCodec {
	return UplinkNonUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// UplinkS1cdma2000tunnellingCodec binds the complete APER value type.
func UplinkS1cdma2000tunnellingCodec() s55.UplinkS1cdma2000tunnellingValueCodec {
	return UplinkS1cdma2000tunnellingProcedure().Initiating().Codec()
}

// UplinkUEAssociatedLPPaTransportCodec binds the complete APER value type.
func UplinkUEAssociatedLPPaTransportCodec() s55.UplinkUEAssociatedLPPaTransportValueCodec {
	return UplinkUEAssociatedLPPaTransportProcedure().Initiating().Codec()
}

// WriteReplaceWarningRequestCodec binds the complete APER value type.
func WriteReplaceWarningRequestCodec() s64.WriteReplaceWarningRequestValueCodec {
	return WriteReplaceWarningProcedure().Initiating().Codec()
}

// WriteReplaceWarningResponseCodec binds the complete APER value type.
func WriteReplaceWarningResponseCodec() s64.WriteReplaceWarningResponseValueCodec {
	return WriteReplaceWarningProcedure().Successful().Codec()
}
func BridgeValidateENBConfigurationTransferBudget(v *s65.ENBConfigurationTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s65.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s65.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s65.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
	report := s65.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationTransfer(v, &report, "ENBConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateMMEConfigurationTransferBudget(v *s65.MMEConfigurationTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationTransfer")
	}
	rows := []s00.FieldInfo{s65.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s65.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s65.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
	report := BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationTransfer(v, &report, "MMEConfigurationTransfer", true)
	return report, nil
}
func BridgeValidateSuccessfulOutcome(v *s64.SuccessfulOutcome, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SuccessfulOutcome")
	}
	if *s64.BridgeSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverCommand()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCommand", "SuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateHandoverCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverRequestAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverRequestAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateHandoverRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequestAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequestAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidatePathSwitchRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsHandoverCancelAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverCancelAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateHandoverCancelAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsERABSetupResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABSetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateERABSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsERABModifyResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModifyResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateERABModifyResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABModifyProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsERABReleaseResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABReleaseResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateERABReleaseResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateInitialContextSetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		body, ok := v.Value.AsResetAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ResetAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateResetAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		body, ok := v.Value.AsS1SetupResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupResponse", "SuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateS1SetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsUEContextModificationResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextModificationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 23:
		body, ok := v.Value.AsUEContextReleaseComplete()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextReleaseComplete", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextReleaseCompleteBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdateAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdateAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateENBConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdateAcknowledge()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdateAcknowledge", "SuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		body, ok := v.Value.AsWriteReplaceWarningResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing WriteReplaceWarningResponse", "SuccessfulOutcome.value:")
		}
		report, err := s64.BridgeValidateWriteReplaceWarningResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{WriteReplaceWarningProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		body, ok := v.Value.AsKillResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing KillResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateKillResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.KillProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		body, ok := v.Value.AsUERadioCapabilityMatchResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityMatchResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUERadioCapabilityMatchResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityMatchProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		body, ok := v.Value.AsERABModificationConfirm()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ERABModificationConfirm", "SuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateERABModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ERABModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		body, ok := v.Value.AsUEContextModificationConfirm()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationConfirm", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 55:
		body, ok := v.Value.AsUEContextSuspendResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextSuspendResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextSuspendResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextSuspendProcedure().Info().Rule}})
		}
		return report, nil
	case 56:
		body, ok := v.Value.AsUEContextResumeResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextResumeResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 63:
		body, ok := v.Value.AsUERadioCapabilityIDMappingResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UERadioCapabilityIDMappingResponse", "SuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUERadioCapabilityIDMappingResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 64:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 67:
		body, ok := v.Value.AsS1RemovalResponse()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalResponse", "SuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateS1RemovalResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateUnsuccessfulOutcome(v *s46.UnsuccessfulOutcome, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UnsuccessfulOutcome")
	}
	if *s46.BridgeUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverPreparationFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverPreparationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateHandoverPreparationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing HandoverFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateHandoverFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.HandoverResourceAllocationProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		body, ok := v.Value.AsPathSwitchRequestFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PathSwitchRequestFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidatePathSwitchRequestFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{PathSwitchRequestProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 7:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 8:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		body, ok := v.Value.AsInitialContextSetupFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing InitialContextSetupFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateInitialContextSetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.InitialContextSetupProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 13:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 15:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 16:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		body, ok := v.Value.AsS1SetupFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1SetupFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateS1SetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 19:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 20:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsUEContextModificationFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextModificationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextModificationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 23:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 24:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 27:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 28:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsENBConfigurationUpdateFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ENBConfigurationUpdateFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s61.BridgeValidateENBConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsMMEConfigurationUpdateFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing MMEConfigurationUpdateFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateMMEConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s65.MMEConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 32:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 35:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 37:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 38:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 40:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 44:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 49:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 51:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 54:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 55:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 56:
		body, ok := v.Value.AsUEContextResumeFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UEContextResumeFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s63.BridgeValidateUEContextResumeFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextResumeProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 58:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 63:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 64:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 65:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 66:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnavailableOutcome), RelatedRules: s31.BridgeS1apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 67:
		body, ok := v.Value.AsS1RemovalFailure()
		if !ok {
			return func() s25.ValidationReport {
				sealed := s25.ValidationReport{}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing S1RemovalFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s62.BridgeValidateS1RemovalFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{S1RemovalProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s25.ValidationReport {
			report := func() s25.ValidationReport {
				sealed := s25.ValidationReport{Complete: false}
				*s25.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s31.BridgeS1apValidationRule(s00.UnknownProcedure)})
			s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "UnsuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func ValidateENBConfigurationTransfer(v *s65.ENBConfigurationTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBConfigurationTransfer")
	}
	report, err := BridgeValidateENBConfigurationTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s65.BridgeENBConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationTransfer")
}
func ValidateMMEConfigurationTransfer(v *s65.MMEConfigurationTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEConfigurationTransfer")
	}
	report, err := BridgeValidateMMEConfigurationTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s65.BridgeMMEConfigurationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationTransfer")
}
func BridgeWalkValidationENBConfigurationTransfer(v *s65.ENBConfigurationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s65.ENBConfigurationTransferIEs().SONConfigurationTransferECT().Info(), s65.ENBConfigurationTransferIEs().ENDCSONConfigurationTransferECT().Info(), s65.ENBConfigurationTransferIEs().IntersystemSONConfigurationTransferECT().Info()}
			s30.BridgeMergeNestedValidation(report, s65.BridgeENBConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONConfigurationTransfer(v *s64.ENDCSONConfigurationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s62.BridgeWalkValidationENDCSONTransferType(&v.Transfertype, report, path+".transfertype", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSONInformation(&v.SONInformation, report, path+".sONInformation", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.X2TNLConfigInfo != nil {
		BridgeWalkValidationX2TNLConfigurationInfo(v.X2TNLConfigInfo, report, path+".x2TNLConfigInfo", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeENDCSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitiatingMessage(v *s65.InitiatingMessage, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationTransfer(v *s65.MMEConfigurationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s65.MMEConfigurationTransferIEs().SONConfigurationTransferMCT().Info(), s65.MMEConfigurationTransferIEs().ENDCSONConfigurationTransferMCT().Info(), s65.MMEConfigurationTransferIEs().IntersystemSONConfigurationTransferMCT().Info()}
			s30.BridgeMergeNestedValidation(report, BridgeMMEConfigurationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1APPDU(v *S1APPDU, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.S1APPDUChoiceInitiatingMessage && v.InitiatingMessage != nil {
		BridgeWalkValidationInitiatingMessage(v.InitiatingMessage, report, path+".initiatingMessage", false)
	}
	if v.Choice == s00.S1APPDUChoiceSuccessfulOutcome && v.SuccessfulOutcome != nil {
		s64.BridgeWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
	}
	if v.Choice == s00.S1APPDUChoiceUnsuccessfulOutcome && v.UnsuccessfulOutcome != nil {
		s63.BridgeWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
	}
}
func BridgeWalkValidationSONConfigurationTransfer(v *s64.SONConfigurationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s63.BridgeWalkValidationTargeteNBID(&v.TargeteNBID, report, path+".targeteNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s62.BridgeWalkValidationSourceeNBID(&v.SourceeNBID, report, path+".sourceeNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSONInformation(&v.SONInformation, report, path+".sONInformation", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s64.SONConfigurationTransferExtIEs().X2TNLConfigurationInfo().Info()), s00.FieldInfo(s64.SONConfigurationTransferExtIEs().SynchronisationInformation().Info()), s00.FieldInfo(s64.SONConfigurationTransferExtIEs().RequestedTNLInfo().Info())}
				s30.BridgeMergeNestedValidation(report, BridgeSONConfigurationTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(152):
					if value, ok := fields[i].ExtensionValue.AsX2TNLConfigurationInfo(); ok {
						BridgeWalkValidationX2TNLConfigurationInfo(value, report, fmt.Sprintf("%s[%d]{id=152}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(209):
					if value, ok := fields[i].ExtensionValue.AsSynchronisationInformation(); ok {
						s62.BridgeWalkValidationSynchronisationInformation(value, report, fmt.Sprintf("%s[%d]{id=209}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(356):
					if value, ok := fields[i].ExtensionValue.AsRequestedTNLInfo(); ok {
						s62.BridgeWalkValidationRequestedTNLInfo(value, report, fmt.Sprintf("%s[%d]{id=356}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformation(v *s64.SONInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONInformationChoiceSONInformationReply && v.SONInformationReply != nil {
		BridgeWalkValidationSONInformationReply(v.SONInformationReply, report, path+".sONInformationReply", false)
	}
	if v.Choice == s00.SONInformationChoiceSONInformationExtension && v.SONInformationExtension != nil {
		s62.BridgeWalkValidationSONInformationExtension(v.SONInformationExtension, report, path+".sONInformation-Extension", false)
	}
}
func BridgeWalkValidationSONInformationReply(v *s64.SONInformationReply, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.X2TNLConfigurationInfo != nil {
		BridgeWalkValidationX2TNLConfigurationInfo(v.X2TNLConfigurationInfo, report, path+".x2TNLConfigurationInfo", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s44.SONInformationReplyExtIEs().TimeSynchronisationInfo().Info()), s00.FieldInfo(s44.SONInformationReplyExtIEs().MutingPatternInformation().Info())}
				s30.BridgeMergeNestedValidation(report, s44.BridgeSONInformationReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(149):
					if value, ok := fields[i].ExtensionValue.AsTimeSynchronisationInfo(); ok {
						s63.BridgeWalkValidationTimeSynchronisationInfo(value, report, fmt.Sprintf("%s[%d]{id=149}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(208):
					if value, ok := fields[i].ExtensionValue.AsMutingPatternInformation(); ok {
						s62.BridgeWalkValidationMutingPatternInformation(value, report, fmt.Sprintf("%s[%d]{id=208}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationX2TNLConfigurationInfo(v *s64.X2TNLConfigurationInfo, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationENBX2TLAs(&v.ENBX2TransportLayerAddresses, report, path+".eNBX2TransportLayerAddresses", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s48.X2TNLConfigurationInfoExtIEs().ENBX2ExtendedTransportLayerAddresses().Info()), s00.FieldInfo(s48.X2TNLConfigurationInfoExtIEs().ENBIndirectX2TransportLayerAddresses().Info())}
				s30.BridgeMergeNestedValidation(report, BridgeX2TNLConfigurationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(153):
					if value, ok := fields[i].ExtensionValue.AsENBX2ExtendedTransportLayerAddresses(); ok {
						s61.BridgeWalkValidationENBX2ExtTLAs(value, report, fmt.Sprintf("%s[%d]{id=153}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(193):
					if value, ok := fields[i].ExtensionValue.AsENBIndirectX2TransportLayerAddresses(); ok {
						s61.BridgeWalkValidationENBIndirectX2TransportLayerAddresses(value, report, fmt.Sprintf("%s[%d]{id=193}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeS1APPDUMethodMarshalAPERBudget(v *S1APPDU, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1APPDUMethodUnmarshalAPERWithOptions(v *S1APPDU, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
