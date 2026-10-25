// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

// TS 36.413 V19.2.0 §9.3.2 selects the PDU alternative; X.691 (02/2021)
// §23 selects exactly one CHOICE alternative. Validation refuses every malformed
// PDU selector state rejected by the encoder, while opaque future choices stay unchecked.
func TestValidationPDURefusalParity(t *testing.T) {
	init := initiatingMessageFreshMust(s52.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0}))
	success := successfulOutcomeFreshMust(s51.NewOpaqueSuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
	failure := unsuccessfulOutcomeFreshMust(s37.NewOpaqueUnsuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
	extension := choiceExtensionFreshMust(aper.NewChoiceExtension(0, []byte{0}))
	emptyExtension := aper.ChoiceExtension{}
	cases := []struct {
		name    string
		pdu     s53.S1APPDU
		refused bool
	}{
		{"initiating", s53.S1APPDU{Choice: 1, InitiatingMessage: &init}, false},
		{"successful", s53.S1APPDU{Choice: 2, SuccessfulOutcome: &success}, false},
		{"unsuccessful", s53.S1APPDU{Choice: 3, UnsuccessfulOutcome: &failure}, false},
		{"nil initiating", s53.S1APPDU{Choice: 1}, true},
		{"nil successful", s53.S1APPDU{Choice: 2}, true},
		{"nil unsuccessful", s53.S1APPDU{Choice: 3}, true},
		{"initiating and unknown", s53.S1APPDU{Choice: 1, InitiatingMessage: &init, UnknownExtension: &extension}, true},
		{"successful and unknown", s53.S1APPDU{Choice: 2, SuccessfulOutcome: &success, UnknownExtension: &extension}, true},
		{"unsuccessful and unknown", s53.S1APPDU{Choice: 3, UnsuccessfulOutcome: &failure, UnknownExtension: &extension}, true},
		{"future empty contents", s53.S1APPDU{UnknownExtension: &emptyExtension}, true},
		{"future choice", s53.S1APPDU{UnknownExtension: &extension}, false},
	}
	for _, choice := range []int{-1, 0, 4, 127} {
		cases = append(cases, struct {
			name    string
			pdu     s53.S1APPDU
			refused bool
		}{name: fmt.Sprintf("invalid %d", choice), pdu: s53.S1APPDU{Choice: choice}, refused: true})
		if choice != 0 {
			cases = append(cases, struct {
				name    string
				pdu     s53.S1APPDU
				refused bool
			}{name: fmt.Sprintf("invalid and opaque %d", choice), pdu: s53.S1APPDU{Choice: choice, UnknownExtension: &extension}, refused: true})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, encodeErr := tc.pdu.MarshalAPER()
			report, validationErr := s53.ValidateMessage(&tc.pdu)
			if (encodeErr != nil) != tc.refused {
				t.Fatalf("encoder refusal=%v want %t", encodeErr, tc.refused)
			}
			if (validationErr != nil) != tc.refused {
				t.Errorf("validation refusal=%v want %t; report=%+v", validationErr, tc.refused, report)
			}
			if !tc.refused && tc.pdu.UnknownExtension != nil && (report.Complete || len(report.Unchecked) != 1 || report.Unchecked[0].Path != "S1APPDU.unknownExtension") {
				t.Errorf("future choice report=%+v", report)
			}
		})
	}
}

// TS 36.413 V19.2.0 §10.3.6 applies to repeated IEs even when their IDs are
// not in the selected object set. Unknown IEs still do not set known-row order.
func TestValidationUnknownDuplicates(t *testing.T) {
	table := s23.S1SetupFailureIEs()
	cause := s1SetupFailureIEFieldFreshMust(table.Cause().New(causeFreshMust(s26.NewCauseMisc(s00.CauseMiscUnspecified))))
	for _, id := range []s00.ProtocolIEID{65532, 0} {
		t.Run(fmt.Sprintf("id-%d", id), func(t *testing.T) {
			unknown := s1SetupFailureIEFieldFreshMust(table.NewOpaque(id, s00.CriticalityIgnore, []byte{0}))
			body := s27.S1SetupFailure{ProtocolIEs: s23.S1SetupFailureIEContainer{cause, unknown, unknown}}
			report, err := s50.ValidateS1SetupFailure(&body)
			if err != nil {
				t.Fatal(err)
			}
			requireRepeatedIE(t, report, id, "[2]")
			var build *s21.BuildError
			if _, err := s50.NewS1SetupFailure(body.ProtocolIEs); !errors.As(err, &build) {
				t.Errorf("builder accepted duplicate id %d: %v", id, err)
			}
		})
	}
	extension := criticalityDiagnosticsExtIEsExtFieldFreshMust(s07.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	value := s22.CriticalityDiagnostics{IEExtensions: s07.CriticalityDiagnosticsExtIEsExtContainer{extension, extension}}
	report := s21.ValidationReport{Complete: true}
	s50.BridgeWalkValidationCriticalityDiagnostics(&value, &report, "CriticalityDiagnostics", false)
	requireRepeatedIE(t, report, 65532, "[1]")
}
func requireRepeatedIE(t *testing.T, report s21.ValidationReport, id s00.ProtocolIEID, index string) {
	t.Helper()
	count := 0
	for _, issue := range report.Issues {
		if issue.Code == s00.RepeatedIE && issue.IEID == id {
			count++
			if !issue.HasIEID || issue.Severity != s00.ValidationSeverityError || !strings.Contains(string(issue.Location.Path), index) {
				t.Errorf("incomplete duplicate issue: %+v", issue)
			}
			rule := false
			for _, related := range issue.RelatedRules {
				rule = rule || related.Clause == "§10.3.6"
			}
			if !rule {
				t.Errorf("missing duplicate source: %+v", issue)
			}
		}
	}
	if count != 1 {
		t.Errorf("repeated id %d issue count=%d want 1; report=%+v", id, count, report)
	}
}

// TS 36.413 V19.2.0 §9.3.7 binds every selected table row to @id. All 63
// source tables containing id-MME-UE-S1AP-ID (0) require a selected row.
func TestValidationAllZeroIDTables(t *testing.T) {
	t.Run("CellTrafficTraceIEs", func(t *testing.T) {
		cellTrafficTraceIEValueRequireZeroIDSelection(t, cellTrafficTraceIEFieldFreshMust(s18.CellTrafficTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), cellTrafficTraceIEFieldFreshMust(s18.CellTrafficTraceIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ConnectionEstablishmentIndicationIEs", func(t *testing.T) {
		connectionEstablishmentIndicationIEValueRequireZeroIDSelection(t, connectionEstablishmentIndicationIEFieldFreshMust(s31.ConnectionEstablishmentIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), connectionEstablishmentIndicationIEFieldFreshMust(s31.ConnectionEstablishmentIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DeactivateTraceIEs", func(t *testing.T) {
		deactivateTraceIEValueRequireZeroIDSelection(t, deactivateTraceIEFieldFreshMust(s08.DeactivateTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), deactivateTraceIEFieldFreshMust(s08.DeactivateTraceIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkNASTransportIEs", func(t *testing.T) {
		downlinkNASTransportIEValueRequireZeroIDSelection(t, downlinkNASTransportIEFieldFreshMust(s43.DownlinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkNASTransportIEFieldFreshMust(s43.DownlinkNASTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkS1cdma2000tunnellingIEs", func(t *testing.T) {
		downlinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t, downlinkS1cdma2000tunnellingIEFieldFreshMust(s40.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkS1cdma2000tunnellingIEFieldFreshMust(s40.DownlinkS1cdma2000tunnellingIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkUEAssociatedLPPaTransportIEs", func(t *testing.T) {
		downlinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t, downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s08.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s08.DownlinkUEAssociatedLPPaTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModificationConfirmIEs", func(t *testing.T) {
		eRABModificationConfirmIEValueRequireZeroIDSelection(t, eRABModificationConfirmIEFieldFreshMust(s40.ERABModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModificationConfirmIEFieldFreshMust(s40.ERABModificationConfirmIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModificationIndicationIEs", func(t *testing.T) {
		eRABModificationIndicationIEValueRequireZeroIDSelection(t, eRABModificationIndicationIEFieldFreshMust(s46.ERABModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModificationIndicationIEFieldFreshMust(s46.ERABModificationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModifyRequestIEs", func(t *testing.T) {
		eRABModifyRequestIEValueRequireZeroIDSelection(t, eRABModifyRequestIEFieldFreshMust(s41.ERABModifyRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModifyRequestIEFieldFreshMust(s41.ERABModifyRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModifyResponseIEs", func(t *testing.T) {
		eRABModifyResponseIEValueRequireZeroIDSelection(t, eRABModifyResponseIEFieldFreshMust(s46.ERABModifyResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModifyResponseIEFieldFreshMust(s46.ERABModifyResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseCommandIEs", func(t *testing.T) {
		eRABReleaseCommandIEValueRequireZeroIDSelection(t, eRABReleaseCommandIEFieldFreshMust(s40.ERABReleaseCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseCommandIEFieldFreshMust(s40.ERABReleaseCommandIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseIndicationIEs", func(t *testing.T) {
		eRABReleaseIndicationIEValueRequireZeroIDSelection(t, eRABReleaseIndicationIEFieldFreshMust(s46.ERABReleaseIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseIndicationIEFieldFreshMust(s46.ERABReleaseIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseResponseIEs", func(t *testing.T) {
		eRABReleaseResponseIEValueRequireZeroIDSelection(t, eRABReleaseResponseIEFieldFreshMust(s46.ERABReleaseResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseResponseIEFieldFreshMust(s46.ERABReleaseResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABSetupRequestIEs", func(t *testing.T) {
		eRABSetupRequestIEValueRequireZeroIDSelection(t, eRABSetupRequestIEFieldFreshMust(s41.ERABSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABSetupRequestIEFieldFreshMust(s41.ERABSetupRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABSetupResponseIEs", func(t *testing.T) {
		eRABSetupResponseIEValueRequireZeroIDSelection(t, eRABSetupResponseIEFieldFreshMust(s46.ERABSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABSetupResponseIEFieldFreshMust(s46.ERABSetupResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ENBEarlyStatusTransferIEs", func(t *testing.T) {
		eNBEarlyStatusTransferIEValueRequireZeroIDSelection(t, eNBEarlyStatusTransferIEFieldFreshMust(s38.ENBEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eNBEarlyStatusTransferIEFieldFreshMust(s38.ENBEarlyStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ENBStatusTransferIEs", func(t *testing.T) {
		eNBStatusTransferIEValueRequireZeroIDSelection(t, eNBStatusTransferIEFieldFreshMust(s22.ENBStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eNBStatusTransferIEFieldFreshMust(s22.ENBStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ErrorIndicationIEs", func(t *testing.T) {
		errorIndicationIEValueRequireZeroIDSelection(t, errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCancelAcknowledgeIEs", func(t *testing.T) {
		handoverCancelAcknowledgeIEValueRequireZeroIDSelection(t, handoverCancelAcknowledgeIEFieldFreshMust(s22.HandoverCancelAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCancelAcknowledgeIEFieldFreshMust(s22.HandoverCancelAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCancelIEs", func(t *testing.T) {
		handoverCancelIEValueRequireZeroIDSelection(t, handoverCancelIEFieldFreshMust(s18.HandoverCancelIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCancelIEFieldFreshMust(s18.HandoverCancelIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCommandIEs", func(t *testing.T) {
		handoverCommandIEValueRequireZeroIDSelection(t, handoverCommandIEFieldFreshMust(s41.HandoverCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCommandIEFieldFreshMust(s41.HandoverCommandIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverFailureIEs", func(t *testing.T) {
		handoverFailureIEValueRequireZeroIDSelection(t, handoverFailureIEFieldFreshMust(s22.HandoverFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverFailureIEFieldFreshMust(s22.HandoverFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverNotifyIEs", func(t *testing.T) {
		handoverNotifyIEValueRequireZeroIDSelection(t, handoverNotifyIEFieldFreshMust(s35.HandoverNotifyIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverNotifyIEFieldFreshMust(s35.HandoverNotifyIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverPreparationFailureIEs", func(t *testing.T) {
		handoverPreparationFailureIEValueRequireZeroIDSelection(t, handoverPreparationFailureIEFieldFreshMust(s22.HandoverPreparationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverPreparationFailureIEFieldFreshMust(s22.HandoverPreparationFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequestAcknowledgeIEs", func(t *testing.T) {
		handoverRequestAcknowledgeIEValueRequireZeroIDSelection(t, handoverRequestAcknowledgeIEFieldFreshMust(s39.HandoverRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequestAcknowledgeIEFieldFreshMust(s39.HandoverRequestAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequestIEs", func(t *testing.T) {
		handoverRequestIEValueRequireZeroIDSelection(t, handoverRequestIEFieldFreshMust(s49.HandoverRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequestIEFieldFreshMust(s49.HandoverRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequiredIEs", func(t *testing.T) {
		handoverRequiredIEValueRequireZeroIDSelection(t, handoverRequiredIEFieldFreshMust(s34.HandoverRequiredIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequiredIEFieldFreshMust(s34.HandoverRequiredIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverSuccessIEs", func(t *testing.T) {
		handoverSuccessIEValueRequireZeroIDSelection(t, handoverSuccessIEFieldFreshMust(s09.HandoverSuccessIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverSuccessIEFieldFreshMust(s09.HandoverSuccessIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupFailureIEs", func(t *testing.T) {
		initialContextSetupFailureIEValueRequireZeroIDSelection(t, initialContextSetupFailureIEFieldFreshMust(s23.InitialContextSetupFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupFailureIEFieldFreshMust(s23.InitialContextSetupFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupRequestIEs", func(t *testing.T) {
		initialContextSetupRequestIEValueRequireZeroIDSelection(t, initialContextSetupRequestIEFieldFreshMust(s49.InitialContextSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupRequestIEFieldFreshMust(s49.InitialContextSetupRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupResponseIEs", func(t *testing.T) {
		initialContextSetupResponseIEValueRequireZeroIDSelection(t, initialContextSetupResponseIEFieldFreshMust(s40.InitialContextSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupResponseIEFieldFreshMust(s40.InitialContextSetupResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportIEs", func(t *testing.T) {
		locationReportIEValueRequireZeroIDSelection(t, locationReportIEFieldFreshMust(s32.LocationReportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportIEFieldFreshMust(s32.LocationReportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportingControlIEs", func(t *testing.T) {
		locationReportingControlIEValueRequireZeroIDSelection(t, locationReportingControlIEFieldFreshMust(s26.LocationReportingControlIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportingControlIEFieldFreshMust(s26.LocationReportingControlIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportingFailureIndicationIEs", func(t *testing.T) {
		locationReportingFailureIndicationIEValueRequireZeroIDSelection(t, locationReportingFailureIndicationIEFieldFreshMust(s19.LocationReportingFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportingFailureIndicationIEFieldFreshMust(s19.LocationReportingFailureIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMECPRelocationIndicationIEs", func(t *testing.T) {
		mMECPRelocationIndicationIEValueRequireZeroIDSelection(t, mMECPRelocationIndicationIEFieldFreshMust(s10.MMECPRelocationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMECPRelocationIndicationIEFieldFreshMust(s10.MMECPRelocationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMEEarlyStatusTransferIEs", func(t *testing.T) {
		mMEEarlyStatusTransferIEValueRequireZeroIDSelection(t, mMEEarlyStatusTransferIEFieldFreshMust(s38.MMEEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMEEarlyStatusTransferIEFieldFreshMust(s38.MMEEarlyStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMEStatusTransferIEs", func(t *testing.T) {
		mMEStatusTransferIEValueRequireZeroIDSelection(t, mMEStatusTransferIEFieldFreshMust(s22.MMEStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMEStatusTransferIEFieldFreshMust(s22.MMEStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("NASDeliveryIndicationIEs", func(t *testing.T) {
		nASDeliveryIndicationIEValueRequireZeroIDSelection(t, nASDeliveryIndicationIEFieldFreshMust(s10.NASDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), nASDeliveryIndicationIEFieldFreshMust(s10.NASDeliveryIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("NASNonDeliveryIndicationIEs", func(t *testing.T) {
		nASNonDeliveryIndicationIEValueRequireZeroIDSelection(t, nASNonDeliveryIndicationIEFieldFreshMust(s19.NASNonDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), nASNonDeliveryIndicationIEFieldFreshMust(s19.NASNonDeliveryIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("PathSwitchRequestAcknowledgeIEs", func(t *testing.T) {
		pathSwitchRequestAcknowledgeIEValueRequireZeroIDSelection(t, pathSwitchRequestAcknowledgeIEFieldFreshMust(s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), pathSwitchRequestAcknowledgeIEFieldFreshMust(s47.PathSwitchRequestAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("PathSwitchRequestFailureIEs", func(t *testing.T) {
		pathSwitchRequestFailureIEValueRequireZeroIDSelection(t, pathSwitchRequestFailureIEFieldFreshMust(s23.PathSwitchRequestFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), pathSwitchRequestFailureIEFieldFreshMust(s23.PathSwitchRequestFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("RerouteNASRequestIEs", func(t *testing.T) {
		rerouteNASRequestIEValueRequireZeroIDSelection(t, rerouteNASRequestIEFieldFreshMust(s20.RerouteNASRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), rerouteNASRequestIEFieldFreshMust(s20.RerouteNASRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("SecondaryRATDataUsageReportIEs", func(t *testing.T) {
		secondaryRATDataUsageReportIEValueRequireZeroIDSelection(t, secondaryRATDataUsageReportIEFieldFreshMust(s46.SecondaryRATDataUsageReportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), secondaryRATDataUsageReportIEFieldFreshMust(s46.SecondaryRATDataUsageReportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("TraceFailureIndicationIEs", func(t *testing.T) {
		traceFailureIndicationIEValueRequireZeroIDSelection(t, traceFailureIndicationIEFieldFreshMust(s21.TraceFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), traceFailureIndicationIEFieldFreshMust(s21.TraceFailureIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("TraceStartIEs", func(t *testing.T) {
		traceStartIEValueRequireZeroIDSelection(t, traceStartIEFieldFreshMust(s49.TraceStartIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), traceStartIEFieldFreshMust(s49.TraceStartIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UECapabilityInfoIndicationIEs", func(t *testing.T) {
		uECapabilityInfoIndicationIEValueRequireZeroIDSelection(t, uECapabilityInfoIndicationIEFieldFreshMust(s12.UECapabilityInfoIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uECapabilityInfoIndicationIEFieldFreshMust(s12.UECapabilityInfoIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationConfirmIEs", func(t *testing.T) {
		uEContextModificationConfirmIEValueRequireZeroIDSelection(t, uEContextModificationConfirmIEFieldFreshMust(s23.UEContextModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationConfirmIEFieldFreshMust(s23.UEContextModificationConfirmIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationFailureIEs", func(t *testing.T) {
		uEContextModificationFailureIEValueRequireZeroIDSelection(t, uEContextModificationFailureIEFieldFreshMust(s23.UEContextModificationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationFailureIEFieldFreshMust(s23.UEContextModificationFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationIndicationIEs", func(t *testing.T) {
		uEContextModificationIndicationIEValueRequireZeroIDSelection(t, uEContextModificationIndicationIEFieldFreshMust(s21.UEContextModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationIndicationIEFieldFreshMust(s21.UEContextModificationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationRequestIEs", func(t *testing.T) {
		uEContextModificationRequestIEValueRequireZeroIDSelection(t, uEContextModificationRequestIEFieldFreshMust(s47.UEContextModificationRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationRequestIEFieldFreshMust(s47.UEContextModificationRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationResponseIEs", func(t *testing.T) {
		uEContextModificationResponseIEValueRequireZeroIDSelection(t, uEContextModificationResponseIEFieldFreshMust(s24.UEContextModificationResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationResponseIEFieldFreshMust(s24.UEContextModificationResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextReleaseCompleteIEs", func(t *testing.T) {
		uEContextReleaseCompleteIEValueRequireZeroIDSelection(t, uEContextReleaseCompleteIEFieldFreshMust(s46.UEContextReleaseCompleteIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextReleaseCompleteIEFieldFreshMust(s46.UEContextReleaseCompleteIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextReleaseRequestIEs", func(t *testing.T) {
		uEContextReleaseRequestIEValueRequireZeroIDSelection(t, uEContextReleaseRequestIEFieldFreshMust(s43.UEContextReleaseRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextReleaseRequestIEFieldFreshMust(s43.UEContextReleaseRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeFailureIEs", func(t *testing.T) {
		uEContextResumeFailureIEValueRequireZeroIDSelection(t, uEContextResumeFailureIEFieldFreshMust(s24.UEContextResumeFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeFailureIEFieldFreshMust(s24.UEContextResumeFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeRequestIEs", func(t *testing.T) {
		uEContextResumeRequestIEValueRequireZeroIDSelection(t, uEContextResumeRequestIEFieldFreshMust(s39.UEContextResumeRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeRequestIEFieldFreshMust(s39.UEContextResumeRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeResponseIEs", func(t *testing.T) {
		uEContextResumeResponseIEValueRequireZeroIDSelection(t, uEContextResumeResponseIEFieldFreshMust(s39.UEContextResumeResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeResponseIEFieldFreshMust(s39.UEContextResumeResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextSuspendRequestIEs", func(t *testing.T) {
		uEContextSuspendRequestIEValueRequireZeroIDSelection(t, uEContextSuspendRequestIEFieldFreshMust(s46.UEContextSuspendRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextSuspendRequestIEFieldFreshMust(s46.UEContextSuspendRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextSuspendResponseIEs", func(t *testing.T) {
		uEContextSuspendResponseIEValueRequireZeroIDSelection(t, uEContextSuspendResponseIEFieldFreshMust(s29.UEContextSuspendResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextSuspendResponseIEFieldFreshMust(s29.UEContextSuspendResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UERadioCapabilityMatchRequestIEs", func(t *testing.T) {
		uERadioCapabilityMatchRequestIEValueRequireZeroIDSelection(t, uERadioCapabilityMatchRequestIEFieldFreshMust(s12.UERadioCapabilityMatchRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uERadioCapabilityMatchRequestIEFieldFreshMust(s12.UERadioCapabilityMatchRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UERadioCapabilityMatchResponseIEs", func(t *testing.T) {
		uERadioCapabilityMatchResponseIEValueRequireZeroIDSelection(t, uERadioCapabilityMatchResponseIEFieldFreshMust(s24.UERadioCapabilityMatchResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uERadioCapabilityMatchResponseIEFieldFreshMust(s24.UERadioCapabilityMatchResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkNASTransportIEs", func(t *testing.T) {
		uplinkNASTransportIEValueRequireZeroIDSelection(t, uplinkNASTransportIEFieldFreshMust(s32.UplinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkNASTransportIEFieldFreshMust(s32.UplinkNASTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkS1cdma2000tunnellingIEs", func(t *testing.T) {
		uplinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t, uplinkS1cdma2000tunnellingIEFieldFreshMust(s21.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s21.UplinkS1cdma2000tunnellingIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkUEAssociatedLPPaTransportIEs", func(t *testing.T) {
		uplinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t, uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s12.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s12.UplinkUEAssociatedLPPaTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
}
