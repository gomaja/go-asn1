// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	strings "strings"
	testing "testing"
)

// TS 36.413 V19.2.0 §9.3.2 selects the PDU alternative; X.691 (02/2021)
// §23 selects exactly one CHOICE alternative. Validation refuses every malformed
// PDU selector state rejected by the encoder, while opaque future choices stay unchecked.
func TestValidationPDURefusalParity(t *testing.T) {
	init := initiatingMessageFreshMust(s66.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0}))
	success := successfulOutcomeFreshMust(s64.NewOpaqueSuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
	failure := unsuccessfulOutcomeFreshMust(s46.NewOpaqueUnsuccessfulOutcome(250, s00.CriticalityIgnore, []byte{0}))
	extension := choiceExtensionFreshMust(aper.NewChoiceExtension(0, []byte{0}))
	emptyExtension := aper.ChoiceExtension{}
	cases := []struct {
		name    string
		pdu     s66.S1APPDU
		refused bool
	}{
		{"initiating", s66.S1APPDU{Choice: 1, InitiatingMessage: &init}, false},
		{"successful", s66.S1APPDU{Choice: 2, SuccessfulOutcome: &success}, false},
		{"unsuccessful", s66.S1APPDU{Choice: 3, UnsuccessfulOutcome: &failure}, false},
		{"nil initiating", s66.S1APPDU{Choice: 1}, true},
		{"nil successful", s66.S1APPDU{Choice: 2}, true},
		{"nil unsuccessful", s66.S1APPDU{Choice: 3}, true},
		{"initiating and unknown", s66.S1APPDU{Choice: 1, InitiatingMessage: &init, UnknownExtension: &extension}, true},
		{"successful and unknown", s66.S1APPDU{Choice: 2, SuccessfulOutcome: &success, UnknownExtension: &extension}, true},
		{"unsuccessful and unknown", s66.S1APPDU{Choice: 3, UnsuccessfulOutcome: &failure, UnknownExtension: &extension}, true},
		{"future empty contents", s66.S1APPDU{UnknownExtension: &emptyExtension}, true},
		{"future choice", s66.S1APPDU{UnknownExtension: &extension}, false},
	}
	for _, choice := range []int{-1, 0, 4, 127} {
		cases = append(cases, struct {
			name    string
			pdu     s66.S1APPDU
			refused bool
		}{name: fmt.Sprintf("invalid %d", choice), pdu: s66.S1APPDU{Choice: choice}, refused: true})
		if choice != 0 {
			cases = append(cases, struct {
				name    string
				pdu     s66.S1APPDU
				refused bool
			}{name: fmt.Sprintf("invalid and opaque %d", choice), pdu: s66.S1APPDU{Choice: choice, UnknownExtension: &extension}, refused: true})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, encodeErr := tc.pdu.MarshalAPER()
			report, validationErr := s67.ValidateMessage(&tc.pdu)
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
	table := s27.S1SetupFailureIEs()
	cause := s1SetupFailureIEFieldFreshMust(table.Cause().New(causeFreshMust(s30.NewCauseMisc(s00.CauseMiscUnspecified))))
	for _, id := range []s00.ProtocolIEID{65532, 0} {
		t.Run(fmt.Sprintf("id-%d", id), func(t *testing.T) {
			unknown := s1SetupFailureIEFieldFreshMust(table.NewOpaque(id, s00.CriticalityIgnore, []byte{0}))
			body := s31.S1SetupFailure{ProtocolIEs: s27.S1SetupFailureIEContainer{cause, unknown, unknown}}
			report, err := s62.ValidateS1SetupFailure(&body)
			if err != nil {
				t.Fatal(err)
			}
			requireRepeatedIE(t, report, id, "[2]")
			var build *s25.BuildError
			if _, err := s62.NewS1SetupFailure(body.ProtocolIEs); !errors.As(err, &build) {
				t.Errorf("builder accepted duplicate id %d: %v", id, err)
			}
		})
	}
	extension := criticalityDiagnosticsExtIEsExtFieldFreshMust(s09.CriticalityDiagnosticsExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	value := s26.CriticalityDiagnostics{IEExtensions: s09.CriticalityDiagnosticsExtIEsExtContainer{extension, extension}}
	report := s25.ValidationReport{Complete: true}
	s61.BridgeWalkValidationCriticalityDiagnostics(&value, &report, "CriticalityDiagnostics", false)
	requireRepeatedIE(t, report, 65532, "[1]")
}
func requireRepeatedIE(t *testing.T, report s25.ValidationReport, id s00.ProtocolIEID, index string) {
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
		cellTrafficTraceIEValueRequireZeroIDSelection(t, cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ConnectionEstablishmentIndicationIEs", func(t *testing.T) {
		connectionEstablishmentIndicationIEValueRequireZeroIDSelection(t, connectionEstablishmentIndicationIEFieldFreshMust(s39.ConnectionEstablishmentIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), connectionEstablishmentIndicationIEFieldFreshMust(s39.ConnectionEstablishmentIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DeactivateTraceIEs", func(t *testing.T) {
		deactivateTraceIEValueRequireZeroIDSelection(t, deactivateTraceIEFieldFreshMust(s09.DeactivateTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), deactivateTraceIEFieldFreshMust(s09.DeactivateTraceIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkNASTransportIEs", func(t *testing.T) {
		downlinkNASTransportIEValueRequireZeroIDSelection(t, downlinkNASTransportIEFieldFreshMust(s53.DownlinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkNASTransportIEFieldFreshMust(s53.DownlinkNASTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkS1cdma2000tunnellingIEs", func(t *testing.T) {
		downlinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t, downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("DownlinkUEAssociatedLPPaTransportIEs", func(t *testing.T) {
		downlinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t, downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModificationConfirmIEs", func(t *testing.T) {
		eRABModificationConfirmIEValueRequireZeroIDSelection(t, eRABModificationConfirmIEFieldFreshMust(s49.ERABModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModificationConfirmIEFieldFreshMust(s49.ERABModificationConfirmIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModificationIndicationIEs", func(t *testing.T) {
		eRABModificationIndicationIEValueRequireZeroIDSelection(t, eRABModificationIndicationIEFieldFreshMust(s57.ERABModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModificationIndicationIEFieldFreshMust(s57.ERABModificationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModifyRequestIEs", func(t *testing.T) {
		eRABModifyRequestIEValueRequireZeroIDSelection(t, eRABModifyRequestIEFieldFreshMust(s51.ERABModifyRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModifyRequestIEFieldFreshMust(s51.ERABModifyRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABModifyResponseIEs", func(t *testing.T) {
		eRABModifyResponseIEValueRequireZeroIDSelection(t, eRABModifyResponseIEFieldFreshMust(s57.ERABModifyResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABModifyResponseIEFieldFreshMust(s57.ERABModifyResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseCommandIEs", func(t *testing.T) {
		eRABReleaseCommandIEValueRequireZeroIDSelection(t, eRABReleaseCommandIEFieldFreshMust(s49.ERABReleaseCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseCommandIEFieldFreshMust(s49.ERABReleaseCommandIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseIndicationIEs", func(t *testing.T) {
		eRABReleaseIndicationIEValueRequireZeroIDSelection(t, eRABReleaseIndicationIEFieldFreshMust(s57.ERABReleaseIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseIndicationIEFieldFreshMust(s57.ERABReleaseIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABReleaseResponseIEs", func(t *testing.T) {
		eRABReleaseResponseIEValueRequireZeroIDSelection(t, eRABReleaseResponseIEFieldFreshMust(s57.ERABReleaseResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABReleaseResponseIEFieldFreshMust(s57.ERABReleaseResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABSetupRequestIEs", func(t *testing.T) {
		eRABSetupRequestIEValueRequireZeroIDSelection(t, eRABSetupRequestIEFieldFreshMust(s51.ERABSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABSetupRequestIEFieldFreshMust(s51.ERABSetupRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ERABSetupResponseIEs", func(t *testing.T) {
		eRABSetupResponseIEValueRequireZeroIDSelection(t, eRABSetupResponseIEFieldFreshMust(s57.ERABSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eRABSetupResponseIEFieldFreshMust(s57.ERABSetupResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ENBEarlyStatusTransferIEs", func(t *testing.T) {
		eNBEarlyStatusTransferIEValueRequireZeroIDSelection(t, eNBEarlyStatusTransferIEFieldFreshMust(s47.ENBEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eNBEarlyStatusTransferIEFieldFreshMust(s47.ENBEarlyStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ENBStatusTransferIEs", func(t *testing.T) {
		eNBStatusTransferIEValueRequireZeroIDSelection(t, eNBStatusTransferIEFieldFreshMust(s25.ENBStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), eNBStatusTransferIEFieldFreshMust(s25.ENBStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("ErrorIndicationIEs", func(t *testing.T) {
		errorIndicationIEValueRequireZeroIDSelection(t, errorIndicationIEFieldFreshMust(s36.ErrorIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), errorIndicationIEFieldFreshMust(s36.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCancelAcknowledgeIEs", func(t *testing.T) {
		handoverCancelAcknowledgeIEValueRequireZeroIDSelection(t, handoverCancelAcknowledgeIEFieldFreshMust(s26.HandoverCancelAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCancelAcknowledgeIEFieldFreshMust(s26.HandoverCancelAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCancelIEs", func(t *testing.T) {
		handoverCancelIEValueRequireZeroIDSelection(t, handoverCancelIEFieldFreshMust(s21.HandoverCancelIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCancelIEFieldFreshMust(s21.HandoverCancelIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverCommandIEs", func(t *testing.T) {
		handoverCommandIEValueRequireZeroIDSelection(t, handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverFailureIEs", func(t *testing.T) {
		handoverFailureIEValueRequireZeroIDSelection(t, handoverFailureIEFieldFreshMust(s26.HandoverFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverFailureIEFieldFreshMust(s26.HandoverFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverNotifyIEs", func(t *testing.T) {
		handoverNotifyIEValueRequireZeroIDSelection(t, handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverPreparationFailureIEs", func(t *testing.T) {
		handoverPreparationFailureIEValueRequireZeroIDSelection(t, handoverPreparationFailureIEFieldFreshMust(s26.HandoverPreparationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverPreparationFailureIEFieldFreshMust(s26.HandoverPreparationFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequestAcknowledgeIEs", func(t *testing.T) {
		handoverRequestAcknowledgeIEValueRequireZeroIDSelection(t, handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequestIEs", func(t *testing.T) {
		handoverRequestIEValueRequireZeroIDSelection(t, handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverRequiredIEs", func(t *testing.T) {
		handoverRequiredIEValueRequireZeroIDSelection(t, handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("HandoverSuccessIEs", func(t *testing.T) {
		handoverSuccessIEValueRequireZeroIDSelection(t, handoverSuccessIEFieldFreshMust(s11.HandoverSuccessIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), handoverSuccessIEFieldFreshMust(s11.HandoverSuccessIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupFailureIEs", func(t *testing.T) {
		initialContextSetupFailureIEValueRequireZeroIDSelection(t, initialContextSetupFailureIEFieldFreshMust(s26.InitialContextSetupFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupFailureIEFieldFreshMust(s26.InitialContextSetupFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupRequestIEs", func(t *testing.T) {
		initialContextSetupRequestIEValueRequireZeroIDSelection(t, initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("InitialContextSetupResponseIEs", func(t *testing.T) {
		initialContextSetupResponseIEValueRequireZeroIDSelection(t, initialContextSetupResponseIEFieldFreshMust(s50.InitialContextSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), initialContextSetupResponseIEFieldFreshMust(s50.InitialContextSetupResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportIEs", func(t *testing.T) {
		locationReportIEValueRequireZeroIDSelection(t, locationReportIEFieldFreshMust(s41.LocationReportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportIEFieldFreshMust(s41.LocationReportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportingControlIEs", func(t *testing.T) {
		locationReportingControlIEValueRequireZeroIDSelection(t, locationReportingControlIEFieldFreshMust(s31.LocationReportingControlIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportingControlIEFieldFreshMust(s31.LocationReportingControlIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("LocationReportingFailureIndicationIEs", func(t *testing.T) {
		locationReportingFailureIndicationIEValueRequireZeroIDSelection(t, locationReportingFailureIndicationIEFieldFreshMust(s22.LocationReportingFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), locationReportingFailureIndicationIEFieldFreshMust(s22.LocationReportingFailureIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMECPRelocationIndicationIEs", func(t *testing.T) {
		mMECPRelocationIndicationIEValueRequireZeroIDSelection(t, mMECPRelocationIndicationIEFieldFreshMust(s12.MMECPRelocationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMECPRelocationIndicationIEFieldFreshMust(s12.MMECPRelocationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMEEarlyStatusTransferIEs", func(t *testing.T) {
		mMEEarlyStatusTransferIEValueRequireZeroIDSelection(t, mMEEarlyStatusTransferIEFieldFreshMust(s47.MMEEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMEEarlyStatusTransferIEFieldFreshMust(s47.MMEEarlyStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("MMEStatusTransferIEs", func(t *testing.T) {
		mMEStatusTransferIEValueRequireZeroIDSelection(t, mMEStatusTransferIEFieldFreshMust(s25.MMEStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), mMEStatusTransferIEFieldFreshMust(s25.MMEStatusTransferIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("NASDeliveryIndicationIEs", func(t *testing.T) {
		nASDeliveryIndicationIEValueRequireZeroIDSelection(t, nASDeliveryIndicationIEFieldFreshMust(s12.NASDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), nASDeliveryIndicationIEFieldFreshMust(s12.NASDeliveryIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("NASNonDeliveryIndicationIEs", func(t *testing.T) {
		nASNonDeliveryIndicationIEValueRequireZeroIDSelection(t, nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("PathSwitchRequestAcknowledgeIEs", func(t *testing.T) {
		pathSwitchRequestAcknowledgeIEValueRequireZeroIDSelection(t, pathSwitchRequestAcknowledgeIEFieldFreshMust(s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), pathSwitchRequestAcknowledgeIEFieldFreshMust(s58.PathSwitchRequestAcknowledgeIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("PathSwitchRequestFailureIEs", func(t *testing.T) {
		pathSwitchRequestFailureIEValueRequireZeroIDSelection(t, pathSwitchRequestFailureIEFieldFreshMust(s27.PathSwitchRequestFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), pathSwitchRequestFailureIEFieldFreshMust(s27.PathSwitchRequestFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("RerouteNASRequestIEs", func(t *testing.T) {
		rerouteNASRequestIEValueRequireZeroIDSelection(t, rerouteNASRequestIEFieldFreshMust(s24.RerouteNASRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), rerouteNASRequestIEFieldFreshMust(s24.RerouteNASRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("SecondaryRATDataUsageReportIEs", func(t *testing.T) {
		secondaryRATDataUsageReportIEValueRequireZeroIDSelection(t, secondaryRATDataUsageReportIEFieldFreshMust(s57.SecondaryRATDataUsageReportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), secondaryRATDataUsageReportIEFieldFreshMust(s57.SecondaryRATDataUsageReportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("TraceFailureIndicationIEs", func(t *testing.T) {
		traceFailureIndicationIEValueRequireZeroIDSelection(t, traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("TraceStartIEs", func(t *testing.T) {
		traceStartIEValueRequireZeroIDSelection(t, traceStartIEFieldFreshMust(s60.TraceStartIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), traceStartIEFieldFreshMust(s60.TraceStartIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UECapabilityInfoIndicationIEs", func(t *testing.T) {
		uECapabilityInfoIndicationIEValueRequireZeroIDSelection(t, uECapabilityInfoIndicationIEFieldFreshMust(s14.UECapabilityInfoIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uECapabilityInfoIndicationIEFieldFreshMust(s14.UECapabilityInfoIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationConfirmIEs", func(t *testing.T) {
		uEContextModificationConfirmIEValueRequireZeroIDSelection(t, uEContextModificationConfirmIEFieldFreshMust(s27.UEContextModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationConfirmIEFieldFreshMust(s27.UEContextModificationConfirmIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationFailureIEs", func(t *testing.T) {
		uEContextModificationFailureIEValueRequireZeroIDSelection(t, uEContextModificationFailureIEFieldFreshMust(s27.UEContextModificationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationFailureIEFieldFreshMust(s27.UEContextModificationFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationIndicationIEs", func(t *testing.T) {
		uEContextModificationIndicationIEValueRequireZeroIDSelection(t, uEContextModificationIndicationIEFieldFreshMust(s24.UEContextModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationIndicationIEFieldFreshMust(s24.UEContextModificationIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationRequestIEs", func(t *testing.T) {
		uEContextModificationRequestIEValueRequireZeroIDSelection(t, uEContextModificationRequestIEFieldFreshMust(s58.UEContextModificationRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationRequestIEFieldFreshMust(s58.UEContextModificationRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextModificationResponseIEs", func(t *testing.T) {
		uEContextModificationResponseIEValueRequireZeroIDSelection(t, uEContextModificationResponseIEFieldFreshMust(s27.UEContextModificationResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextModificationResponseIEFieldFreshMust(s27.UEContextModificationResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextReleaseCompleteIEs", func(t *testing.T) {
		uEContextReleaseCompleteIEValueRequireZeroIDSelection(t, uEContextReleaseCompleteIEFieldFreshMust(s57.UEContextReleaseCompleteIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextReleaseCompleteIEFieldFreshMust(s57.UEContextReleaseCompleteIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextReleaseRequestIEs", func(t *testing.T) {
		uEContextReleaseRequestIEValueRequireZeroIDSelection(t, uEContextReleaseRequestIEFieldFreshMust(s53.UEContextReleaseRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextReleaseRequestIEFieldFreshMust(s53.UEContextReleaseRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeFailureIEs", func(t *testing.T) {
		uEContextResumeFailureIEValueRequireZeroIDSelection(t, uEContextResumeFailureIEFieldFreshMust(s28.UEContextResumeFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeFailureIEFieldFreshMust(s28.UEContextResumeFailureIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeRequestIEs", func(t *testing.T) {
		uEContextResumeRequestIEValueRequireZeroIDSelection(t, uEContextResumeRequestIEFieldFreshMust(s48.UEContextResumeRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeRequestIEFieldFreshMust(s48.UEContextResumeRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextResumeResponseIEs", func(t *testing.T) {
		uEContextResumeResponseIEValueRequireZeroIDSelection(t, uEContextResumeResponseIEFieldFreshMust(s49.UEContextResumeResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextResumeResponseIEFieldFreshMust(s49.UEContextResumeResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextSuspendRequestIEs", func(t *testing.T) {
		uEContextSuspendRequestIEValueRequireZeroIDSelection(t, uEContextSuspendRequestIEFieldFreshMust(s57.UEContextSuspendRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextSuspendRequestIEFieldFreshMust(s57.UEContextSuspendRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UEContextSuspendResponseIEs", func(t *testing.T) {
		uEContextSuspendResponseIEValueRequireZeroIDSelection(t, uEContextSuspendResponseIEFieldFreshMust(s37.UEContextSuspendResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uEContextSuspendResponseIEFieldFreshMust(s37.UEContextSuspendResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UERadioCapabilityMatchRequestIEs", func(t *testing.T) {
		uERadioCapabilityMatchRequestIEValueRequireZeroIDSelection(t, uERadioCapabilityMatchRequestIEFieldFreshMust(s14.UERadioCapabilityMatchRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uERadioCapabilityMatchRequestIEFieldFreshMust(s14.UERadioCapabilityMatchRequestIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UERadioCapabilityMatchResponseIEs", func(t *testing.T) {
		uERadioCapabilityMatchResponseIEValueRequireZeroIDSelection(t, uERadioCapabilityMatchResponseIEFieldFreshMust(s28.UERadioCapabilityMatchResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uERadioCapabilityMatchResponseIEFieldFreshMust(s28.UERadioCapabilityMatchResponseIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkNASTransportIEs", func(t *testing.T) {
		uplinkNASTransportIEValueRequireZeroIDSelection(t, uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkS1cdma2000tunnellingIEs", func(t *testing.T) {
		uplinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t, uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
	t.Run("UplinkUEAssociatedLPPaTransportIEs", func(t *testing.T) {
		uplinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t, uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(1))), uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})))
	})
}
