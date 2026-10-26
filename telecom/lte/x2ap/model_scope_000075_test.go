// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// TS 36.423 V19.1.0 §9.3.3: all 110 available bodies, constructed
// from minimal source-allowed IE sets; golden bytes use an independent encoder.
func TestEveryProcedureFreshConstruction(t *testing.T) {
	t.Run("HandoverRequest", func(t *testing.T) {
		var fields s18.HandoverRequestIEContainer
		v0, _, err0 := s18.HandoverRequestIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s18.HandoverRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().Cause().New(v1.Value)))
		v2, _, err2 := s18.HandoverRequestIEs().TargetCellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().TargetCellID().New(v2.Value)))
		v3, _, err3 := s18.HandoverRequestIEs().GUMMEIID().Codec().DecodeAPER(freshHex("00000000000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().GUMMEIID().New(v3.Value)))
		v4, _, err4 := s18.HandoverRequestIEs().UEContextInformation().Codec().DecodeAPER(freshHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004400b000000000000000000000000"))
		if err4 != nil {
			t.Fatal(err4)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().UEContextInformation().New(v4.Value)))
		v5, _, err5 := s18.HandoverRequestIEs().UEHistoryInformation().Codec().DecodeAPER(freshHex("000000000000000000000000"))
		if err5 != nil {
			t.Fatal(err5)
		}
		fields = append(fields, handoverRequestIEFieldfreshMust(s18.HandoverRequestIEs().UEHistoryInformation().New(v5.Value)))
		body := handoverRequestfreshMust(s19.NewHandoverRequest(fields))
		env := initiatingMessagefreshMust(s19.HandoverPreparationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00000076000006000a00020000000540020000000b000800000000000000000017000700000000000000000e003c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004400b000000000000000000000000000f400c000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("HandoverRequestAcknowledge", func(t *testing.T) {
		var fields s14.HandoverRequestAcknowledgeIEContainer
		v0, _, err0 := s14.HandoverRequestAcknowledgeIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverRequestAcknowledgeIEFieldfreshMust(s14.HandoverRequestAcknowledgeIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s14.HandoverRequestAcknowledgeIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverRequestAcknowledgeIEFieldfreshMust(s14.HandoverRequestAcknowledgeIEs().NewENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s14.HandoverRequestAcknowledgeIEs().ERABsAdmittedList().Codec().DecodeAPER(freshHex("00000040020000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, handoverRequestAcknowledgeIEFieldfreshMust(s14.HandoverRequestAcknowledgeIEs().ERABsAdmittedList().New(v2.Value)))
		v3, _, err3 := s14.HandoverRequestAcknowledgeIEs().TargeteNBtoSourceENBTransparentContainer().Codec().DecodeAPER(freshHex("00"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, handoverRequestAcknowledgeIEFieldfreshMust(s14.HandoverRequestAcknowledgeIEs().TargeteNBtoSourceENBTransparentContainer().New(v3.Value)))
		body := handoverRequestAcknowledgefreshMust(s19.NewHandoverRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.HandoverPreparationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2000001f000004000a400200000009400200000001400700000040020000000c400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("HandoverPreparationFailure", func(t *testing.T) {
		var fields s11.HandoverPreparationFailureIEContainer
		v0, _, err0 := s11.HandoverPreparationFailureIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverPreparationFailureIEFieldfreshMust(s11.HandoverPreparationFailureIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.HandoverPreparationFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverPreparationFailureIEFieldfreshMust(s11.HandoverPreparationFailureIEs().Cause().New(v1.Value)))
		body := handoverPreparationFailurefreshMust(s14.NewHandoverPreparationFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.HandoverPreparationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("4000000f000002000a40020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SNStatusTransfer", func(t *testing.T) {
		var fields s15.SNStatusTransferIEContainer
		v0, _, err0 := s15.SNStatusTransferIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sNStatusTransferIEFieldfreshMust(s15.SNStatusTransferIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SNStatusTransferIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sNStatusTransferIEFieldfreshMust(s15.SNStatusTransferIEs().NewENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.SNStatusTransferIEs().ERABsSubjectToStatusTransferList().Codec().DecodeAPER(freshHex("000013400b0000000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sNStatusTransferIEFieldfreshMust(s15.SNStatusTransferIEs().ERABsSubjectToStatusTransferList().New(v2.Value)))
		body := sNStatusTransferfreshMust(s19.NewSNStatusTransfer(fields))
		env := initiatingMessagefreshMust(s19.SnStatusTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00044023000003000a0002000000090002000000124010000013400b0000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("UEContextRelease", func(t *testing.T) {
		var fields s12.UEContextReleaseIEContainer
		v0, _, err0 := s12.UEContextReleaseIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, uEContextReleaseIEFieldfreshMust(s12.UEContextReleaseIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.UEContextReleaseIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, uEContextReleaseIEFieldfreshMust(s12.UEContextReleaseIEs().NewENBUEX2APID().New(v1.Value)))
		body := uEContextReleasefreshMust(s20.NewUEContextRelease(fields))
		env := initiatingMessagefreshMust(s20.UEContextReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0005400f000002000a00020000000900020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("HandoverCancel", func(t *testing.T) {
		var fields s14.HandoverCancelIEContainer
		v0, _, err0 := s14.HandoverCancelIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverCancelIEFieldfreshMust(s14.HandoverCancelIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s14.HandoverCancelIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverCancelIEFieldfreshMust(s14.HandoverCancelIEs().Cause().New(v1.Value)))
		body := handoverCancelfreshMust(s19.NewHandoverCancel(fields))
		env := initiatingMessagefreshMust(s19.HandoverCancelProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0001400f000002000a00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("HandoverReport", func(t *testing.T) {
		var fields s11.HandoverReportIEContainer
		v0, _, err0 := s11.HandoverReportIEs().HandoverReportType().Codec().DecodeAPER(freshHex("00"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverReportIEFieldfreshMust(s11.HandoverReportIEs().HandoverReportType().New(v0.Value)))
		v1, _, err1 := s11.HandoverReportIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverReportIEFieldfreshMust(s11.HandoverReportIEs().Cause().New(v1.Value)))
		v2, _, err2 := s11.HandoverReportIEs().SourceCellECGI().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, handoverReportIEFieldfreshMust(s11.HandoverReportIEs().SourceCellECGI().New(v2.Value)))
		v3, _, err3 := s11.HandoverReportIEs().FailureCellECGI().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, handoverReportIEFieldfreshMust(s11.HandoverReportIEs().FailureCellECGI().New(v3.Value)))
		body := handoverReportfreshMust(s19.NewHandoverReport(fields))
		env := initiatingMessagefreshMust(s19.HandoverReportProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000e40260000040036400100000540020000003440080000000000000000003540080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ErrorIndication", func(t *testing.T) {
		var fields s11.ErrorIndicationIEContainer
		body := errorIndicationfreshMust(s19.NewErrorIndication(fields))
		env := initiatingMessagefreshMust(s19.ErrorIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00034003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResetRequest", func(t *testing.T) {
		var fields s07.ResetRequestIEContainer
		v0, _, err0 := s07.ResetRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, resetRequestIEFieldfreshMust(s07.ResetRequestIEs().Cause().New(v0.Value)))
		body := resetRequestfreshMust(s19.NewResetRequest(fields))
		env := initiatingMessagefreshMust(s19.ResetProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00070009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResetResponse", func(t *testing.T) {
		var fields s07.ResetResponseIEContainer
		body := resetResponsefreshMust(s19.NewResetResponse(fields))
		env := successfulOutcomefreshMust(s19.ResetProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20070003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2SetupRequest", func(t *testing.T) {
		var fields s17.X2SetupRequestIEContainer
		v0, _, err0 := s17.X2SetupRequestIEs().GlobalENBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2SetupRequestIEFieldfreshMust(s17.X2SetupRequestIEs().GlobalENBID().New(v0.Value)))
		v1, _, err1 := s17.X2SetupRequestIEs().ServedCells().Codec().DecodeAPER(freshHex("0000000000000000000000000000000000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, x2SetupRequestIEFieldfreshMust(s17.X2SetupRequestIEs().ServedCells().New(v1.Value)))
		body := x2SetupRequestfreshMust(s20.NewX2SetupRequest(fields))
		env := initiatingMessagefreshMust(s20.X2SetupProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0006002a000002001500080000000000000000001400170000000000000000000000000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2SetupResponse", func(t *testing.T) {
		var fields s17.X2SetupResponseIEContainer
		v0, _, err0 := s17.X2SetupResponseIEs().GlobalENBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2SetupResponseIEFieldfreshMust(s17.X2SetupResponseIEs().GlobalENBID().New(v0.Value)))
		v1, _, err1 := s17.X2SetupResponseIEs().ServedCells().Codec().DecodeAPER(freshHex("0000000000000000000000000000000000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, x2SetupResponseIEFieldfreshMust(s17.X2SetupResponseIEs().ServedCells().New(v1.Value)))
		body := x2SetupResponsefreshMust(s20.NewX2SetupResponse(fields))
		env := successfulOutcomefreshMust(s20.X2SetupProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2006002a000002001500080000000000000000001400170000000000000000000000000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2SetupFailure", func(t *testing.T) {
		var fields s07.X2SetupFailureIEContainer
		v0, _, err0 := s07.X2SetupFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2SetupFailureIEFieldfreshMust(s07.X2SetupFailureIEs().Cause().New(v0.Value)))
		body := x2SetupFailurefreshMust(s14.NewX2SetupFailure(fields))
		env := unsuccessfulOutcomefreshMust(s20.X2SetupProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40060009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("LoadInformation", func(t *testing.T) {
		var fields s14.LoadInformationIEContainer
		v0, _, err0 := s14.LoadInformationIEs().CellInformation().Codec().DecodeAPER(freshHex("00000740080000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, loadInformationIEFieldfreshMust(s14.LoadInformationIEs().CellInformation().New(v0.Value)))
		body := loadInformationfreshMust(s19.NewLoadInformation(fields))
		env := initiatingMessagefreshMust(s19.LoadIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000240140000010006400d00000740080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENBConfigurationUpdate", func(t *testing.T) {
		var fields s17.ENBConfigurationUpdateIEContainer
		body := eNBConfigurationUpdatefreshMust(s19.NewENBConfigurationUpdate(fields))
		env := initiatingMessagefreshMust(s19.ENBConfigurationUpdateProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00080003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENBConfigurationUpdateAcknowledge", func(t *testing.T) {
		var fields s06.ENBConfigurationUpdateAcknowledgeIEContainer
		body := eNBConfigurationUpdateAcknowledgefreshMust(s19.NewENBConfigurationUpdateAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.ENBConfigurationUpdateProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20080003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENBConfigurationUpdateFailure", func(t *testing.T) {
		var fields s06.ENBConfigurationUpdateFailureIEContainer
		v0, _, err0 := s06.ENBConfigurationUpdateFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNBConfigurationUpdateFailureIEFieldfreshMust(s06.ENBConfigurationUpdateFailureIEs().Cause().New(v0.Value)))
		body := eNBConfigurationUpdateFailurefreshMust(s14.NewENBConfigurationUpdateFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.ENBConfigurationUpdateProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40080009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResourceStatusRequest", func(t *testing.T) {
		var fields s14.ResourceStatusRequestIEContainer
		v0, _, err0 := s14.ResourceStatusRequestIEs().ENB1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, resourceStatusRequestIEFieldfreshMust(s14.ResourceStatusRequestIEs().ENB1MeasurementID().New(v0.Value)))
		v1, _, err1 := s14.ResourceStatusRequestIEs().RegistrationRequest().Codec().DecodeAPER(freshHex("00"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, resourceStatusRequestIEFieldfreshMust(s14.ResourceStatusRequestIEs().RegistrationRequest().New(v1.Value)))
		v2, _, err2 := s14.ResourceStatusRequestIEs().CellToReport().Codec().DecodeAPER(freshHex("00001f40080000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, resourceStatusRequestIEFieldfreshMust(s14.ResourceStatusRequestIEs().CellToReport().New(v2.Value)))
		body := resourceStatusRequestfreshMust(s19.NewResourceStatusRequest(fields))
		env := initiatingMessagefreshMust(s19.ResourceStatusReportingInitiationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0009002000000300270003000000001c000100001d400d00001f40080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResourceStatusResponse", func(t *testing.T) {
		var fields s16.ResourceStatusResponseIEContainer
		v0, _, err0 := s16.ResourceStatusResponseIEs().ENB1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, resourceStatusResponseIEFieldfreshMust(s16.ResourceStatusResponseIEs().ENB1MeasurementID().New(v0.Value)))
		v1, _, err1 := s16.ResourceStatusResponseIEs().ENB2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, resourceStatusResponseIEFieldfreshMust(s16.ResourceStatusResponseIEs().ENB2MeasurementID().New(v1.Value)))
		body := resourceStatusResponsefreshMust(s19.NewResourceStatusResponse(fields))
		env := successfulOutcomefreshMust(s19.ResourceStatusReportingInitiationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("200900110000020027000300000000280003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResourceStatusFailure", func(t *testing.T) {
		var fields s14.ResourceStatusFailureIEContainer
		v0, _, err0 := s14.ResourceStatusFailureIEs().ENB1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, resourceStatusFailureIEFieldfreshMust(s14.ResourceStatusFailureIEs().ENB1MeasurementID().New(v0.Value)))
		v1, _, err1 := s14.ResourceStatusFailureIEs().ENB2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, resourceStatusFailureIEFieldfreshMust(s14.ResourceStatusFailureIEs().ENB2MeasurementID().New(v1.Value)))
		v2, _, err2 := s14.ResourceStatusFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, resourceStatusFailureIEFieldfreshMust(s14.ResourceStatusFailureIEs().Cause().New(v2.Value)))
		body := resourceStatusFailurefreshMust(s14.NewResourceStatusFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.ResourceStatusReportingInitiationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("400900170000030027000300000000280003000000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ResourceStatusUpdate", func(t *testing.T) {
		var fields s17.ResourceStatusUpdateIEContainer
		v0, _, err0 := s17.ResourceStatusUpdateIEs().ENB1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, resourceStatusUpdateIEFieldfreshMust(s17.ResourceStatusUpdateIEs().ENB1MeasurementID().New(v0.Value)))
		v1, _, err1 := s17.ResourceStatusUpdateIEs().ENB2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, resourceStatusUpdateIEFieldfreshMust(s17.ResourceStatusUpdateIEs().ENB2MeasurementID().New(v1.Value)))
		v2, _, err2 := s17.ResourceStatusUpdateIEs().CellMeasurementResult().Codec().DecodeAPER(freshHex("00002140080000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, resourceStatusUpdateIEFieldfreshMust(s17.ResourceStatusUpdateIEs().CellMeasurementResult().New(v2.Value)))
		body := resourceStatusUpdatefreshMust(s19.NewResourceStatusUpdate(fields))
		env := initiatingMessagefreshMust(s19.ResourceStatusReportingProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000a402200000300270003000000002800030000000020400d00002140080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RLFIndication", func(t *testing.T) {
		var fields s11.RLFIndicationIEContainer
		v0, _, err0 := s11.RLFIndicationIEs().FailureCellPCI().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, rLFIndicationIEFieldfreshMust(s11.RLFIndicationIEs().FailureCellPCI().New(v0.Value)))
		v1, _, err1 := s11.RLFIndicationIEs().ReEstablishmentCellECGI().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, rLFIndicationIEFieldfreshMust(s11.RLFIndicationIEs().ReEstablishmentCellECGI().New(v1.Value)))
		v2, _, err2 := s11.RLFIndicationIEs().FailureCellCRNTI().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, rLFIndicationIEFieldfreshMust(s11.RLFIndicationIEs().FailureCellCRNTI().New(v2.Value)))
		body := rLFIndicationfreshMust(s19.NewRLFIndication(fields))
		env := initiatingMessagefreshMust(s19.RLFIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000d401c00000300304003000000003140080000000000000000003240020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("PrivateMessage", func(t *testing.T) {
		body := privateMessagefreshMust(s19.NewPrivateMessage(s00.PrivateMessageIEsValuePrivateIEContainer{privateMessageIEsValuePrivateIEFieldfreshMust(s00.PrivateMessageIEs().NewOpaque(privateIEIDfreshMust(s00.NewPrivateIEIDLocal(1)), s00.CriticalityIgnore, []byte{0}))}))
		env := initiatingMessagefreshMust(s19.PrivateMessageProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000b4009000000000001400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("MobilityChangeRequest", func(t *testing.T) {
		var fields s07.MobilityChangeRequestIEContainer
		v0, _, err0 := s07.MobilityChangeRequestIEs().ENB1CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, mobilityChangeRequestIEFieldfreshMust(s07.MobilityChangeRequestIEs().ENB1CellID().New(v0.Value)))
		v1, _, err1 := s07.MobilityChangeRequestIEs().ENB2CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, mobilityChangeRequestIEFieldfreshMust(s07.MobilityChangeRequestIEs().ENB2CellID().New(v1.Value)))
		v2, _, err2 := s07.MobilityChangeRequestIEs().ENB2ProposedMobilityParameters().Codec().DecodeAPER(freshHex("00"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, mobilityChangeRequestIEFieldfreshMust(s07.MobilityChangeRequestIEs().ENB2ProposedMobilityParameters().New(v2.Value)))
		v3, _, err3 := s07.MobilityChangeRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, mobilityChangeRequestIEFieldfreshMust(s07.MobilityChangeRequestIEs().Cause().New(v3.Value)))
		body := mobilityChangeRequestfreshMust(s19.NewMobilityChangeRequest(fields))
		env := initiatingMessagefreshMust(s19.MobilitySettingsChangeProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000c0026000004002b00080000000000000000002c00080000000000000000002d000100000500020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("MobilityChangeAcknowledge", func(t *testing.T) {
		var fields s07.MobilityChangeAcknowledgeIEContainer
		v0, _, err0 := s07.MobilityChangeAcknowledgeIEs().ENB1CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, mobilityChangeAcknowledgeIEFieldfreshMust(s07.MobilityChangeAcknowledgeIEs().ENB1CellID().New(v0.Value)))
		v1, _, err1 := s07.MobilityChangeAcknowledgeIEs().ENB2CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, mobilityChangeAcknowledgeIEFieldfreshMust(s07.MobilityChangeAcknowledgeIEs().ENB2CellID().New(v1.Value)))
		body := mobilityChangeAcknowledgefreshMust(s19.NewMobilityChangeAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.MobilitySettingsChangeProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("200c001b000002002b00080000000000000000002c00080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("MobilityChangeFailure", func(t *testing.T) {
		var fields s07.MobilityChangeFailureIEContainer
		v0, _, err0 := s07.MobilityChangeFailureIEs().ENB1CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, mobilityChangeFailureIEFieldfreshMust(s07.MobilityChangeFailureIEs().ENB1CellID().New(v0.Value)))
		v1, _, err1 := s07.MobilityChangeFailureIEs().ENB2CellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, mobilityChangeFailureIEFieldfreshMust(s07.MobilityChangeFailureIEs().ENB2CellID().New(v1.Value)))
		v2, _, err2 := s07.MobilityChangeFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, mobilityChangeFailureIEFieldfreshMust(s07.MobilityChangeFailureIEs().Cause().New(v2.Value)))
		body := mobilityChangeFailurefreshMust(s14.NewMobilityChangeFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.MobilitySettingsChangeProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("400c0021000003002b40080000000000000000002c40080000000000000000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("CellActivationRequest", func(t *testing.T) {
		var fields s17.CellActivationRequestIEContainer
		v0, _, err0 := s17.CellActivationRequestIEs().ServedCellsToActivate().Codec().DecodeAPER(freshHex("000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, cellActivationRequestIEFieldfreshMust(s17.CellActivationRequestIEs().ServedCellsToActivate().New(v0.Value)))
		body := cellActivationRequestfreshMust(s19.NewCellActivationRequest(fields))
		env := initiatingMessagefreshMust(s19.CellActivationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("000f001000000100390009000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("CellActivationResponse", func(t *testing.T) {
		var fields s13.CellActivationResponseIEContainer
		v0, _, err0 := s13.CellActivationResponseIEs().ActivatedCellList().Codec().DecodeAPER(freshHex("000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, cellActivationResponseIEFieldfreshMust(s13.CellActivationResponseIEs().ActivatedCellList().New(v0.Value)))
		body := cellActivationResponsefreshMust(s19.NewCellActivationResponse(fields))
		env := successfulOutcomefreshMust(s19.CellActivationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("200f0010000001003a4009000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("CellActivationFailure", func(t *testing.T) {
		var fields s06.CellActivationFailureIEContainer
		v0, _, err0 := s06.CellActivationFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, cellActivationFailureIEFieldfreshMust(s06.CellActivationFailureIEs().Cause().New(v0.Value)))
		body := cellActivationFailurefreshMust(s14.NewCellActivationFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.CellActivationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("400f0009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2Release", func(t *testing.T) {
		var fields s07.X2ReleaseIEContainer
		v0, _, err0 := s07.X2ReleaseIEs().GlobalENBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2ReleaseIEFieldfreshMust(s07.X2ReleaseIEs().GlobalENBID().New(v0.Value)))
		body := x2ReleasefreshMust(s20.NewX2Release(fields))
		env := initiatingMessagefreshMust(s20.X2ReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0010000f000001001500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2APMessageTransfer", func(t *testing.T) {
		var fields s13.X2APMessageTransferIEContainer
		v0, _, err0 := s13.X2APMessageTransferIEs().RNLHeader().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2APMessageTransferIEFieldfreshMust(s13.X2APMessageTransferIEs().RNLHeader().New(v0.Value)))
		body := x2APMessageTransferfreshMust(s20.NewX2APMessageTransfer(fields))
		env := initiatingMessagefreshMust(s20.X2APMessageTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0011000f000001006500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBAdditionRequest", func(t *testing.T) {
		var fields s15.SeNBAdditionRequestIEContainer
		v0, _, err0 := s15.SeNBAdditionRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBAdditionRequestIEFieldfreshMust(s15.SeNBAdditionRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SeNBAdditionRequestIEs().SeNBUEAggregateMaximumBitRate().Codec().DecodeAPER(freshHex("00000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBAdditionRequestIEFieldfreshMust(s15.SeNBAdditionRequestIEs().SeNBUEAggregateMaximumBitRate().New(v1.Value)))
		v2, _, err2 := s15.SeNBAdditionRequestIEs().ERABsToBeAddedList().Codec().DecodeAPER(freshHex("000076000b0000000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBAdditionRequestIEFieldfreshMust(s15.SeNBAdditionRequestIEs().ERABsToBeAddedList().New(v2.Value)))
		v3, _, err3 := s15.SeNBAdditionRequestIEs().MeNBtoSeNBContainer().Codec().DecodeAPER(freshHex("00"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, seNBAdditionRequestIEFieldfreshMust(s15.SeNBAdditionRequestIEs().MeNBtoSeNBContainer().New(v3.Value)))
		body := seNBAdditionRequestfreshMust(s19.NewSeNBAdditionRequest(fields))
		env := initiatingMessagefreshMust(s19.SeNBAdditionPreparationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0013002a000004006f00020000007300040000000000750010000076000b00000000000000000000000077000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBAdditionRequestAcknowledge", func(t *testing.T) {
		var fields s14.SeNBAdditionRequestAcknowledgeIEContainer
		v0, _, err0 := s14.SeNBAdditionRequestAcknowledgeIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBAdditionRequestAcknowledgeIEFieldfreshMust(s14.SeNBAdditionRequestAcknowledgeIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s14.SeNBAdditionRequestAcknowledgeIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBAdditionRequestAcknowledgeIEFieldfreshMust(s14.SeNBAdditionRequestAcknowledgeIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s14.SeNBAdditionRequestAcknowledgeIEs().ERABsAdmittedToBeAddedList().Codec().DecodeAPER(freshHex("00007940080000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBAdditionRequestAcknowledgeIEFieldfreshMust(s14.SeNBAdditionRequestAcknowledgeIEs().ERABsAdmittedToBeAddedList().New(v2.Value)))
		v3, _, err3 := s14.SeNBAdditionRequestAcknowledgeIEs().SeNBtoMeNBContainer().Codec().DecodeAPER(freshHex("00"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, seNBAdditionRequestAcknowledgeIEFieldfreshMust(s14.SeNBAdditionRequestAcknowledgeIEs().SeNBtoMeNBContainer().New(v3.Value)))
		body := seNBAdditionRequestAcknowledgefreshMust(s19.NewSeNBAdditionRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.SeNBAdditionPreparationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20130025000004006f000200000070000200000078400d00007940080000000000000000007a000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBAdditionRequestReject", func(t *testing.T) {
		var fields s11.SeNBAdditionRequestRejectIEContainer
		v0, _, err0 := s11.SeNBAdditionRequestRejectIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBAdditionRequestRejectIEFieldfreshMust(s11.SeNBAdditionRequestRejectIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.SeNBAdditionRequestRejectIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBAdditionRequestRejectIEFieldfreshMust(s11.SeNBAdditionRequestRejectIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.SeNBAdditionRequestRejectIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBAdditionRequestRejectIEFieldfreshMust(s11.SeNBAdditionRequestRejectIEs().Cause().New(v2.Value)))
		body := seNBAdditionRequestRejectfreshMust(s14.NewSeNBAdditionRequestReject(fields))
		env := unsuccessfulOutcomefreshMust(s19.SeNBAdditionPreparationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40130015000003006f00020000007000020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBReconfigurationComplete", func(t *testing.T) {
		var fields s12.SeNBReconfigurationCompleteIEContainer
		v0, _, err0 := s12.SeNBReconfigurationCompleteIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBReconfigurationCompleteIEFieldfreshMust(s12.SeNBReconfigurationCompleteIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SeNBReconfigurationCompleteIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBReconfigurationCompleteIEFieldfreshMust(s12.SeNBReconfigurationCompleteIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SeNBReconfigurationCompleteIEs().ResponseInformationSeNBReconfComp().Codec().DecodeAPER(freshHex("00"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBReconfigurationCompleteIEFieldfreshMust(s12.SeNBReconfigurationCompleteIEs().ResponseInformationSeNBReconfComp().New(v2.Value)))
		body := seNBReconfigurationCompletefreshMust(s19.NewSeNBReconfigurationComplete(fields))
		env := initiatingMessagefreshMust(s19.SeNBReconfigurationCompletionProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00144014000003006f00020000007000020000007b400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationRequest", func(t *testing.T) {
		var fields s12.SeNBModificationRequestIEContainer
		v0, _, err0 := s12.SeNBModificationRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationRequestIEFieldfreshMust(s12.SeNBModificationRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SeNBModificationRequestIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationRequestIEFieldfreshMust(s12.SeNBModificationRequestIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SeNBModificationRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBModificationRequestIEFieldfreshMust(s12.SeNBModificationRequestIEs().Cause().New(v2.Value)))
		body := seNBModificationRequestfreshMust(s19.NewSeNBModificationRequest(fields))
		env := initiatingMessagefreshMust(s19.MeNBinitiatedSeNBModificationPreparationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00150015000003006f00020000007000020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationRequestAcknowledge", func(t *testing.T) {
		var fields s15.SeNBModificationRequestAcknowledgeIEContainer
		v0, _, err0 := s15.SeNBModificationRequestAcknowledgeIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationRequestAcknowledgeIEFieldfreshMust(s15.SeNBModificationRequestAcknowledgeIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SeNBModificationRequestAcknowledgeIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationRequestAcknowledgeIEFieldfreshMust(s15.SeNBModificationRequestAcknowledgeIEs().SeNBUEX2APID().New(v1.Value)))
		body := seNBModificationRequestAcknowledgefreshMust(s19.NewSeNBModificationRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.MeNBinitiatedSeNBModificationPreparationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2015000f000002006f40020000007040020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationRequestReject", func(t *testing.T) {
		var fields s12.SeNBModificationRequestRejectIEContainer
		v0, _, err0 := s12.SeNBModificationRequestRejectIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationRequestRejectIEFieldfreshMust(s12.SeNBModificationRequestRejectIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SeNBModificationRequestRejectIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationRequestRejectIEFieldfreshMust(s12.SeNBModificationRequestRejectIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SeNBModificationRequestRejectIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBModificationRequestRejectIEFieldfreshMust(s12.SeNBModificationRequestRejectIEs().Cause().New(v2.Value)))
		body := seNBModificationRequestRejectfreshMust(s14.NewSeNBModificationRequestReject(fields))
		env := unsuccessfulOutcomefreshMust(s19.MeNBinitiatedSeNBModificationPreparationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40150015000003006f40020000007040020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationRequired", func(t *testing.T) {
		var fields s15.SeNBModificationRequiredIEContainer
		v0, _, err0 := s15.SeNBModificationRequiredIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationRequiredIEFieldfreshMust(s15.SeNBModificationRequiredIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SeNBModificationRequiredIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationRequiredIEFieldfreshMust(s15.SeNBModificationRequiredIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.SeNBModificationRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBModificationRequiredIEFieldfreshMust(s15.SeNBModificationRequiredIEs().Cause().New(v2.Value)))
		body := seNBModificationRequiredfreshMust(s19.NewSeNBModificationRequired(fields))
		env := initiatingMessagefreshMust(s19.SeNBinitiatedSeNBModificationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00160015000003006f00020000007000020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationConfirm", func(t *testing.T) {
		var fields s11.SeNBModificationConfirmIEContainer
		v0, _, err0 := s11.SeNBModificationConfirmIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationConfirmIEFieldfreshMust(s11.SeNBModificationConfirmIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.SeNBModificationConfirmIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationConfirmIEFieldfreshMust(s11.SeNBModificationConfirmIEs().SeNBUEX2APID().New(v1.Value)))
		body := seNBModificationConfirmfreshMust(s19.NewSeNBModificationConfirm(fields))
		env := successfulOutcomefreshMust(s19.SeNBinitiatedSeNBModificationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2016000f000002006f40020000007040020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBModificationRefuse", func(t *testing.T) {
		var fields s11.SeNBModificationRefuseIEContainer
		v0, _, err0 := s11.SeNBModificationRefuseIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBModificationRefuseIEFieldfreshMust(s11.SeNBModificationRefuseIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.SeNBModificationRefuseIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBModificationRefuseIEFieldfreshMust(s11.SeNBModificationRefuseIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.SeNBModificationRefuseIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBModificationRefuseIEFieldfreshMust(s11.SeNBModificationRefuseIEs().Cause().New(v2.Value)))
		body := seNBModificationRefusefreshMust(s14.NewSeNBModificationRefuse(fields))
		env := unsuccessfulOutcomefreshMust(s19.SeNBinitiatedSeNBModificationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40160015000003006f40020000007040020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBReleaseRequest", func(t *testing.T) {
		var fields s15.SeNBReleaseRequestIEContainer
		v0, _, err0 := s15.SeNBReleaseRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBReleaseRequestIEFieldfreshMust(s15.SeNBReleaseRequestIEs().MeNBUEX2APID().New(v0.Value)))
		body := seNBReleaseRequestfreshMust(s19.NewSeNBReleaseRequest(fields))
		env := initiatingMessagefreshMust(s19.MeNBinitiatedSeNBReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00174009000001006f00020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBReleaseRequired", func(t *testing.T) {
		var fields s12.SeNBReleaseRequiredIEContainer
		v0, _, err0 := s12.SeNBReleaseRequiredIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBReleaseRequiredIEFieldfreshMust(s12.SeNBReleaseRequiredIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SeNBReleaseRequiredIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBReleaseRequiredIEFieldfreshMust(s12.SeNBReleaseRequiredIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SeNBReleaseRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBReleaseRequiredIEFieldfreshMust(s12.SeNBReleaseRequiredIEs().Cause().New(v2.Value)))
		body := seNBReleaseRequiredfreshMust(s19.NewSeNBReleaseRequired(fields))
		env := initiatingMessagefreshMust(s19.SeNBinitiatedSeNBReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00180015000003006f00020000007000020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBReleaseConfirm", func(t *testing.T) {
		var fields s15.SeNBReleaseConfirmIEContainer
		v0, _, err0 := s15.SeNBReleaseConfirmIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBReleaseConfirmIEFieldfreshMust(s15.SeNBReleaseConfirmIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SeNBReleaseConfirmIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBReleaseConfirmIEFieldfreshMust(s15.SeNBReleaseConfirmIEs().SeNBUEX2APID().New(v1.Value)))
		body := seNBReleaseConfirmfreshMust(s19.NewSeNBReleaseConfirm(fields))
		env := successfulOutcomefreshMust(s19.SeNBinitiatedSeNBReleaseProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2018000f000002006f40020000007040020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SeNBCounterCheckRequest", func(t *testing.T) {
		var fields s15.SeNBCounterCheckRequestIEContainer
		v0, _, err0 := s15.SeNBCounterCheckRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, seNBCounterCheckRequestIEFieldfreshMust(s15.SeNBCounterCheckRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SeNBCounterCheckRequestIEs().SeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, seNBCounterCheckRequestIEFieldfreshMust(s15.SeNBCounterCheckRequestIEs().SeNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.SeNBCounterCheckRequestIEs().ERABsSubjectToCounterCheckList().Codec().DecodeAPER(freshHex("00008e40050000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, seNBCounterCheckRequestIEFieldfreshMust(s15.SeNBCounterCheckRequestIEs().ERABsSubjectToCounterCheckList().New(v2.Value)))
		body := seNBCounterCheckRequestfreshMust(s19.NewSeNBCounterCheckRequest(fields))
		env := initiatingMessagefreshMust(s19.SeNBCounterCheckProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0019001d000003006f00020000007000020000008d400a00008e40050000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2RemovalRequest", func(t *testing.T) {
		var fields s13.X2RemovalRequestIEContainer
		v0, _, err0 := s13.X2RemovalRequestIEs().GlobalENBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2RemovalRequestIEFieldfreshMust(s13.X2RemovalRequestIEs().GlobalENBID().New(v0.Value)))
		body := x2RemovalRequestfreshMust(s20.NewX2RemovalRequest(fields))
		env := initiatingMessagefreshMust(s20.X2RemovalProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0012000f000001001500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2RemovalResponse", func(t *testing.T) {
		var fields s07.X2RemovalResponseIEContainer
		v0, _, err0 := s07.X2RemovalResponseIEs().GlobalENBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2RemovalResponseIEFieldfreshMust(s07.X2RemovalResponseIEs().GlobalENBID().New(v0.Value)))
		body := x2RemovalResponsefreshMust(s20.NewX2RemovalResponse(fields))
		env := successfulOutcomefreshMust(s20.X2RemovalProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2012000f000001001500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("X2RemovalFailure", func(t *testing.T) {
		var fields s07.X2RemovalFailureIEContainer
		v0, _, err0 := s07.X2RemovalFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, x2RemovalFailureIEFieldfreshMust(s07.X2RemovalFailureIEs().Cause().New(v0.Value)))
		body := x2RemovalFailurefreshMust(s14.NewX2RemovalFailure(fields))
		env := unsuccessfulOutcomefreshMust(s20.X2RemovalProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40120009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RetrieveUEContextRequest", func(t *testing.T) {
		var fields s11.RetrieveUEContextRequestIEContainer
		v0, _, err0 := s11.RetrieveUEContextRequestIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, retrieveUEContextRequestIEFieldfreshMust(s11.RetrieveUEContextRequestIEs().NewENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.RetrieveUEContextRequestIEs().ResumeID().Codec().DecodeAPER(freshHex("000000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, retrieveUEContextRequestIEFieldfreshMust(s11.RetrieveUEContextRequestIEs().ResumeID().New(v1.Value)))
		v2, _, err2 := s11.RetrieveUEContextRequestIEs().ShortMACI().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, retrieveUEContextRequestIEFieldfreshMust(s11.RetrieveUEContextRequestIEs().ShortMACI().New(v2.Value)))
		v3, _, err3 := s11.RetrieveUEContextRequestIEs().NewEUTRANCellIdentifier().Codec().DecodeAPER(freshHex("00000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, retrieveUEContextRequestIEFieldfreshMust(s11.RetrieveUEContextRequestIEs().NewEUTRANCellIdentifier().New(v3.Value)))
		body := retrieveUEContextRequestfreshMust(s19.NewRetrieveUEContextRequest(fields))
		env := initiatingMessagefreshMust(s19.RetrieveUEContextProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001a002100000400090002000000ac000600000000000000330002000000af000400000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RetrieveUEContextResponse", func(t *testing.T) {
		var fields s17.RetrieveUEContextResponseIEContainer
		v0, _, err0 := s17.RetrieveUEContextResponseIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, retrieveUEContextResponseIEFieldfreshMust(s17.RetrieveUEContextResponseIEs().NewENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.RetrieveUEContextResponseIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, retrieveUEContextResponseIEFieldfreshMust(s17.RetrieveUEContextResponseIEs().OldENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s17.RetrieveUEContextResponseIEs().GUMMEIID().Codec().DecodeAPER(freshHex("00000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, retrieveUEContextResponseIEFieldfreshMust(s17.RetrieveUEContextResponseIEs().GUMMEIID().New(v2.Value)))
		v3, _, err3 := s17.RetrieveUEContextResponseIEs().UEContextInformationRetrieve().Codec().DecodeAPER(freshHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ae40040000000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, retrieveUEContextResponseIEFieldfreshMust(s17.RetrieveUEContextResponseIEs().UEContextInformationRetrieve().New(v3.Value)))
		body := retrieveUEContextResponsefreshMust(s19.NewRetrieveUEContextResponse(fields))
		env := successfulOutcomefreshMust(s19.RetrieveUEContextProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("201a0054000004000940020000000a40020000001700070000000000000000ad003600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ae40040000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RetrieveUEContextFailure", func(t *testing.T) {
		var fields s11.RetrieveUEContextFailureIEContainer
		v0, _, err0 := s11.RetrieveUEContextFailureIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, retrieveUEContextFailureIEFieldfreshMust(s11.RetrieveUEContextFailureIEs().NewENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.RetrieveUEContextFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, retrieveUEContextFailureIEFieldfreshMust(s11.RetrieveUEContextFailureIEs().Cause().New(v1.Value)))
		body := retrieveUEContextFailurefreshMust(s14.NewRetrieveUEContextFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.RetrieveUEContextProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("401a000f000002000940020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBAdditionRequest", func(t *testing.T) {
		var fields s18.SgNBAdditionRequestIEContainer
		v0, _, err0 := s18.SgNBAdditionRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s18.SgNBAdditionRequestIEs().NRUESecurityCapabilities().Codec().DecodeAPER(freshHex("0000000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().NRUESecurityCapabilities().New(v1.Value)))
		v2, _, err2 := s18.SgNBAdditionRequestIEs().SgNBSecurityKey().Codec().DecodeAPER(freshHex("0000000000000000000000000000000000000000000000000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().SgNBSecurityKey().New(v2.Value)))
		v3, _, err3 := s18.SgNBAdditionRequestIEs().SgNBUEAggregateMaximumBitRate().Codec().DecodeAPER(freshHex("00000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().SgNBUEAggregateMaximumBitRate().New(v3.Value)))
		v4, _, err4 := s18.SgNBAdditionRequestIEs().ERABsToBeAddedSgNBAddReqList().Codec().DecodeAPER(freshHex("0000d1000d00000000000000000000000000"))
		if err4 != nil {
			t.Fatal(err4)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().ERABsToBeAddedSgNBAddReqList().New(v4.Value)))
		v5, _, err5 := s18.SgNBAdditionRequestIEs().MeNBtoSgNBContainer().Codec().DecodeAPER(freshHex("00"))
		if err5 != nil {
			t.Fatal(err5)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().MeNBtoSgNBContainer().New(v5.Value)))
		v6, _, err6 := s18.SgNBAdditionRequestIEs().MeNBCellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err6 != nil {
			t.Fatal(err6)
		}
		fields = append(fields, sgNBAdditionRequestIEFieldfreshMust(s18.SgNBAdditionRequestIEs().MeNBCellID().New(v6.Value)))
		body := sgNBAdditionRequestfreshMust(s19.NewSgNBAdditionRequest(fields))
		env := initiatingMessagefreshMust(s19.SgNBAdditionPreparationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001b0065000007006f0002000000f80005000000000000cb0020000000000000000000000000000000000000000000000000000000000000000000cc00040000000000cd00120000d1000d0000000000000000000000000000ce000100011700080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBAdditionRequestAcknowledge", func(t *testing.T) {
		var fields s14.SgNBAdditionRequestAcknowledgeIEContainer
		v0, _, err0 := s15.SgNBAdditionRequestAcknowledgeIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBAdditionRequestAcknowledgeIEFieldfreshMust(s15.SgNBAdditionRequestAcknowledgeIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBAdditionRequestAcknowledgeIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBAdditionRequestAcknowledgeIEFieldfreshMust(s15.SgNBAdditionRequestAcknowledgeIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.SgNBAdditionRequestAcknowledgeIEs().ERABsAdmittedToBeAddedSgNBAddReqAckList().Codec().DecodeAPER(freshHex("0000d5400a00000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBAdditionRequestAcknowledgeIEFieldfreshMust(s15.SgNBAdditionRequestAcknowledgeIEs().ERABsAdmittedToBeAddedSgNBAddReqAckList().New(v2.Value)))
		v3, _, err3 := s15.SgNBAdditionRequestAcknowledgeIEs().SgNBtoMeNBContainer().Codec().DecodeAPER(freshHex("00"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, sgNBAdditionRequestAcknowledgeIEFieldfreshMust(s15.SgNBAdditionRequestAcknowledgeIEs().SgNBtoMeNBContainer().New(v3.Value)))
		body := sgNBAdditionRequestAcknowledgefreshMust(s19.NewSgNBAdditionRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.SgNBAdditionPreparationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("201b0027000004006f0002000000cf0002000000d2400f0000d5400a0000000000000000000000d3000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBAdditionRequestReject", func(t *testing.T) {
		var fields s12.SgNBAdditionRequestRejectIEContainer
		v0, _, err0 := s12.SgNBAdditionRequestRejectIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBAdditionRequestRejectIEFieldfreshMust(s12.SgNBAdditionRequestRejectIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBAdditionRequestRejectIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBAdditionRequestRejectIEFieldfreshMust(s12.SgNBAdditionRequestRejectIEs().Cause().New(v1.Value)))
		body := sgNBAdditionRequestRejectfreshMust(s14.NewSgNBAdditionRequestReject(fields))
		env := unsuccessfulOutcomefreshMust(s19.SgNBAdditionPreparationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("401b000f000002006f00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReconfigurationComplete", func(t *testing.T) {
		var fields s12.SgNBReconfigurationCompleteIEContainer
		v0, _, err0 := s12.SgNBReconfigurationCompleteIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReconfigurationCompleteIEFieldfreshMust(s12.SgNBReconfigurationCompleteIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBReconfigurationCompleteIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReconfigurationCompleteIEFieldfreshMust(s12.SgNBReconfigurationCompleteIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SgNBReconfigurationCompleteIEs().ResponseInformationSgNBReconfComp().Codec().DecodeAPER(freshHex("00"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBReconfigurationCompleteIEFieldfreshMust(s12.SgNBReconfigurationCompleteIEs().ResponseInformationSgNBReconfComp().New(v2.Value)))
		body := sgNBReconfigurationCompletefreshMust(s19.NewSgNBReconfigurationComplete(fields))
		env := initiatingMessagefreshMust(s19.SgNBReconfigurationCompletionProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001c4014000003006f0002000000cf0002000000d6400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationRequest", func(t *testing.T) {
		var fields s16.SgNBModificationRequestIEContainer
		v0, _, err0 := s16.SgNBModificationRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationRequestIEFieldfreshMust(s16.SgNBModificationRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s16.SgNBModificationRequestIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationRequestIEFieldfreshMust(s16.SgNBModificationRequestIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s16.SgNBModificationRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBModificationRequestIEFieldfreshMust(s16.SgNBModificationRequestIEs().Cause().New(v2.Value)))
		body := sgNBModificationRequestfreshMust(s19.NewSgNBModificationRequest(fields))
		env := initiatingMessagefreshMust(s19.MeNBinitiatedSgNBModificationPreparationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001d0015000003006f0002000000cf00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationRequestAcknowledge", func(t *testing.T) {
		var fields s17.SgNBModificationRequestAcknowledgeIEContainer
		v0, _, err0 := s17.SgNBModificationRequestAcknowledgeIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationRequestAcknowledgeIEFieldfreshMust(s17.SgNBModificationRequestAcknowledgeIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SgNBModificationRequestAcknowledgeIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationRequestAcknowledgeIEFieldfreshMust(s17.SgNBModificationRequestAcknowledgeIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBModificationRequestAcknowledgefreshMust(s19.NewSgNBModificationRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.MeNBinitiatedSgNBModificationPreparationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("201d000f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationRequestReject", func(t *testing.T) {
		var fields s12.SgNBModificationRequestRejectIEContainer
		v0, _, err0 := s12.SgNBModificationRequestRejectIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationRequestRejectIEFieldfreshMust(s12.SgNBModificationRequestRejectIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBModificationRequestRejectIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationRequestRejectIEFieldfreshMust(s12.SgNBModificationRequestRejectIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SgNBModificationRequestRejectIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBModificationRequestRejectIEFieldfreshMust(s12.SgNBModificationRequestRejectIEs().Cause().New(v2.Value)))
		body := sgNBModificationRequestRejectfreshMust(s14.NewSgNBModificationRequestReject(fields))
		env := unsuccessfulOutcomefreshMust(s19.MeNBinitiatedSgNBModificationPreparationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("401d0015000003006f4002000000cf40020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationRequired", func(t *testing.T) {
		var fields s17.SgNBModificationRequiredIEContainer
		v0, _, err0 := s17.SgNBModificationRequiredIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationRequiredIEFieldfreshMust(s17.SgNBModificationRequiredIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SgNBModificationRequiredIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationRequiredIEFieldfreshMust(s17.SgNBModificationRequiredIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s17.SgNBModificationRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBModificationRequiredIEFieldfreshMust(s17.SgNBModificationRequiredIEs().Cause().New(v2.Value)))
		body := sgNBModificationRequiredfreshMust(s19.NewSgNBModificationRequired(fields))
		env := initiatingMessagefreshMust(s19.SgNBinitiatedSgNBModificationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001e0015000003006f0002000000cf00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationConfirm", func(t *testing.T) {
		var fields s15.SgNBModificationConfirmIEContainer
		v0, _, err0 := s15.SgNBModificationConfirmIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationConfirmIEFieldfreshMust(s15.SgNBModificationConfirmIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBModificationConfirmIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationConfirmIEFieldfreshMust(s15.SgNBModificationConfirmIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBModificationConfirmfreshMust(s19.NewSgNBModificationConfirm(fields))
		env := successfulOutcomefreshMust(s19.SgNBinitiatedSgNBModificationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("201e000f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBModificationRefuse", func(t *testing.T) {
		var fields s12.SgNBModificationRefuseIEContainer
		v0, _, err0 := s12.SgNBModificationRefuseIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBModificationRefuseIEFieldfreshMust(s12.SgNBModificationRefuseIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBModificationRefuseIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBModificationRefuseIEFieldfreshMust(s12.SgNBModificationRefuseIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SgNBModificationRefuseIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBModificationRefuseIEFieldfreshMust(s12.SgNBModificationRefuseIEs().Cause().New(v2.Value)))
		body := sgNBModificationRefusefreshMust(s14.NewSgNBModificationRefuse(fields))
		env := unsuccessfulOutcomefreshMust(s19.SgNBinitiatedSgNBModificationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("401e0015000003006f4002000000cf40020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReleaseRequest", func(t *testing.T) {
		var fields s15.SgNBReleaseRequestIEContainer
		v0, _, err0 := s15.SgNBReleaseRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReleaseRequestIEFieldfreshMust(s15.SgNBReleaseRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBReleaseRequestIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReleaseRequestIEFieldfreshMust(s15.SgNBReleaseRequestIEs().Cause().New(v1.Value)))
		body := sgNBReleaseRequestfreshMust(s19.NewSgNBReleaseRequest(fields))
		env := initiatingMessagefreshMust(s20.MeNBinitiatedSgNBReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("001f400f000002006f00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReleaseRequestAcknowledge", func(t *testing.T) {
		var fields s17.SgNBReleaseRequestAcknowledgeIEContainer
		v0, _, err0 := s17.SgNBReleaseRequestAcknowledgeIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReleaseRequestAcknowledgeIEFieldfreshMust(s17.SgNBReleaseRequestAcknowledgeIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SgNBReleaseRequestAcknowledgeIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReleaseRequestAcknowledgeIEFieldfreshMust(s17.SgNBReleaseRequestAcknowledgeIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBReleaseRequestAcknowledgefreshMust(s20.NewSgNBReleaseRequestAcknowledge(fields))
		env := successfulOutcomefreshMust(s20.MeNBinitiatedSgNBReleaseProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("201f400f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReleaseRequestReject", func(t *testing.T) {
		var fields s12.SgNBReleaseRequestRejectIEContainer
		v0, _, err0 := s12.SgNBReleaseRequestRejectIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReleaseRequestRejectIEFieldfreshMust(s12.SgNBReleaseRequestRejectIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBReleaseRequestRejectIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReleaseRequestRejectIEFieldfreshMust(s12.SgNBReleaseRequestRejectIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SgNBReleaseRequestRejectIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBReleaseRequestRejectIEFieldfreshMust(s12.SgNBReleaseRequestRejectIEs().Cause().New(v2.Value)))
		body := sgNBReleaseRequestRejectfreshMust(s14.NewSgNBReleaseRequestReject(fields))
		env := unsuccessfulOutcomefreshMust(s20.MeNBinitiatedSgNBReleaseProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("401f4015000003006f4002000000cf40020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReleaseRequired", func(t *testing.T) {
		var fields s17.SgNBReleaseRequiredIEContainer
		v0, _, err0 := s17.SgNBReleaseRequiredIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReleaseRequiredIEFieldfreshMust(s17.SgNBReleaseRequiredIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SgNBReleaseRequiredIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReleaseRequiredIEFieldfreshMust(s17.SgNBReleaseRequiredIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s17.SgNBReleaseRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBReleaseRequiredIEFieldfreshMust(s17.SgNBReleaseRequiredIEs().Cause().New(v2.Value)))
		body := sgNBReleaseRequiredfreshMust(s20.NewSgNBReleaseRequired(fields))
		env := initiatingMessagefreshMust(s20.SgNBinitiatedSgNBReleaseProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00200015000003006f0002000000cf00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBReleaseConfirm", func(t *testing.T) {
		var fields s15.SgNBReleaseConfirmIEContainer
		v0, _, err0 := s15.SgNBReleaseConfirmIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBReleaseConfirmIEFieldfreshMust(s15.SgNBReleaseConfirmIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBReleaseConfirmIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBReleaseConfirmIEFieldfreshMust(s15.SgNBReleaseConfirmIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBReleaseConfirmfreshMust(s19.NewSgNBReleaseConfirm(fields))
		env := successfulOutcomefreshMust(s20.SgNBinitiatedSgNBReleaseProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2020000f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBCounterCheckRequest", func(t *testing.T) {
		var fields s15.SgNBCounterCheckRequestIEContainer
		v0, _, err0 := s15.SgNBCounterCheckRequestIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBCounterCheckRequestIEFieldfreshMust(s15.SgNBCounterCheckRequestIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBCounterCheckRequestIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBCounterCheckRequestIEFieldfreshMust(s15.SgNBCounterCheckRequestIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.SgNBCounterCheckRequestIEs().ERABsSubjectToSgNBCounterCheckList().Codec().DecodeAPER(freshHex("0000ec40050000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBCounterCheckRequestIEFieldfreshMust(s15.SgNBCounterCheckRequestIEs().ERABsSubjectToSgNBCounterCheckList().New(v2.Value)))
		body := sgNBCounterCheckRequestfreshMust(s19.NewSgNBCounterCheckRequest(fields))
		env := initiatingMessagefreshMust(s19.SgNBCounterCheckProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0021001d000003006f0002000000cf0002000000eb400a0000ec40050000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBChangeRequired", func(t *testing.T) {
		var fields s17.SgNBChangeRequiredIEContainer
		v0, _, err0 := s17.SgNBChangeRequiredIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBChangeRequiredIEFieldfreshMust(s17.SgNBChangeRequiredIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SgNBChangeRequiredIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBChangeRequiredIEFieldfreshMust(s17.SgNBChangeRequiredIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s17.SgNBChangeRequiredIEs().TargetSgNBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBChangeRequiredIEFieldfreshMust(s17.SgNBChangeRequiredIEs().TargetSgNBID().New(v2.Value)))
		v3, _, err3 := s17.SgNBChangeRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, sgNBChangeRequiredIEFieldfreshMust(s17.SgNBChangeRequiredIEs().Cause().New(v3.Value)))
		body := sgNBChangeRequiredfreshMust(s19.NewSgNBChangeRequired(fields))
		env := initiatingMessagefreshMust(s19.SgNBChangeProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00220021000004006f0002000000cf0002000000ef00080000000000000000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBChangeConfirm", func(t *testing.T) {
		var fields s15.SgNBChangeConfirmIEContainer
		v0, _, err0 := s15.SgNBChangeConfirmIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBChangeConfirmIEFieldfreshMust(s15.SgNBChangeConfirmIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.SgNBChangeConfirmIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBChangeConfirmIEFieldfreshMust(s15.SgNBChangeConfirmIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBChangeConfirmfreshMust(s19.NewSgNBChangeConfirm(fields))
		env := successfulOutcomefreshMust(s19.SgNBChangeProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2022000f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBChangeRefuse", func(t *testing.T) {
		var fields s12.SgNBChangeRefuseIEContainer
		v0, _, err0 := s12.SgNBChangeRefuseIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBChangeRefuseIEFieldfreshMust(s12.SgNBChangeRefuseIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s12.SgNBChangeRefuseIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBChangeRefuseIEFieldfreshMust(s12.SgNBChangeRefuseIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s12.SgNBChangeRefuseIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sgNBChangeRefuseIEFieldfreshMust(s12.SgNBChangeRefuseIEs().Cause().New(v2.Value)))
		body := sgNBChangeRefusefreshMust(s14.NewSgNBChangeRefuse(fields))
		env := unsuccessfulOutcomefreshMust(s19.SgNBChangeProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40220015000003006f4002000000cf40020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RRCTransfer", func(t *testing.T) {
		var fields s11.RRCTransferIEContainer
		v0, _, err0 := s11.RRCTransferIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, rRCTransferIEFieldfreshMust(s11.RRCTransferIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.RRCTransferIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, rRCTransferIEFieldfreshMust(s11.RRCTransferIEs().SgNBUEX2APID().New(v1.Value)))
		body := rRCTransferfreshMust(s19.NewRRCTransfer(fields))
		env := initiatingMessagefreshMust(s19.RRCTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0023000f000002006f0002000000cf00020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2SetupRequest", func(t *testing.T) {
		var fields s18.ENDCX2SetupRequestIEContainer
		v0, _, err0 := s18.ENDCX2SetupRequestIEs().InitiatingNodeTypeEndcX2Setup().Codec().DecodeAPER(freshHex("00000200150008000000000000000000fa00170000000000000000000000000000000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2SetupRequestIEFieldfreshMust(s18.ENDCX2SetupRequestIEs().InitiatingNodeTypeEndcX2Setup().New(v0.Value)))
		body := eNDCX2SetupRequestfreshMust(s19.NewENDCX2SetupRequest(fields))
		env := initiatingMessagefreshMust(s19.EndcX2SetupProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0024003100000100f4002a00000200150008000000000000000000fa00170000000000000000000000000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2SetupResponse", func(t *testing.T) {
		var fields s18.ENDCX2SetupResponseIEContainer
		v0, _, err0 := s18.ENDCX2SetupResponseIEs().RespondingNodeTypeEndcX2Setup().Codec().DecodeAPER(freshHex("00000200150008000000000000000000fa00170000000000000000000000000000000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2SetupResponseIEFieldfreshMust(s18.ENDCX2SetupResponseIEs().RespondingNodeTypeEndcX2Setup().New(v0.Value)))
		body := eNDCX2SetupResponsefreshMust(s19.NewENDCX2SetupResponse(fields))
		env := successfulOutcomefreshMust(s19.EndcX2SetupProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2024003100000100f6002a00000200150008000000000000000000fa00170000000000000000000000000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2SetupFailure", func(t *testing.T) {
		var fields s06.ENDCX2SetupFailureIEContainer
		v0, _, err0 := s06.ENDCX2SetupFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2SetupFailureIEFieldfreshMust(s06.ENDCX2SetupFailureIEs().Cause().New(v0.Value)))
		body := eNDCX2SetupFailurefreshMust(s14.NewENDCX2SetupFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.EndcX2SetupProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40240009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCConfigurationUpdate", func(t *testing.T) {
		var fields s18.ENDCConfigurationUpdateIEContainer
		v0, _, err0 := s18.ENDCConfigurationUpdateIEs().InitiatingNodeTypeEndcConfigUpdate().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCConfigurationUpdateIEFieldfreshMust(s18.ENDCConfigurationUpdateIEs().InitiatingNodeTypeEndcConfigUpdate().New(v0.Value)))
		body := eNDCConfigurationUpdatefreshMust(s19.NewENDCConfigurationUpdate(fields))
		env := initiatingMessagefreshMust(s19.EndcConfigurationUpdateProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0025000a00000100f50003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCConfigurationUpdateAcknowledge", func(t *testing.T) {
		var fields s18.ENDCConfigurationUpdateAcknowledgeIEContainer
		v0, _, err0 := s18.ENDCConfigurationUpdateAcknowledgeIEs().RespondingNodeTypeEndcConfigUpdate().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCConfigurationUpdateAcknowledgeIEFieldfreshMust(s18.ENDCConfigurationUpdateAcknowledgeIEs().RespondingNodeTypeEndcConfigUpdate().New(v0.Value)))
		body := eNDCConfigurationUpdateAcknowledgefreshMust(s19.NewENDCConfigurationUpdateAcknowledge(fields))
		env := successfulOutcomefreshMust(s19.EndcConfigurationUpdateProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2025000a00000100f70003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCConfigurationUpdateFailure", func(t *testing.T) {
		var fields s06.ENDCConfigurationUpdateFailureIEContainer
		v0, _, err0 := s06.ENDCConfigurationUpdateFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCConfigurationUpdateFailureIEFieldfreshMust(s06.ENDCConfigurationUpdateFailureIEs().Cause().New(v0.Value)))
		body := eNDCConfigurationUpdateFailurefreshMust(s14.NewENDCConfigurationUpdateFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.EndcConfigurationUpdateProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40250009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SecondaryRATDataUsageReport", func(t *testing.T) {
		var fields s17.SecondaryRATDataUsageReportIEContainer
		v0, _, err0 := s17.SecondaryRATDataUsageReportIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, secondaryRATDataUsageReportIEFieldfreshMust(s17.SecondaryRATDataUsageReportIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s17.SecondaryRATDataUsageReportIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, secondaryRATDataUsageReportIEFieldfreshMust(s17.SecondaryRATDataUsageReportIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s17.SecondaryRATDataUsageReportIEs().SecondaryRATUsageReportList().Codec().DecodeAPER(freshHex("00010a001300000107400d00000000000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, secondaryRATDataUsageReportIEFieldfreshMust(s17.SecondaryRATDataUsageReportIEs().SecondaryRATUsageReportList().New(v2.Value)))
		body := secondaryRATDataUsageReportfreshMust(s19.NewSecondaryRATDataUsageReport(fields))
		env := initiatingMessagefreshMust(s19.SecondaryRATDataUsageReportProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0026002b000003006f0002000000cf000200000109001800010a001300000107400d00000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCCellActivationRequest", func(t *testing.T) {
		var fields s17.ENDCCellActivationRequestIEContainer
		v0, _, err0 := s17.ENDCCellActivationRequestIEs().ServedNRCellsToActivate().Codec().DecodeAPER(freshHex("0000000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCCellActivationRequestIEFieldfreshMust(s17.ENDCCellActivationRequestIEs().ServedNRCellsToActivate().New(v0.Value)))
		v1, _, err1 := s17.ENDCCellActivationRequestIEs().ActivationID().Codec().DecodeAPER(freshHex("00"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCCellActivationRequestIEFieldfreshMust(s17.ENDCCellActivationRequestIEs().ActivationID().New(v1.Value)))
		body := eNDCCellActivationRequestfreshMust(s19.NewENDCCellActivationRequest(fields))
		env := initiatingMessagefreshMust(s19.EndcCellActivationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00270017000002010b000b00000000000000000000000100000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCCellActivationResponse", func(t *testing.T) {
		var fields s13.ENDCCellActivationResponseIEContainer
		v0, _, err0 := s13.ENDCCellActivationResponseIEs().ActivatedNRCellList().Codec().DecodeAPER(freshHex("0000000000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCCellActivationResponseIEFieldfreshMust(s13.ENDCCellActivationResponseIEs().ActivatedNRCellList().New(v0.Value)))
		v1, _, err1 := s13.ENDCCellActivationResponseIEs().ActivationID().Codec().DecodeAPER(freshHex("00"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCCellActivationResponseIEFieldfreshMust(s13.ENDCCellActivationResponseIEs().ActivationID().New(v1.Value)))
		body := eNDCCellActivationResponsefreshMust(s19.NewENDCCellActivationResponse(fields))
		env := successfulOutcomefreshMust(s19.EndcCellActivationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20270017000002010c400b00000000000000000000000100000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCCellActivationFailure", func(t *testing.T) {
		var fields s06.ENDCCellActivationFailureIEContainer
		v0, _, err0 := s06.ENDCCellActivationFailureIEs().ActivationID().Codec().DecodeAPER(freshHex("00"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCCellActivationFailureIEFieldfreshMust(s06.ENDCCellActivationFailureIEs().ActivationID().New(v0.Value)))
		v1, _, err1 := s06.ENDCCellActivationFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCCellActivationFailureIEFieldfreshMust(s06.ENDCCellActivationFailureIEs().Cause().New(v1.Value)))
		body := eNDCCellActivationFailurefreshMust(s14.NewENDCCellActivationFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.EndcCellActivationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("4027000e0000020100000100000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCPartialResetRequired", func(t *testing.T) {
		var fields s18.ENDCPartialResetRequiredIEContainer
		v0, _, err0 := s18.ENDCPartialResetRequiredIEs().UEsToBeReset().Codec().DecodeAPER(freshHex("0000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCPartialResetRequiredIEFieldfreshMust(s18.ENDCPartialResetRequiredIEs().UEsToBeReset().New(v0.Value)))
		v1, _, err1 := s18.ENDCPartialResetRequiredIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCPartialResetRequiredIEFieldfreshMust(s18.ENDCPartialResetRequiredIEs().Cause().New(v1.Value)))
		body := eNDCPartialResetRequiredfreshMust(s19.NewENDCPartialResetRequired(fields))
		env := initiatingMessagefreshMust(s19.EndcPartialResetProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00280012000002010e00050000000000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCPartialResetConfirm", func(t *testing.T) {
		var fields s18.ENDCPartialResetConfirmIEContainer
		v0, _, err0 := s18.ENDCPartialResetConfirmIEs().UEsAdmittedToBeReset().Codec().DecodeAPER(freshHex("0000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCPartialResetConfirmIEFieldfreshMust(s18.ENDCPartialResetConfirmIEs().UEsAdmittedToBeReset().New(v0.Value)))
		body := eNDCPartialResetConfirmfreshMust(s19.NewENDCPartialResetConfirm(fields))
		env := successfulOutcomefreshMust(s19.EndcPartialResetProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2028000c000001010f00050000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("EUTRANRCellResourceCoordinationRequest", func(t *testing.T) {
		var fields s15.EUTRANRCellResourceCoordinationRequestIEContainer
		v0, _, err0 := s15.EUTRANRCellResourceCoordinationRequestIEs().InitiatingNodeTypeEutranrCellResourceCoordination().Codec().DecodeAPER(freshHex("000003011f0007000000000000000120000100012100020000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eUTRANRCellResourceCoordinationRequestIEFieldfreshMust(s15.EUTRANRCellResourceCoordinationRequestIEs().InitiatingNodeTypeEutranrCellResourceCoordination().New(v0.Value)))
		body := eUTRANRCellResourceCoordinationRequestfreshMust(s19.NewEUTRANRCellResourceCoordinationRequest(fields))
		env := initiatingMessagefreshMust(s19.EUTRANRCellResourceCoordinationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00290020000001011d0019000003011f0007000000000000000120000100012100020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("EUTRANRCellResourceCoordinationResponse", func(t *testing.T) {
		var fields s15.EUTRANRCellResourceCoordinationResponseIEContainer
		v0, _, err0 := s15.EUTRANRCellResourceCoordinationResponseIEs().RespondingNodeTypeEutranrCellResourceCoordination().Codec().DecodeAPER(freshHex("000003011f0007000000000000000120000100012200020000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eUTRANRCellResourceCoordinationResponseIEFieldfreshMust(s15.EUTRANRCellResourceCoordinationResponseIEs().RespondingNodeTypeEutranrCellResourceCoordination().New(v0.Value)))
		body := eUTRANRCellResourceCoordinationResponsefreshMust(s19.NewEUTRANRCellResourceCoordinationResponse(fields))
		env := successfulOutcomefreshMust(s19.EUTRANRCellResourceCoordinationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20290020000001011e0019000003011f0007000000000000000120000100012200020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SgNBActivityNotification", func(t *testing.T) {
		var fields s14.SgNBActivityNotificationIEContainer
		v0, _, err0 := s14.SgNBActivityNotificationIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sgNBActivityNotificationIEFieldfreshMust(s14.SgNBActivityNotificationIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s14.SgNBActivityNotificationIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sgNBActivityNotificationIEFieldfreshMust(s14.SgNBActivityNotificationIEs().SgNBUEX2APID().New(v1.Value)))
		body := sgNBActivityNotificationfreshMust(s19.NewSgNBActivityNotification(fields))
		env := initiatingMessagefreshMust(s19.SgNBActivityNotificationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002a000f000002006f0002000000cf00020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2RemovalRequest", func(t *testing.T) {
		var fields s07.ENDCX2RemovalRequestIEContainer
		v0, _, err0 := s07.ENDCX2RemovalRequestIEs().InitiatingNodeTypeEndcX2Removal().Codec().DecodeAPER(freshHex("000001001500080000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2RemovalRequestIEFieldfreshMust(s07.ENDCX2RemovalRequestIEs().InitiatingNodeTypeEndcX2Removal().New(v0.Value)))
		body := eNDCX2RemovalRequestfreshMust(s19.NewENDCX2RemovalRequest(fields))
		env := initiatingMessagefreshMust(s19.EndcX2RemovalProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002b0016000001012a000f000001001500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2RemovalResponse", func(t *testing.T) {
		var fields s07.ENDCX2RemovalResponseIEContainer
		v0, _, err0 := s07.ENDCX2RemovalResponseIEs().RespondingNodeTypeEndcX2Removal().Codec().DecodeAPER(freshHex("000001001500080000000000000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2RemovalResponseIEFieldfreshMust(s07.ENDCX2RemovalResponseIEs().RespondingNodeTypeEndcX2Removal().New(v0.Value)))
		body := eNDCX2RemovalResponsefreshMust(s19.NewENDCX2RemovalResponse(fields))
		env := successfulOutcomefreshMust(s19.EndcX2RemovalProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("202b0016000001012b000f000001001500080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCX2RemovalFailure", func(t *testing.T) {
		var fields s06.ENDCX2RemovalFailureIEContainer
		v0, _, err0 := s06.ENDCX2RemovalFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCX2RemovalFailureIEFieldfreshMust(s06.ENDCX2RemovalFailureIEs().Cause().New(v0.Value)))
		body := eNDCX2RemovalFailurefreshMust(s14.NewENDCX2RemovalFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.EndcX2RemovalProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("402b0009000001000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("DataForwardingAddressIndication", func(t *testing.T) {
		var fields s15.DataForwardingAddressIndicationIEContainer
		v0, _, err0 := s15.DataForwardingAddressIndicationIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, dataForwardingAddressIndicationIEFieldfreshMust(s15.DataForwardingAddressIndicationIEs().NewENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s15.DataForwardingAddressIndicationIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, dataForwardingAddressIndicationIEFieldfreshMust(s15.DataForwardingAddressIndicationIEs().OldENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s15.DataForwardingAddressIndicationIEs().ERABsDataForwardingAddressList().Codec().DecodeAPER(freshHex("00013440080000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, dataForwardingAddressIndicationIEFieldfreshMust(s15.DataForwardingAddressIndicationIEs().ERABsDataForwardingAddressList().New(v2.Value)))
		body := dataForwardingAddressIndicationfreshMust(s19.NewDataForwardingAddressIndication(fields))
		env := initiatingMessagefreshMust(s19.DataForwardingAddressIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002c4020000003000940020000000a400200000133400d00013440080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("GNBStatusIndication", func(t *testing.T) {
		var fields s07.GNBStatusIndicationIEContainer
		v0, _, err0 := s07.GNBStatusIndicationIEs().GNBOverloadInformation().Codec().DecodeAPER(freshHex("00"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, gNBStatusIndicationIEFieldfreshMust(s07.GNBStatusIndicationIEs().GNBOverloadInformation().New(v0.Value)))
		body := gNBStatusIndicationfreshMust(s19.NewGNBStatusIndication(fields))
		env := initiatingMessagefreshMust(s19.GNBStatusIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002d40080000010136400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCConfigurationTransfer", func(t *testing.T) {
		var fields s06.ENDCConfigurationTransferIEContainer
		body := eNDCConfigurationTransferfreshMust(s19.NewENDCConfigurationTransfer(fields))
		env := initiatingMessagefreshMust(s19.EndcConfigurationTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00304003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("DeactivateTrace", func(t *testing.T) {
		var fields s11.DeactivateTraceIEContainer
		v0, _, err0 := s11.DeactivateTraceIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, deactivateTraceIEFieldfreshMust(s11.DeactivateTraceIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.DeactivateTraceIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, deactivateTraceIEFieldfreshMust(s11.DeactivateTraceIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.DeactivateTraceIEs().EUTRANTraceID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, deactivateTraceIEFieldfreshMust(s11.DeactivateTraceIEs().EUTRANTraceID().New(v2.Value)))
		body := deactivateTracefreshMust(s19.NewDeactivateTrace(fields))
		env := initiatingMessagefreshMust(s19.DeactivateTraceProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002e401b000003006f0002000000cf00020000014d40080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("TraceStart", func(t *testing.T) {
		var fields s16.TraceStartIEContainer
		v0, _, err0 := s16.TraceStartIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, traceStartIEFieldfreshMust(s16.TraceStartIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s16.TraceStartIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, traceStartIEFieldfreshMust(s16.TraceStartIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s16.TraceStartIEs().TraceActivation().Codec().DecodeAPER(freshHex("00000000000000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, traceStartIEFieldfreshMust(s16.TraceStartIEs().TraceActivation().New(v2.Value)))
		body := traceStartfreshMust(s20.NewTraceStart(fields))
		env := initiatingMessagefreshMust(s20.TraceStartProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("002f4020000003006f0002000000cf00020000000d400d00000000000000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("HandoverSuccess", func(t *testing.T) {
		var fields s11.HandoverSuccessIEContainer
		v0, _, err0 := s11.HandoverSuccessIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, handoverSuccessIEFieldfreshMust(s11.HandoverSuccessIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.HandoverSuccessIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, handoverSuccessIEFieldfreshMust(s11.HandoverSuccessIEs().NewENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.HandoverSuccessIEs().TargetCellID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, handoverSuccessIEFieldfreshMust(s11.HandoverSuccessIEs().TargetCellID().New(v2.Value)))
		body := handoverSuccessfreshMust(s19.NewHandoverSuccess(fields))
		env := initiatingMessagefreshMust(s19.HandoverSuccessProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0031401b000003000a00020000000900020000000b00080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("EarlyStatusTransfer", func(t *testing.T) {
		var fields s11.EarlyStatusTransferIEContainer
		v0, _, err0 := s11.EarlyStatusTransferIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, earlyStatusTransferIEFieldfreshMust(s11.EarlyStatusTransferIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.EarlyStatusTransferIEs().NewENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, earlyStatusTransferIEFieldfreshMust(s11.EarlyStatusTransferIEs().NewENBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.EarlyStatusTransferIEs().ProcedureStage().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, earlyStatusTransferIEFieldfreshMust(s11.EarlyStatusTransferIEs().ProcedureStage().New(v2.Value)))
		body := earlyStatusTransferfreshMust(s19.NewEarlyStatusTransfer(fields))
		env := initiatingMessagefreshMust(s19.EarlyStatusTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0033401b000003000a00020000000900020000016f00080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ConditionalHandoverCancel", func(t *testing.T) {
		var fields s14.ConditionalHandoverCancelIEContainer
		v0, _, err0 := s14.ConditionalHandoverCancelIEs().OldENBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, conditionalHandoverCancelIEFieldfreshMust(s14.ConditionalHandoverCancelIEs().OldENBUEX2APID().New(v0.Value)))
		v1, _, err1 := s14.ConditionalHandoverCancelIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, conditionalHandoverCancelIEFieldfreshMust(s14.ConditionalHandoverCancelIEs().Cause().New(v1.Value)))
		body := conditionalHandoverCancelfreshMust(s19.NewConditionalHandoverCancel(fields))
		env := initiatingMessagefreshMust(s19.ConditionalHandoverCancelProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0032400f000002000a00020000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCResourceStatusRequest", func(t *testing.T) {
		var fields s14.ENDCResourceStatusRequestIEContainer
		v0, _, err0 := s14.ENDCResourceStatusRequestIEs().EUTRANNode1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCResourceStatusRequestIEFieldfreshMust(s14.ENDCResourceStatusRequestIEs().EUTRANNode1MeasurementID().New(v0.Value)))
		v1, _, err1 := s14.ENDCResourceStatusRequestIEs().RegistrationRequest().Codec().DecodeAPER(freshHex("00"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCResourceStatusRequestIEFieldfreshMust(s14.ENDCResourceStatusRequestIEs().RegistrationRequest().New(v1.Value)))
		body := eNDCResourceStatusRequestfreshMust(s19.NewENDCResourceStatusRequest(fields))
		env := initiatingMessagefreshMust(s19.EndcresourceStatusReportingInitiationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("0036000f000002017f0003000000001c000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCResourceStatusResponse", func(t *testing.T) {
		var fields s06.ENDCResourceStatusResponseIEContainer
		v0, _, err0 := s06.ENDCResourceStatusResponseIEs().EUTRANNode1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCResourceStatusResponseIEFieldfreshMust(s06.ENDCResourceStatusResponseIEs().EUTRANNode1MeasurementID().New(v0.Value)))
		v1, _, err1 := s06.ENDCResourceStatusResponseIEs().EUTRANNode2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCResourceStatusResponseIEFieldfreshMust(s06.ENDCResourceStatusResponseIEs().EUTRANNode2MeasurementID().New(v1.Value)))
		body := eNDCResourceStatusResponsefreshMust(s19.NewENDCResourceStatusResponse(fields))
		env := successfulOutcomefreshMust(s19.EndcresourceStatusReportingInitiationProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("20360011000002017f000300000001800003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCResourceStatusFailure", func(t *testing.T) {
		var fields s06.ENDCResourceStatusFailureIEContainer
		v0, _, err0 := s06.ENDCResourceStatusFailureIEs().EUTRANNode1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCResourceStatusFailureIEFieldfreshMust(s06.ENDCResourceStatusFailureIEs().EUTRANNode1MeasurementID().New(v0.Value)))
		v1, _, err1 := s06.ENDCResourceStatusFailureIEs().EUTRANNode2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCResourceStatusFailureIEFieldfreshMust(s06.ENDCResourceStatusFailureIEs().EUTRANNode2MeasurementID().New(v1.Value)))
		v2, _, err2 := s06.ENDCResourceStatusFailureIEs().Cause().Codec().DecodeAPER(freshHex("0000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, eNDCResourceStatusFailureIEFieldfreshMust(s06.ENDCResourceStatusFailureIEs().Cause().New(v2.Value)))
		body := eNDCResourceStatusFailurefreshMust(s14.NewENDCResourceStatusFailure(fields))
		env := unsuccessfulOutcomefreshMust(s19.EndcresourceStatusReportingInitiationProcedure().Unsuccessful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUUnsuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("40360017000003017f000300000001800003000000000540020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("ENDCResourceStatusUpdate", func(t *testing.T) {
		var fields s14.ENDCResourceStatusUpdateIEContainer
		v0, _, err0 := s14.ENDCResourceStatusUpdateIEs().EUTRANNode1MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, eNDCResourceStatusUpdateIEFieldfreshMust(s14.ENDCResourceStatusUpdateIEs().EUTRANNode1MeasurementID().New(v0.Value)))
		v1, _, err1 := s14.ENDCResourceStatusUpdateIEs().EUTRANNode2MeasurementID().Codec().DecodeAPER(freshHex("000000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, eNDCResourceStatusUpdateIEFieldfreshMust(s14.ENDCResourceStatusUpdateIEs().EUTRANNode2MeasurementID().New(v1.Value)))
		body := eNDCResourceStatusUpdatefreshMust(s19.NewENDCResourceStatusUpdate(fields))
		env := initiatingMessagefreshMust(s19.EndcresourceStatusReportingProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00354011000002017f000300000001800003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("CellTrafficTrace", func(t *testing.T) {
		var fields s11.CellTrafficTraceIEContainer
		v0, _, err0 := s11.CellTrafficTraceIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, cellTrafficTraceIEFieldfreshMust(s11.CellTrafficTraceIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.CellTrafficTraceIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, cellTrafficTraceIEFieldfreshMust(s11.CellTrafficTraceIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.CellTrafficTraceIEs().EUTRANTraceID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, cellTrafficTraceIEFieldfreshMust(s11.CellTrafficTraceIEs().EUTRANTraceID().New(v2.Value)))
		v3, _, err3 := s11.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().Codec().DecodeAPER(freshHex("000000"))
		if err3 != nil {
			t.Fatal(err3)
		}
		fields = append(fields, cellTrafficTraceIEFieldfreshMust(s11.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().New(v3.Value)))
		body := cellTrafficTracefreshMust(s19.NewCellTrafficTrace(fields))
		env := initiatingMessagefreshMust(s19.CellTrafficTraceProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00344022000004006f0002000000cf00020000014d4008000000000000000001794003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("F1CTrafficTransfer", func(t *testing.T) {
		var fields s11.F1CTrafficTransferIEContainer
		v0, _, err0 := s11.F1CTrafficTransferIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, f1CTrafficTransferIEFieldfreshMust(s11.F1CTrafficTransferIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.F1CTrafficTransferIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, f1CTrafficTransferIEFieldfreshMust(s11.F1CTrafficTransferIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.F1CTrafficTransferIEs().F1CTrafficContainer().Codec().DecodeAPER(freshHex("00"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, f1CTrafficTransferIEFieldfreshMust(s11.F1CTrafficTransferIEs().F1CTrafficContainer().New(v2.Value)))
		body := f1CTrafficTransferfreshMust(s19.NewF1CTrafficTransfer(fields))
		env := initiatingMessagefreshMust(s19.F1CTrafficTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00374014000003006f0002000000cf00020000018d000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("UERadioCapabilityIDMappingRequest", func(t *testing.T) {
		var fields s11.UERadioCapabilityIDMappingRequestIEContainer
		v0, _, err0 := s11.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Codec().DecodeAPER(freshHex("00"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, uERadioCapabilityIDMappingRequestIEFieldfreshMust(s11.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().New(v0.Value)))
		body := uERadioCapabilityIDMappingRequestfreshMust(s20.NewUERadioCapabilityIDMappingRequest(fields))
		env := initiatingMessagefreshMust(s20.UERadioCapabilityIDMappingProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00380008000001017a000100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("UERadioCapabilityIDMappingResponse", func(t *testing.T) {
		var fields s11.UERadioCapabilityIDMappingResponseIEContainer
		v0, _, err0 := s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Codec().DecodeAPER(freshHex("00"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, uERadioCapabilityIDMappingResponseIEFieldfreshMust(s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().New(v0.Value)))
		v1, _, err1 := s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Codec().DecodeAPER(freshHex("00"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, uERadioCapabilityIDMappingResponseIEFieldfreshMust(s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().New(v1.Value)))
		body := uERadioCapabilityIDMappingResponsefreshMust(s20.NewUERadioCapabilityIDMappingResponse(fields))
		env := successfulOutcomefreshMust(s20.UERadioCapabilityIDMappingProcedure().Successful().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUSuccessfulOutcome(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("2038000d000002017a0001000190400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("AccessAndMobilityIndication", func(t *testing.T) {
		var fields s16.AccessAndMobilityIndicationIEContainer
		body := accessAndMobilityIndicationfreshMust(s19.NewAccessAndMobilityIndication(fields))
		env := initiatingMessagefreshMust(s19.AccessAndMobilityIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("00394003000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("CPCCancel", func(t *testing.T) {
		var fields s11.CPCCancelIEContainer
		v0, _, err0 := s11.CPCCancelIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, cPCCancelIEFieldfreshMust(s11.CPCCancelIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.CPCCancelIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, cPCCancelIEFieldfreshMust(s11.CPCCancelIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.CPCCancelIEs().TargetSgNBID().Codec().DecodeAPER(freshHex("0000000000000000"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, cPCCancelIEFieldfreshMust(s11.CPCCancelIEs().TargetSgNBID().New(v2.Value)))
		body := cPCCancelfreshMust(s19.NewCPCCancel(fields))
		env := initiatingMessagefreshMust(s19.CPCCancelProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("003b401b000003006f0002000000cf0002000000ef00080000000000000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("RachIndication", func(t *testing.T) {
		var fields s17.RachIndicationIEContainer
		v0, _, err0 := s17.RachIndicationIEs().RaReportIndicationList().Codec().DecodeAPER(freshHex("00000000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, rachIndicationIEFieldfreshMust(s17.RachIndicationIEs().RaReportIndicationList().New(v0.Value)))
		body := rachIndicationfreshMust(s19.NewRachIndication(fields))
		env := initiatingMessagefreshMust(s19.RachIndicationProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("003c400b00000101bf000400000000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SCGFailureInformationReport", func(t *testing.T) {
		var fields s11.SCGFailureInformationReportIEContainer
		v0, _, err0 := s11.SCGFailureInformationReportIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sCGFailureInformationReportIEFieldfreshMust(s11.SCGFailureInformationReportIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.SCGFailureInformationReportIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sCGFailureInformationReportIEFieldfreshMust(s11.SCGFailureInformationReportIEs().SgNBUEX2APID().New(v1.Value)))
		v2, _, err2 := s11.SCGFailureInformationReportIEs().SCGFailureReportContainer().Codec().DecodeAPER(freshHex("00"))
		if err2 != nil {
			t.Fatal(err2)
		}
		fields = append(fields, sCGFailureInformationReportIEFieldfreshMust(s11.SCGFailureInformationReportIEs().SCGFailureReportContainer().New(v2.Value)))
		body := sCGFailureInformationReportfreshMust(s19.NewSCGFailureInformationReport(fields))
		env := initiatingMessagefreshMust(s19.ScgFailureInformationReportProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("003d4014000003006f4002000000cf4002000001c4400100")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
	t.Run("SCGFailureTransfer", func(t *testing.T) {
		var fields s11.SCGFailureTransferIEContainer
		v0, _, err0 := s11.SCGFailureTransferIEs().MeNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err0 != nil {
			t.Fatal(err0)
		}
		fields = append(fields, sCGFailureTransferIEFieldfreshMust(s11.SCGFailureTransferIEs().MeNBUEX2APID().New(v0.Value)))
		v1, _, err1 := s11.SCGFailureTransferIEs().SgNBUEX2APID().Codec().DecodeAPER(freshHex("0000"))
		if err1 != nil {
			t.Fatal(err1)
		}
		fields = append(fields, sCGFailureTransferIEFieldfreshMust(s11.SCGFailureTransferIEs().SgNBUEX2APID().New(v1.Value)))
		body := sCGFailureTransferfreshMust(s19.NewSCGFailureTransfer(fields))
		env := initiatingMessagefreshMust(s19.ScgFailureTransferProcedure().Initiating().Build(body))
		pdu := x2APPDUfreshMust(s20.NewX2APPDUInitiatingMessage(env))
		report, err := s20.ValidateMessage(&pdu)
		if err != nil || len(report.Issues) != 0 {
			t.Fatalf("validation: %+v, %v", report, err)
		}
		wire, err := pdu.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(wire, freshHex("003e400f000002006f4002000000cf40020000")) {
			t.Fatalf("fresh bytes = %x, %v", wire, err)
		}
	})
}
