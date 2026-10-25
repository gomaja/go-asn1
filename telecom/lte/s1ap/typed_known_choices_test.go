// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

// TS 36.413 V19.2.0 §9.3.4 and Annex B.2; X.691 (02/2021) §23.8.
// Source-derived complete values checked by an independent APER implementation.
func TestEveryKnownChoiceExtensionHasNoUnknownObservation(t *testing.T) {
	t.Run("S1AP-IEs.AreaScopeOfMDT.tAIBased", func(t *testing.T) {
		wire, err := hex.DecodeString("8006000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s33.AreaScopeOfMDT
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.AreaScopeOfMDTChoiceTAIBased {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.ENB-ID.short-macroENB-ID", func(t *testing.T) {
		wire, err := hex.DecodeString("8003000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s15.ENBID
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.ENBIDChoiceShortMacroENBID {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.ENB-ID.long-macroENB-ID", func(t *testing.T) {
		wire, err := hex.DecodeString("8103000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s15.ENBID
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.ENBIDChoiceLongMacroENBID {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.LastVisitedCell-Item.nG-RAN-Cell", func(t *testing.T) {
		wire, err := hex.DecodeString("800100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s42.LastVisitedCellItem
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.LastVisitedCellItemChoiceNGRANCell {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.MDTMode.mDTMode-Extension", func(t *testing.T) {
		wire, err := hex.DecodeString("800600c540020000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s48.MDTMode
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.MDTModeChoiceMDTModeExtension {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.RIMRoutingAddress.targetRNC-ID", func(t *testing.T) {
		wire, err := hex.DecodeString("80080000000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s34.RIMRoutingAddress
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.RIMRoutingAddressChoiceTargetRNCID {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.RIMRoutingAddress.eHRPD-Sector-ID", func(t *testing.T) {
		wire, err := hex.DecodeString("811000000000000000000000000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s34.RIMRoutingAddress
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.RIMRoutingAddressChoiceEHRPDSectorID {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.SONInformation.sONInformation-Extension", func(t *testing.T) {
		wire, err := hex.DecodeString("800600ce40020000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s51.SONInformation
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONInformationChoiceSONInformationExtension {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("S1AP-IEs.TargetID.targetgNgRanNode-ID", func(t *testing.T) {
		wire, err := hex.DecodeString("800e0000000000000000000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s34.TargetID
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.TargetIDChoiceTargetgNgRanNodeID {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.multiCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("8003000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceMultiCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.eventTriggeredCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("810100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.hOReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("8206000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceHOReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.eutranCellActivation", func(t *testing.T) {
		wire, err := hex.DecodeString("830400000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceEutranCellActivation {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.energySavingsIndication", func(t *testing.T) {
		wire, err := hex.DecodeString("84050000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceEnergySavingsIndication {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferRequestContainer.failureEventReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("85020000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferRequestContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferRequestContainerChoiceFailureEventReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.multiCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("80050000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceMultiCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.eventTriggeredCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("81020000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.hOReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("820100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceHOReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.eutranCellActivation", func(t *testing.T) {
		wire, err := hex.DecodeString("8303000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceEutranCellActivation {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.energySavingsIndication", func(t *testing.T) {
		wire, err := hex.DecodeString("840100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceEnergySavingsIndication {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferResponseContainer.failureEventReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("850100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s24.SONtransferResponseContainer
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferResponseContainerChoiceFailureEventReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.multiCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("800100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceMultiCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.eventTriggeredCellLoadReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("810100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.hOReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("820100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceHOReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.eutranCellActivation", func(t *testing.T) {
		wire, err := hex.DecodeString("830100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceEutranCellActivation {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.energySavingsIndication", func(t *testing.T) {
		wire, err := hex.DecodeString("840100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceEnergySavingsIndication {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.SONtransferCause.failureEventReporting", func(t *testing.T) {
		wire, err := hex.DecodeString("850100")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s20.SONtransferCause
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.SONtransferCauseChoiceFailureEventReporting {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.CellLoadReportingResponse.eHRPD", func(t *testing.T) {
		wire, err := hex.DecodeString("80050000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s18.CellLoadReportingResponse
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.CellLoadReportingResponseChoiceEHRPD {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.IRAT-Cell-ID.eHRPD", func(t *testing.T) {
		wire, err := hex.DecodeString("801000000000000000000000000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s18.IRATCellID
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.IRATCellIDChoiceEHRPD {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
	t.Run("SonTransfer-IEs.MultiCellLoadReportingResponse-Item.eHRPD", func(t *testing.T) {
		wire, err := hex.DecodeString("801600000000000000000000000000000000000000000000")
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
			var value s19.MultiCellLoadReportingResponseItem
			report, err := value.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 || value.Choice != s00.MultiCellLoadReportingResponseItemChoiceEHRPD {
				t.Fatalf("choice=%d report=%+v err=%v", value.Choice, report, err)
			}
			out, err := value.MarshalAPER()
			if err != nil || !bytes.Equal(out, wire) {
				t.Fatalf("replay=%x err=%v", out, err)
			}
		}
	})
}
