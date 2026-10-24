// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s13 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s13

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.InformationForCECapableUEsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.InformationForCECapableUEsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CellIDBroadcastItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			s12.BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CellIDCancelledItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CellIDCancelledItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CellTypeExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CellTypeExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CompletedCellinEAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CompletedCellinEAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CompletedCellinTAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CompletedCellinTAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.ConnectedengNBItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.ConnectedengNBItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.ContextatSourceExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.ContextatSourceExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s07.DAPSRequestInfoExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s07.DAPSRequestInfoExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.DAPSResponseInfoExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.DAPSResponseInfoExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.DAPSResponseInfoItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.DAPSResponseInfoItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.DLCPSecurityInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.DLCPSecurityInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainer(v *s08.DeactivateTraceIEContainer, s *aper.SemanticCapture) {
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
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainer(v *s08.DeactivateTraceIEContainer, s *aper.SemanticComparison) {
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
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s08.DownlinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s08.DownlinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENBX2ExtTLAExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENBX2ExtTLAExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENDCSONConfigurationTransferExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENDCSONConfigurationTransferExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENDCSONeNBIdentificationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENDCSONeNBIdentificationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENDCSONengNBIdentificationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENDCSONengNBIdentificationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENDCTransferTypeReplyExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENDCTransferTypeReplyExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ENDCTransferTypeRequestExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ENDCTransferTypeRequestExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABAdmittedItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABAdmittedItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABDataForwardingItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABDataForwardingItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABQoSParametersExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABQoSParametersExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABModifyItemBearerModConfExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABModifyItemBearerModConfExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABModifyItemBearerModResExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABModifyItemBearerModResExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABSecurityResultItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABSecurityResultItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABSetupItemBearerSUResExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABSetupItemBearerSUResExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.ERABSetupItemCtxtSUResExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.ERABSetupItemCtxtSUResExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ERABToBeSwitchedULItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ERABToBeSwitchedULItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ERABToBeUpdatedItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ERABToBeUpdatedItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ERABUsageReportItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ERABUsageReportItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.EUTRANCGIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.EUTRANCGIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.EventL1LoggedMDTConfigExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.EventL1LoggedMDTConfigExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(v *s09.EventTriggerExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(v *s09.EventTriggerExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ExpectedUEActivityBehaviourExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ExpectedUEActivityBehaviourExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ExpectedUEBehaviourExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ExpectedUEBehaviourExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.FiveGSTAIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.FiveGSTAIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ForbiddenLAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ForbiddenLAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ForbiddenTAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ForbiddenTAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GBRQosInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GBRQosInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GERANCellIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GERANCellIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGNBExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GNBExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGNBExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGNBExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GNBExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGNBExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GUMMEIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GUMMEIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GlobalENBIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GlobalENBIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GlobalEnGNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GlobalEnGNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.GlobalGNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.GlobalGNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainer(v *s09.HandoverSuccessIEContainer, s *aper.SemanticCapture) {
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
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainer(v *s09.HandoverSuccessIEContainer, s *aper.SemanticComparison) {
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
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.InterSystemMeasurementItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.InterSystemMeasurementItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.InterSystemMeasurementParametersExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.InterSystemMeasurementParametersExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.IntersystemMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.IntersystemMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.LAIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeLAIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.LAIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeLAIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.LTENTNTAIInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.LTENTNTAIInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.LastVisitedPSCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.LastVisitedPSCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ListeningSubframePatternExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ListeningSubframePatternExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.LoggedMBSFNMDTExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.LoggedMBSFNMDTExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.M1PeriodicReportingExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.M1PeriodicReportingExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M1ThresholdEventA2ExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M1ThresholdEventA2ExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M3ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M3ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M4ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M4ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M5ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M5ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M6ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M6ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.M7ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.M7ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.MBSFNResultToLogInfoExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.MBSFNResultToLogInfoExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(v *s10.MMECPRelocationIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(v *s10.MMECPRelocationIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.MutingPatternInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.MutingPatternInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(v *s10.NASDeliveryIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(v *s10.NASDeliveryIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NBIoTPagingEDRXInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NBIoTPagingEDRXInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NGENBExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNGENBExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NGENBExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNGENBExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NRCGIExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NRCGIExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NRUESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NRUESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.NRV2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.NRV2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PC5FlowBitRatesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PC5FlowBitRatesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PC5QoSFlowItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PC5QoSFlowItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PSCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PSCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.PagingEDRXInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func DeactivateTraceIEValueERABIEContainerListCodec(table s00.DeactivateTraceIEValueIETable) s08.DeactivateTraceIEValueERABIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DeactivateTraceIEValueERABIEContainerListValueCodec{}
	}
	return func() s08.DeactivateTraceIEValueERABIEContainerListValueCodec {
		sealed := s08.DeactivateTraceIEValueERABIEContainerListValueCodec{}
		*s08.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DeactivateTraceIEValueERABIEContainerList, error) {
			value, err := (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DeactivateTraceIEValueERABIEContainerList(value), err
		}
		*s08.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DeactivateTraceIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s08.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s08.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DeactivateTraceIEValueERABIEContainerList, options aper.DecodeState) (s08.DeactivateTraceIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DeactivateTraceIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	return func() s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList(value), err
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	return func() s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList(value), err
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EventTriggerExtIEValueERABIEContainerListCodec(table s00.EventTriggerExtIEValueIETable) s09.EventTriggerExtIEValueERABIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.EventTriggerExtIEValueERABIEContainerListValueCodec{}
	}
	return func() s09.EventTriggerExtIEValueERABIEContainerListValueCodec {
		sealed := s09.EventTriggerExtIEValueERABIEContainerListValueCodec{}
		*s09.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventTriggerExtIEValueERABIEContainerList, error) {
			value, err := (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.EventTriggerExtIEValueERABIEContainerList(value), err
		}
		*s09.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.EventTriggerExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s09.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s09.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.EventTriggerExtIEValueERABIEContainerList, options aper.DecodeState) (s09.EventTriggerExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.EventTriggerExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverSuccessIEValueERABIEContainerListCodec(table s00.HandoverSuccessIEValueIETable) s09.HandoverSuccessIEValueERABIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.HandoverSuccessIEValueERABIEContainerListValueCodec{}
	}
	return func() s09.HandoverSuccessIEValueERABIEContainerListValueCodec {
		sealed := s09.HandoverSuccessIEValueERABIEContainerListValueCodec{}
		*s09.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.HandoverSuccessIEValueERABIEContainerList, error) {
			value, err := (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.HandoverSuccessIEValueERABIEContainerList(value), err
		}
		*s09.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.HandoverSuccessIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s09.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s09.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.HandoverSuccessIEValueERABIEContainerList, options aper.DecodeState) (s09.HandoverSuccessIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.HandoverSuccessIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MMECPRelocationIndicationIEValueERABIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable) s10.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s10.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s10.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec{}
		*s10.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueERABIEContainerList, error) {
			value, err := (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MMECPRelocationIndicationIEValueERABIEContainerList(value), err
		}
		*s10.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MMECPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s10.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MMECPRelocationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MMECPRelocationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec{}
	}
	return func() s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec {
		sealed := s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec{}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, error) {
			value, err := (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList(value), err
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s10.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NASDeliveryIndicationIEValueERABIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable) s10.NASDeliveryIndicationIEValueERABIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.NASDeliveryIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s10.NASDeliveryIndicationIEValueERABIEContainerListValueCodec {
		sealed := s10.NASDeliveryIndicationIEValueERABIEContainerListValueCodec{}
		*s10.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueERABIEContainerList, error) {
			value, err := (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.NASDeliveryIndicationIEValueERABIEContainerList(value), err
		}
		*s10.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.NASDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s10.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.NASDeliveryIndicationIEValueERABIEContainerList, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.NASDeliveryIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CellIDCancelledItemExtIEsValueExtensionFieldTableCodec(table s00.CellIDCancelledItemExtIEsValueExtensionTable) s07.CellIDCancelledItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellIDCancelledItemExtIEsExtFieldValueCodec{}
	}
	return func() s07.CellIDCancelledItemExtIEsExtFieldValueCodec {
		sealed := s07.CellIDCancelledItemExtIEsExtFieldValueCodec{}
		*s07.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellIDCancelledItemExtIEsExtField, error) {
			var field s07.CellIDCancelledItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CellIDCancelledItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CellIDCancelledItemExtIEsExtField, options aper.DecodeState) (s07.CellIDCancelledItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CellIDCancelledItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionFieldTableCodec(table s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable) s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec{}
	}
	return func() s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec {
		sealed := s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec{}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, error) {
			var field s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, options aper.DecodeState) (s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CellTypeExtIEsValueExtensionFieldTableCodec(table s00.CellTypeExtIEsValueExtensionTable) s07.CellTypeExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellTypeExtIEsExtFieldValueCodec{}
	}
	return func() s07.CellTypeExtIEsExtFieldValueCodec {
		sealed := s07.CellTypeExtIEsExtFieldValueCodec{}
		*s07.BridgeCellTypeExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellTypeExtIEsExtField, error) {
			var field s07.CellTypeExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCellTypeExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CellTypeExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCellTypeExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CellTypeExtIEsExtField, options aper.DecodeState) (s07.CellTypeExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCellTypeExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CellTypeExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellTypeExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CompletedCellinEAIItemExtIEsValueExtensionFieldTableCodec(table s00.CompletedCellinEAIItemExtIEsValueExtensionTable) s07.CompletedCellinEAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCompletedCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CompletedCellinEAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s07.CompletedCellinEAIItemExtIEsExtFieldValueCodec {
		sealed := s07.CompletedCellinEAIItemExtIEsExtFieldValueCodec{}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CompletedCellinEAIItemExtIEsExtField, error) {
			var field s07.CompletedCellinEAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CompletedCellinEAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CompletedCellinEAIItemExtIEsExtField, options aper.DecodeState) (s07.CompletedCellinEAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CompletedCellinEAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CompletedCellinTAIItemExtIEsValueExtensionFieldTableCodec(table s00.CompletedCellinTAIItemExtIEsValueExtensionTable) s07.CompletedCellinTAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCompletedCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CompletedCellinTAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s07.CompletedCellinTAIItemExtIEsExtFieldValueCodec {
		sealed := s07.CompletedCellinTAIItemExtIEsExtFieldValueCodec{}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CompletedCellinTAIItemExtIEsExtField, error) {
			var field s07.CompletedCellinTAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CompletedCellinTAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CompletedCellinTAIItemExtIEsExtField, options aper.DecodeState) (s07.CompletedCellinTAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CompletedCellinTAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ConnectedengNBItemExtIEsValueExtensionFieldTableCodec(table s00.ConnectedengNBItemExtIEsValueExtensionTable) s07.ConnectedengNBItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeConnectedengNBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.ConnectedengNBItemExtIEsExtFieldValueCodec{}
	}
	return func() s07.ConnectedengNBItemExtIEsExtFieldValueCodec {
		sealed := s07.ConnectedengNBItemExtIEsExtFieldValueCodec{}
		*s07.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.ConnectedengNBItemExtIEsExtField, error) {
			var field s07.ConnectedengNBItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.ConnectedengNBItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.ConnectedengNBItemExtIEsExtField, options aper.DecodeState) (s07.ConnectedengNBItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.ConnectedengNBItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ContextatSourceExtIEsValueExtensionFieldTableCodec(table s00.ContextatSourceExtIEsValueExtensionTable) s07.ContextatSourceExtIEsExtFieldValueCodec {
	if !*s00.BridgeContextatSourceExtIEsValueExtensionTableFieldBound(&table) {
		return s07.ContextatSourceExtIEsExtFieldValueCodec{}
	}
	return func() s07.ContextatSourceExtIEsExtFieldValueCodec {
		sealed := s07.ContextatSourceExtIEsExtFieldValueCodec{}
		*s07.BridgeContextatSourceExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.ContextatSourceExtIEsExtField, error) {
			var field s07.ContextatSourceExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeContextatSourceExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.ContextatSourceExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeContextatSourceExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.ContextatSourceExtIEsExtField, options aper.DecodeState) (s07.ContextatSourceExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeContextatSourceExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.ContextatSourceExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeContextatSourceExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CriticalityDiagnosticsExtIEsValueExtensionFieldTableCodec(table s00.CriticalityDiagnosticsExtIEsValueExtensionTable) s07.CriticalityDiagnosticsExtIEsExtFieldValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CriticalityDiagnosticsExtIEsExtFieldValueCodec{}
	}
	return func() s07.CriticalityDiagnosticsExtIEsExtFieldValueCodec {
		sealed := s07.CriticalityDiagnosticsExtIEsExtFieldValueCodec{}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CriticalityDiagnosticsExtIEsExtField, error) {
			var field s07.CriticalityDiagnosticsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CriticalityDiagnosticsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CriticalityDiagnosticsExtIEsExtField, options aper.DecodeState) (s07.CriticalityDiagnosticsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CriticalityDiagnosticsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CriticalityDiagnosticsIEItemExtIEsValueExtensionFieldTableCodec(table s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable) s07.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsIEItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec{}
	}
	return func() s07.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec {
		sealed := s07.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec{}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CriticalityDiagnosticsIEItemExtIEsExtField, error) {
			var field s07.CriticalityDiagnosticsIEItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.CriticalityDiagnosticsIEItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.CriticalityDiagnosticsIEItemExtIEsExtField, options aper.DecodeState) (s07.CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.CriticalityDiagnosticsIEItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DAPSRequestInfoExtIEsValueExtensionFieldTableCodec(table s00.DAPSRequestInfoExtIEsValueExtensionTable) s08.DAPSRequestInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSRequestInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DAPSRequestInfoExtIEsExtFieldValueCodec{}
	}
	return func() s08.DAPSRequestInfoExtIEsExtFieldValueCodec {
		sealed := s08.DAPSRequestInfoExtIEsExtFieldValueCodec{}
		*s08.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.DAPSRequestInfoExtIEsExtField, error) {
			var field s07.DAPSRequestInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s07.DAPSRequestInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s07.DAPSRequestInfoExtIEsExtField, options aper.DecodeState) (s07.DAPSRequestInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s07.DAPSRequestInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoExtIEsValueExtensionFieldTableCodec(table s00.DAPSResponseInfoExtIEsValueExtensionTable) s08.DAPSResponseInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DAPSResponseInfoExtIEsExtFieldValueCodec{}
	}
	return func() s08.DAPSResponseInfoExtIEsExtFieldValueCodec {
		sealed := s08.DAPSResponseInfoExtIEsExtFieldValueCodec{}
		*s08.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DAPSResponseInfoExtIEsExtField, error) {
			var field s08.DAPSResponseInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.DAPSResponseInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.DAPSResponseInfoExtIEsExtField, options aper.DecodeState) (s08.DAPSResponseInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.DAPSResponseInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoItemExtIEsValueExtensionFieldTableCodec(table s00.DAPSResponseInfoItemExtIEsValueExtensionTable) s08.DAPSResponseInfoItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DAPSResponseInfoItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.DAPSResponseInfoItemExtIEsExtFieldValueCodec {
		sealed := s08.DAPSResponseInfoItemExtIEsExtFieldValueCodec{}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DAPSResponseInfoItemExtIEsExtField, error) {
			var field s08.DAPSResponseInfoItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.DAPSResponseInfoItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.DAPSResponseInfoItemExtIEsExtField, options aper.DecodeState) (s08.DAPSResponseInfoItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.DAPSResponseInfoItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DLCPSecurityInformationExtIEsValueExtensionFieldTableCodec(table s00.DLCPSecurityInformationExtIEsValueExtensionTable) s08.DLCPSecurityInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeDLCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DLCPSecurityInformationExtIEsExtFieldValueCodec{}
	}
	return func() s08.DLCPSecurityInformationExtIEsExtFieldValueCodec {
		sealed := s08.DLCPSecurityInformationExtIEsExtFieldValueCodec{}
		*s08.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DLCPSecurityInformationExtIEsExtField, error) {
			var field s08.DLCPSecurityInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.DLCPSecurityInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.DLCPSecurityInformationExtIEsExtField, options aper.DecodeState) (s08.DLCPSecurityInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.DLCPSecurityInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable) s08.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
		sealed := s08.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENBStatusTransferTransparentContainerExtIEsExtField, error) {
			var field s08.ENBStatusTransferTransparentContainerExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENBStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENBStatusTransferTransparentContainerExtIEsExtField, options aper.DecodeState) (s08.ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENBStatusTransferTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBX2ExtTLAExtIEsValueExtensionFieldTableCodec(table s00.ENBX2ExtTLAExtIEsValueExtensionTable) s08.ENBX2ExtTLAExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBX2ExtTLAExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENBX2ExtTLAExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENBX2ExtTLAExtIEsExtFieldValueCodec {
		sealed := s08.ENBX2ExtTLAExtIEsExtFieldValueCodec{}
		*s08.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENBX2ExtTLAExtIEsExtField, error) {
			var field s08.ENBX2ExtTLAExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENBX2ExtTLAExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENBX2ExtTLAExtIEsExtField, options aper.DecodeState) (s08.ENBX2ExtTLAExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENBX2ExtTLAExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONConfigurationTransferExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable) s08.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec {
		sealed := s08.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec{}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONConfigurationTransferExtIEsExtField, error) {
			var field s08.ENDCSONConfigurationTransferExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENDCSONConfigurationTransferExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONConfigurationTransferExtIEsExtField, options aper.DecodeState) (s08.ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONConfigurationTransferExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONeNBIdentificationExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable) s08.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONeNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec {
		sealed := s08.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec{}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONeNBIdentificationExtIEsExtField, error) {
			var field s08.ENDCSONeNBIdentificationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENDCSONeNBIdentificationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONeNBIdentificationExtIEsExtField, options aper.DecodeState) (s08.ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONeNBIdentificationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONengNBIdentificationExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable) s08.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONengNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec {
		sealed := s08.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec{}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONengNBIdentificationExtIEsExtField, error) {
			var field s08.ENDCSONengNBIdentificationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENDCSONengNBIdentificationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONengNBIdentificationExtIEsExtField, options aper.DecodeState) (s08.ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONengNBIdentificationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENDCTransferTypeReplyExtIEsValueExtensionFieldTableCodec(table s00.ENDCTransferTypeReplyExtIEsValueExtensionTable) s08.ENDCTransferTypeReplyExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCTransferTypeReplyExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCTransferTypeReplyExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENDCTransferTypeReplyExtIEsExtFieldValueCodec {
		sealed := s08.ENDCTransferTypeReplyExtIEsExtFieldValueCodec{}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCTransferTypeReplyExtIEsExtField, error) {
			var field s08.ENDCTransferTypeReplyExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENDCTransferTypeReplyExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENDCTransferTypeReplyExtIEsExtField, options aper.DecodeState) (s08.ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENDCTransferTypeReplyExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENDCTransferTypeRequestExtIEsValueExtensionFieldTableCodec(table s00.ENDCTransferTypeRequestExtIEsValueExtensionTable) s08.ENDCTransferTypeRequestExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCTransferTypeRequestExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCTransferTypeRequestExtIEsExtFieldValueCodec{}
	}
	return func() s08.ENDCTransferTypeRequestExtIEsExtFieldValueCodec {
		sealed := s08.ENDCTransferTypeRequestExtIEsExtFieldValueCodec{}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCTransferTypeRequestExtIEsExtField, error) {
			var field s08.ENDCTransferTypeRequestExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ENDCTransferTypeRequestExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ENDCTransferTypeRequestExtIEsExtField, options aper.DecodeState) (s08.ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ENDCTransferTypeRequestExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemExtIEsValueExtensionFieldTableCodec(table s00.ERABAdmittedItemExtIEsValueExtensionTable) s08.ERABAdmittedItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABAdmittedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABAdmittedItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABAdmittedItemExtIEsExtFieldValueCodec {
		sealed := s08.ERABAdmittedItemExtIEsExtFieldValueCodec{}
		*s08.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABAdmittedItemExtIEsExtField, error) {
			var field s08.ERABAdmittedItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABAdmittedItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABAdmittedItemExtIEsExtField, options aper.DecodeState) (s08.ERABAdmittedItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABAdmittedItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemExtIEsValueExtensionFieldTableCodec(table s00.ERABDataForwardingItemExtIEsValueExtensionTable) s08.ERABDataForwardingItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABDataForwardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABDataForwardingItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABDataForwardingItemExtIEsExtFieldValueCodec {
		sealed := s08.ERABDataForwardingItemExtIEsExtFieldValueCodec{}
		*s08.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABDataForwardingItemExtIEsExtField, error) {
			var field s08.ERABDataForwardingItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABDataForwardingItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABDataForwardingItemExtIEsExtField, options aper.DecodeState) (s08.ERABDataForwardingItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABDataForwardingItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable) s08.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec {
		sealed := s08.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec{}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeReqExtIEsExtField, error) {
			var field s08.ERABFailedToResumeItemResumeReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABFailedToResumeItemResumeReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToResumeItemResumeReqExtIEsExtField, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToResumeItemResumeReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable) s08.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec {
		sealed := s08.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec{}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeResExtIEsExtField, error) {
			var field s08.ERABFailedToResumeItemResumeResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABFailedToResumeItemResumeResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToResumeItemResumeResExtIEsExtField, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToResumeItemResumeResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToSetupItemHOReqAckExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable) s08.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec {
		sealed := s08.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec{}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, error) {
			var field s08.ERABFailedToSetupItemHOReqAckExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, options aper.DecodeState) (s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABItemExtIEsValueExtensionFieldTableCodec(table s00.ERABItemExtIEsValueExtensionTable) s08.ERABItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABItemExtIEsExtFieldValueCodec {
		sealed := s08.ERABItemExtIEsExtFieldValueCodec{}
		*s08.BridgeERABItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABItemExtIEsExtField, error) {
			var field s08.ERABItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABItemExtIEsExtField, options aper.DecodeState) (s08.ERABItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfExtIEsValueExtensionFieldTableCodec(table s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable) s08.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec {
		sealed := s08.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec{}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABModifyItemBearerModConfExtIEsExtField, error) {
			var field s08.ERABModifyItemBearerModConfExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABModifyItemBearerModConfExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABModifyItemBearerModConfExtIEsExtField, options aper.DecodeState) (s08.ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABModifyItemBearerModConfExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResExtIEsValueExtensionFieldTableCodec(table s00.ERABModifyItemBearerModResExtIEsValueExtensionTable) s08.ERABModifyItemBearerModResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABModifyItemBearerModResExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABModifyItemBearerModResExtIEsExtFieldValueCodec {
		sealed := s08.ERABModifyItemBearerModResExtIEsExtFieldValueCodec{}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABModifyItemBearerModResExtIEsExtField, error) {
			var field s08.ERABModifyItemBearerModResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABModifyItemBearerModResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABModifyItemBearerModResExtIEsExtField, options aper.DecodeState) (s08.ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABModifyItemBearerModResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable) s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
		sealed := s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, error) {
			var field s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, options aper.DecodeState) (s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABQoSParametersExtIEsValueExtensionFieldTableCodec(table s00.ERABQoSParametersExtIEsValueExtensionTable) s08.ERABQoSParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABQoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABQoSParametersExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABQoSParametersExtIEsExtFieldValueCodec {
		sealed := s08.ERABQoSParametersExtIEsExtFieldValueCodec{}
		*s08.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABQoSParametersExtIEsExtField, error) {
			var field s08.ERABQoSParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABQoSParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABQoSParametersExtIEsExtField, options aper.DecodeState) (s08.ERABQoSParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABQoSParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABReleaseItemBearerRelCompExtIEsValueExtensionFieldTableCodec(table s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable) s08.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec {
		sealed := s08.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec{}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABReleaseItemBearerRelCompExtIEsExtField, error) {
			var field s08.ERABReleaseItemBearerRelCompExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABReleaseItemBearerRelCompExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABReleaseItemBearerRelCompExtIEsExtField, options aper.DecodeState) (s08.ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABReleaseItemBearerRelCompExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABSecurityResultItemExtIEsValueExtensionFieldTableCodec(table s00.ERABSecurityResultItemExtIEsValueExtensionTable) s08.ERABSecurityResultItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSecurityResultItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABSecurityResultItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABSecurityResultItemExtIEsExtFieldValueCodec {
		sealed := s08.ERABSecurityResultItemExtIEsExtFieldValueCodec{}
		*s08.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSecurityResultItemExtIEsExtField, error) {
			var field s08.ERABSecurityResultItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABSecurityResultItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABSecurityResultItemExtIEsExtField, options aper.DecodeState) (s08.ERABSecurityResultItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABSecurityResultItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupItemBearerSUResExtIEsValueExtensionFieldTableCodec(table s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable) s08.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec{}
	}
	return func() s08.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec {
		sealed := s08.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec{}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSetupItemBearerSUResExtIEsExtField, error) {
			var field s08.ERABSetupItemBearerSUResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABSetupItemBearerSUResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABSetupItemBearerSUResExtIEsExtField, options aper.DecodeState) (s08.ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABSetupItemBearerSUResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupItemCtxtSUResExtIEsValueExtensionFieldTableCodec(table s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable) s09.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec{}
	}
	return func() s09.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec {
		sealed := s09.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec{}
		*s09.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSetupItemCtxtSUResExtIEsExtField, error) {
			var field s08.ERABSetupItemCtxtSUResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.ERABSetupItemCtxtSUResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.ERABSetupItemCtxtSUResExtIEsExtField, options aper.DecodeState) (s08.ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.ERABSetupItemCtxtSUResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable) s09.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
	}
	return func() s09.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
		sealed := s09.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, error) {
			var field s09.ERABToBeModifiedItemBearerModIndExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, options aper.DecodeState) (s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedULItemExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable) s09.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec {
		sealed := s09.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec{}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeSwitchedULItemExtIEsExtField, error) {
			var field s09.ERABToBeSwitchedULItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ERABToBeSwitchedULItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeSwitchedULItemExtIEsExtField, options aper.DecodeState) (s09.ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeSwitchedULItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeUpdatedItemExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeUpdatedItemExtIEsValueExtensionTable) s09.ERABToBeUpdatedItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeUpdatedItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ERABToBeUpdatedItemExtIEsExtFieldValueCodec {
		sealed := s09.ERABToBeUpdatedItemExtIEsExtFieldValueCodec{}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeUpdatedItemExtIEsExtField, error) {
			var field s09.ERABToBeUpdatedItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ERABToBeUpdatedItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeUpdatedItemExtIEsExtField, options aper.DecodeState) (s09.ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeUpdatedItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABUsageReportItemExtIEsValueExtensionFieldTableCodec(table s00.ERABUsageReportItemExtIEsValueExtensionTable) s09.ERABUsageReportItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABUsageReportItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ERABUsageReportItemExtIEsExtFieldValueCodec {
		sealed := s09.ERABUsageReportItemExtIEsExtFieldValueCodec{}
		*s09.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABUsageReportItemExtIEsExtField, error) {
			var field s09.ERABUsageReportItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ERABUsageReportItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ERABUsageReportItemExtIEsExtField, options aper.DecodeState) (s09.ERABUsageReportItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ERABUsageReportItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EUTRANCGIExtIEsValueExtensionFieldTableCodec(table s00.EUTRANCGIExtIEsValueExtensionTable) s09.EUTRANCGIExtIEsExtFieldValueCodec {
	if !*s00.BridgeEUTRANCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EUTRANCGIExtIEsExtFieldValueCodec{}
	}
	return func() s09.EUTRANCGIExtIEsExtFieldValueCodec {
		sealed := s09.EUTRANCGIExtIEsExtFieldValueCodec{}
		*s09.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EUTRANCGIExtIEsExtField, error) {
			var field s09.EUTRANCGIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.EUTRANCGIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.EUTRANCGIExtIEsExtField, options aper.DecodeState) (s09.EUTRANCGIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.EUTRANCGIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EmergencyAreaIDBroadcastItemExtIEsValueExtensionFieldTableCodec(table s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable) s09.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeEmergencyAreaIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec {
		sealed := s09.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec{}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EmergencyAreaIDBroadcastItemExtIEsExtField, error) {
			var field s09.EmergencyAreaIDBroadcastItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.EmergencyAreaIDBroadcastItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.EmergencyAreaIDBroadcastItemExtIEsExtField, options aper.DecodeState) (s09.EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.EmergencyAreaIDBroadcastItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EmergencyAreaIDCancelledItemExtIEsValueExtensionFieldTableCodec(table s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable) s09.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeEmergencyAreaIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec {
		sealed := s09.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec{}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EmergencyAreaIDCancelledItemExtIEsExtField, error) {
			var field s09.EmergencyAreaIDCancelledItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.EmergencyAreaIDCancelledItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.EmergencyAreaIDCancelledItemExtIEsExtField, options aper.DecodeState) (s09.EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.EmergencyAreaIDCancelledItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EventL1LoggedMDTConfigExtIEsValueExtensionFieldTableCodec(table s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable) s09.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec {
	if !*s00.BridgeEventL1LoggedMDTConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec{}
	}
	return func() s09.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec {
		sealed := s09.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec{}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventL1LoggedMDTConfigExtIEsExtField, error) {
			var field s09.EventL1LoggedMDTConfigExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.EventL1LoggedMDTConfigExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.EventL1LoggedMDTConfigExtIEsExtField, options aper.DecodeState) (s09.EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.EventL1LoggedMDTConfigExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ExpectedUEActivityBehaviourExtIEsValueExtensionFieldTableCodec(table s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable) s09.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec {
	if !*s00.BridgeExpectedUEActivityBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec{}
	}
	return func() s09.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec {
		sealed := s09.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec{}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ExpectedUEActivityBehaviourExtIEsExtField, error) {
			var field s09.ExpectedUEActivityBehaviourExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ExpectedUEActivityBehaviourExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ExpectedUEActivityBehaviourExtIEsExtField, options aper.DecodeState) (s09.ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ExpectedUEActivityBehaviourExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ExpectedUEBehaviourExtIEsValueExtensionFieldTableCodec(table s00.ExpectedUEBehaviourExtIEsValueExtensionTable) s09.ExpectedUEBehaviourExtIEsExtFieldValueCodec {
	if !*s00.BridgeExpectedUEBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ExpectedUEBehaviourExtIEsExtFieldValueCodec{}
	}
	return func() s09.ExpectedUEBehaviourExtIEsExtFieldValueCodec {
		sealed := s09.ExpectedUEBehaviourExtIEsExtFieldValueCodec{}
		*s09.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ExpectedUEBehaviourExtIEsExtField, error) {
			var field s09.ExpectedUEBehaviourExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ExpectedUEBehaviourExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ExpectedUEBehaviourExtIEsExtField, options aper.DecodeState) (s09.ExpectedUEBehaviourExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ExpectedUEBehaviourExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func FiveGSTAIExtIEsValueExtensionFieldTableCodec(table s00.FiveGSTAIExtIEsValueExtensionTable) s09.FiveGSTAIExtIEsExtFieldValueCodec {
	if !*s00.BridgeFiveGSTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.FiveGSTAIExtIEsExtFieldValueCodec{}
	}
	return func() s09.FiveGSTAIExtIEsExtFieldValueCodec {
		sealed := s09.FiveGSTAIExtIEsExtFieldValueCodec{}
		*s09.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.FiveGSTAIExtIEsExtField, error) {
			var field s09.FiveGSTAIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.FiveGSTAIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.FiveGSTAIExtIEsExtField, options aper.DecodeState) (s09.FiveGSTAIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.FiveGSTAIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ForbiddenLAsItemExtIEsValueExtensionFieldTableCodec(table s00.ForbiddenLAsItemExtIEsValueExtensionTable) s09.ForbiddenLAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeForbiddenLAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ForbiddenLAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ForbiddenLAsItemExtIEsExtFieldValueCodec {
		sealed := s09.ForbiddenLAsItemExtIEsExtFieldValueCodec{}
		*s09.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ForbiddenLAsItemExtIEsExtField, error) {
			var field s09.ForbiddenLAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ForbiddenLAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ForbiddenLAsItemExtIEsExtField, options aper.DecodeState) (s09.ForbiddenLAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ForbiddenLAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ForbiddenTAsItemExtIEsValueExtensionFieldTableCodec(table s00.ForbiddenTAsItemExtIEsValueExtensionTable) s09.ForbiddenTAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeForbiddenTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ForbiddenTAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ForbiddenTAsItemExtIEsExtFieldValueCodec {
		sealed := s09.ForbiddenTAsItemExtIEsExtFieldValueCodec{}
		*s09.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ForbiddenTAsItemExtIEsExtField, error) {
			var field s09.ForbiddenTAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ForbiddenTAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ForbiddenTAsItemExtIEsExtField, options aper.DecodeState) (s09.ForbiddenTAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ForbiddenTAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GBRQosInformationExtIEsValueExtensionFieldTableCodec(table s00.GBRQosInformationExtIEsValueExtensionTable) s09.GBRQosInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeGBRQosInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GBRQosInformationExtIEsExtFieldValueCodec{}
	}
	return func() s09.GBRQosInformationExtIEsExtFieldValueCodec {
		sealed := s09.GBRQosInformationExtIEsExtFieldValueCodec{}
		*s09.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GBRQosInformationExtIEsExtField, error) {
			var field s09.GBRQosInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GBRQosInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GBRQosInformationExtIEsExtField, options aper.DecodeState) (s09.GBRQosInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GBRQosInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GERANCellIDExtIEsValueExtensionFieldTableCodec(table s00.GERANCellIDExtIEsValueExtensionTable) s09.GERANCellIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGERANCellIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GERANCellIDExtIEsExtFieldValueCodec{}
	}
	return func() s09.GERANCellIDExtIEsExtFieldValueCodec {
		sealed := s09.GERANCellIDExtIEsExtFieldValueCodec{}
		*s09.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GERANCellIDExtIEsExtField, error) {
			var field s09.GERANCellIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GERANCellIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GERANCellIDExtIEsExtField, options aper.DecodeState) (s09.GERANCellIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GERANCellIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GNBExtIEsValueExtensionFieldTableCodec(table s00.GNBExtIEsValueExtensionTable) s09.GNBExtIEsExtFieldValueCodec {
	if !*s00.BridgeGNBExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GNBExtIEsExtFieldValueCodec{}
	}
	return func() s09.GNBExtIEsExtFieldValueCodec {
		sealed := s09.GNBExtIEsExtFieldValueCodec{}
		*s09.BridgeGNBExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GNBExtIEsExtField, error) {
			var field s09.GNBExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGNBExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GNBExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGNBExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GNBExtIEsExtField, options aper.DecodeState) (s09.GNBExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGNBExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGNBExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GNBExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGNBExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGNBExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GUMMEIExtIEsValueExtensionFieldTableCodec(table s00.GUMMEIExtIEsValueExtensionTable) s09.GUMMEIExtIEsExtFieldValueCodec {
	if !*s00.BridgeGUMMEIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GUMMEIExtIEsExtFieldValueCodec{}
	}
	return func() s09.GUMMEIExtIEsExtFieldValueCodec {
		sealed := s09.GUMMEIExtIEsExtFieldValueCodec{}
		*s09.BridgeGUMMEIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GUMMEIExtIEsExtField, error) {
			var field s09.GUMMEIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGUMMEIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GUMMEIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGUMMEIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GUMMEIExtIEsExtField, options aper.DecodeState) (s09.GUMMEIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGUMMEIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GUMMEIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGUMMEIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GlobalENBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalENBIDExtIEsValueExtensionTable) s09.GlobalENBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalENBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalENBIDExtIEsExtFieldValueCodec{}
	}
	return func() s09.GlobalENBIDExtIEsExtFieldValueCodec {
		sealed := s09.GlobalENBIDExtIEsExtFieldValueCodec{}
		*s09.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalENBIDExtIEsExtField, error) {
			var field s09.GlobalENBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GlobalENBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GlobalENBIDExtIEsExtField, options aper.DecodeState) (s09.GlobalENBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GlobalENBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GlobalEnGNBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalEnGNBIDExtIEsValueExtensionTable) s09.GlobalEnGNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalEnGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalEnGNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s09.GlobalEnGNBIDExtIEsExtFieldValueCodec {
		sealed := s09.GlobalEnGNBIDExtIEsExtFieldValueCodec{}
		*s09.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalEnGNBIDExtIEsExtField, error) {
			var field s09.GlobalEnGNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GlobalEnGNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GlobalEnGNBIDExtIEsExtField, options aper.DecodeState) (s09.GlobalEnGNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GlobalEnGNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func GlobalGNBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalGNBIDExtIEsValueExtensionTable) s09.GlobalGNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalGNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s09.GlobalGNBIDExtIEsExtFieldValueCodec {
		sealed := s09.GlobalGNBIDExtIEsExtFieldValueCodec{}
		*s09.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalGNBIDExtIEsExtField, error) {
			var field s09.GlobalGNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.GlobalGNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.GlobalGNBIDExtIEsExtField, options aper.DecodeState) (s09.GlobalGNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.GlobalGNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func InformationForCECapableUEsExtIEsValueExtensionFieldTableCodec(table s00.InformationForCECapableUEsExtIEsValueExtensionTable) s09.InformationForCECapableUEsExtIEsExtFieldValueCodec {
	if !*s00.BridgeInformationForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InformationForCECapableUEsExtIEsExtFieldValueCodec{}
	}
	return func() s09.InformationForCECapableUEsExtIEsExtFieldValueCodec {
		sealed := s09.InformationForCECapableUEsExtIEsExtFieldValueCodec{}
		*s09.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InformationForCECapableUEsExtIEsExtField, error) {
			var field s09.InformationForCECapableUEsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.InformationForCECapableUEsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.InformationForCECapableUEsExtIEsExtField, options aper.DecodeState) (s09.InformationForCECapableUEsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.InformationForCECapableUEsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionFieldTableCodec(table s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable) s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec {
		sealed := s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec{}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, error) {
			var field s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, options aper.DecodeState) (s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func InterSystemMeasurementItemExtIEsValueExtensionFieldTableCodec(table s00.InterSystemMeasurementItemExtIEsValueExtensionTable) s09.InterSystemMeasurementItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeInterSystemMeasurementItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InterSystemMeasurementItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.InterSystemMeasurementItemExtIEsExtFieldValueCodec {
		sealed := s09.InterSystemMeasurementItemExtIEsExtFieldValueCodec{}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InterSystemMeasurementItemExtIEsExtField, error) {
			var field s09.InterSystemMeasurementItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.InterSystemMeasurementItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.InterSystemMeasurementItemExtIEsExtField, options aper.DecodeState) (s09.InterSystemMeasurementItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.InterSystemMeasurementItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func InterSystemMeasurementParametersExtIEsValueExtensionFieldTableCodec(table s00.InterSystemMeasurementParametersExtIEsValueExtensionTable) s09.InterSystemMeasurementParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgeInterSystemMeasurementParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InterSystemMeasurementParametersExtIEsExtFieldValueCodec{}
	}
	return func() s09.InterSystemMeasurementParametersExtIEsExtFieldValueCodec {
		sealed := s09.InterSystemMeasurementParametersExtIEsExtFieldValueCodec{}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InterSystemMeasurementParametersExtIEsExtField, error) {
			var field s09.InterSystemMeasurementParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.InterSystemMeasurementParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.InterSystemMeasurementParametersExtIEsExtField, options aper.DecodeState) (s09.InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.InterSystemMeasurementParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func IntersystemMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable) s09.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeIntersystemMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s09.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s09.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.IntersystemMeasurementConfigurationExtIEsExtField, error) {
			var field s09.IntersystemMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.IntersystemMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.IntersystemMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s09.IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.IntersystemMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LAIExtIEsValueExtensionFieldTableCodec(table s00.LAIExtIEsValueExtensionTable) s09.LAIExtIEsExtFieldValueCodec {
	if !*s00.BridgeLAIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LAIExtIEsExtFieldValueCodec{}
	}
	return func() s09.LAIExtIEsExtFieldValueCodec {
		sealed := s09.LAIExtIEsExtFieldValueCodec{}
		*s09.BridgeLAIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LAIExtIEsExtField, error) {
			var field s09.LAIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeLAIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.LAIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeLAIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.LAIExtIEsExtField, options aper.DecodeState) (s09.LAIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLAIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeLAIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.LAIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLAIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLAIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LTENTNTAIInformationExtIEsValueExtensionFieldTableCodec(table s00.LTENTNTAIInformationExtIEsValueExtensionTable) s09.LTENTNTAIInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeLTENTNTAIInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LTENTNTAIInformationExtIEsExtFieldValueCodec{}
	}
	return func() s09.LTENTNTAIInformationExtIEsExtFieldValueCodec {
		sealed := s09.LTENTNTAIInformationExtIEsExtFieldValueCodec{}
		*s09.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LTENTNTAIInformationExtIEsExtField, error) {
			var field s09.LTENTNTAIInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.LTENTNTAIInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.LTENTNTAIInformationExtIEsExtField, options aper.DecodeState) (s09.LTENTNTAIInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.LTENTNTAIInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LastVisitedPSCellInformationExtIEsValueExtensionFieldTableCodec(table s00.LastVisitedPSCellInformationExtIEsValueExtensionTable) s09.LastVisitedPSCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeLastVisitedPSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LastVisitedPSCellInformationExtIEsExtFieldValueCodec{}
	}
	return func() s09.LastVisitedPSCellInformationExtIEsExtFieldValueCodec {
		sealed := s09.LastVisitedPSCellInformationExtIEsExtFieldValueCodec{}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LastVisitedPSCellInformationExtIEsExtField, error) {
			var field s09.LastVisitedPSCellInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.LastVisitedPSCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.LastVisitedPSCellInformationExtIEsExtField, options aper.DecodeState) (s09.LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.LastVisitedPSCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ListeningSubframePatternExtIEsValueExtensionFieldTableCodec(table s00.ListeningSubframePatternExtIEsValueExtensionTable) s09.ListeningSubframePatternExtIEsExtFieldValueCodec {
	if !*s00.BridgeListeningSubframePatternExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ListeningSubframePatternExtIEsExtFieldValueCodec{}
	}
	return func() s09.ListeningSubframePatternExtIEsExtFieldValueCodec {
		sealed := s09.ListeningSubframePatternExtIEsExtFieldValueCodec{}
		*s09.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ListeningSubframePatternExtIEsExtField, error) {
			var field s09.ListeningSubframePatternExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ListeningSubframePatternExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ListeningSubframePatternExtIEsExtField, options aper.DecodeState) (s09.ListeningSubframePatternExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ListeningSubframePatternExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LoggedMBSFNMDTExtIEsValueExtensionFieldTableCodec(table s00.LoggedMBSFNMDTExtIEsValueExtensionTable) s09.LoggedMBSFNMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeLoggedMBSFNMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LoggedMBSFNMDTExtIEsExtFieldValueCodec{}
	}
	return func() s09.LoggedMBSFNMDTExtIEsExtFieldValueCodec {
		sealed := s09.LoggedMBSFNMDTExtIEsExtFieldValueCodec{}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LoggedMBSFNMDTExtIEsExtField, error) {
			var field s09.LoggedMBSFNMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.LoggedMBSFNMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.LoggedMBSFNMDTExtIEsExtField, options aper.DecodeState) (s09.LoggedMBSFNMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.LoggedMBSFNMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M1PeriodicReportingExtIEsValueExtensionFieldTableCodec(table s00.M1PeriodicReportingExtIEsValueExtensionTable) s09.M1PeriodicReportingExtIEsExtFieldValueCodec {
	if !*s00.BridgeM1PeriodicReportingExtIEsValueExtensionTableFieldBound(&table) {
		return s09.M1PeriodicReportingExtIEsExtFieldValueCodec{}
	}
	return func() s09.M1PeriodicReportingExtIEsExtFieldValueCodec {
		sealed := s09.M1PeriodicReportingExtIEsExtFieldValueCodec{}
		*s09.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.M1PeriodicReportingExtIEsExtField, error) {
			var field s09.M1PeriodicReportingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.M1PeriodicReportingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.M1PeriodicReportingExtIEsExtField, options aper.DecodeState) (s09.M1PeriodicReportingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.M1PeriodicReportingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M1ThresholdEventA2ExtIEsValueExtensionFieldTableCodec(table s00.M1ThresholdEventA2ExtIEsValueExtensionTable) s10.M1ThresholdEventA2ExtIEsExtFieldValueCodec {
	if !*s00.BridgeM1ThresholdEventA2ExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M1ThresholdEventA2ExtIEsExtFieldValueCodec{}
	}
	return func() s10.M1ThresholdEventA2ExtIEsExtFieldValueCodec {
		sealed := s10.M1ThresholdEventA2ExtIEsExtFieldValueCodec{}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M1ThresholdEventA2ExtIEsExtField, error) {
			var field s10.M1ThresholdEventA2ExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M1ThresholdEventA2ExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M1ThresholdEventA2ExtIEsExtField, options aper.DecodeState) (s10.M1ThresholdEventA2ExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M1ThresholdEventA2ExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M3ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M3ConfigurationExtIEsValueExtensionTable) s10.M3ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM3ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M3ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s10.M3ConfigurationExtIEsExtFieldValueCodec {
		sealed := s10.M3ConfigurationExtIEsExtFieldValueCodec{}
		*s10.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M3ConfigurationExtIEsExtField, error) {
			var field s10.M3ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M3ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M3ConfigurationExtIEsExtField, options aper.DecodeState) (s10.M3ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M3ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M4ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M4ConfigurationExtIEsValueExtensionTable) s10.M4ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM4ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M4ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s10.M4ConfigurationExtIEsExtFieldValueCodec {
		sealed := s10.M4ConfigurationExtIEsExtFieldValueCodec{}
		*s10.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M4ConfigurationExtIEsExtField, error) {
			var field s10.M4ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M4ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M4ConfigurationExtIEsExtField, options aper.DecodeState) (s10.M4ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M4ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M5ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M5ConfigurationExtIEsValueExtensionTable) s10.M5ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM5ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M5ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s10.M5ConfigurationExtIEsExtFieldValueCodec {
		sealed := s10.M5ConfigurationExtIEsExtFieldValueCodec{}
		*s10.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M5ConfigurationExtIEsExtField, error) {
			var field s10.M5ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M5ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M5ConfigurationExtIEsExtField, options aper.DecodeState) (s10.M5ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M5ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M6ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M6ConfigurationExtIEsValueExtensionTable) s10.M6ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM6ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M6ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s10.M6ConfigurationExtIEsExtFieldValueCodec {
		sealed := s10.M6ConfigurationExtIEsExtFieldValueCodec{}
		*s10.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M6ConfigurationExtIEsExtField, error) {
			var field s10.M6ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M6ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M6ConfigurationExtIEsExtField, options aper.DecodeState) (s10.M6ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M6ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func M7ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M7ConfigurationExtIEsValueExtensionTable) s10.M7ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM7ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M7ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s10.M7ConfigurationExtIEsExtFieldValueCodec {
		sealed := s10.M7ConfigurationExtIEsExtFieldValueCodec{}
		*s10.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M7ConfigurationExtIEsExtField, error) {
			var field s10.M7ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.M7ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.M7ConfigurationExtIEsExtField, options aper.DecodeState) (s10.M7ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.M7ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MBSFNResultToLogInfoExtIEsValueExtensionFieldTableCodec(table s00.MBSFNResultToLogInfoExtIEsValueExtensionTable) s10.MBSFNResultToLogInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeMBSFNResultToLogInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s10.MBSFNResultToLogInfoExtIEsExtFieldValueCodec{}
	}
	return func() s10.MBSFNResultToLogInfoExtIEsExtFieldValueCodec {
		sealed := s10.MBSFNResultToLogInfoExtIEsExtFieldValueCodec{}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MBSFNResultToLogInfoExtIEsExtField, error) {
			var field s10.MBSFNResultToLogInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.MBSFNResultToLogInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.MBSFNResultToLogInfoExtIEsExtField, options aper.DecodeState) (s10.MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.MBSFNResultToLogInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MutingPatternInformationExtIEsValueExtensionFieldTableCodec(table s00.MutingPatternInformationExtIEsValueExtensionTable) s10.MutingPatternInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeMutingPatternInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.MutingPatternInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.MutingPatternInformationExtIEsExtFieldValueCodec {
		sealed := s10.MutingPatternInformationExtIEsExtFieldValueCodec{}
		*s10.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MutingPatternInformationExtIEsExtField, error) {
			var field s10.MutingPatternInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.MutingPatternInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.MutingPatternInformationExtIEsExtField, options aper.DecodeState) (s10.MutingPatternInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.MutingPatternInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NBIoTPagingEDRXInformationExtIEsValueExtensionFieldTableCodec(table s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable) s10.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeNBIoTPagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec {
		sealed := s10.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec{}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NBIoTPagingEDRXInformationExtIEsExtField, error) {
			var field s10.NBIoTPagingEDRXInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NBIoTPagingEDRXInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NBIoTPagingEDRXInformationExtIEsExtField, options aper.DecodeState) (s10.NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NBIoTPagingEDRXInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NGENBExtIEsValueExtensionFieldTableCodec(table s00.NGENBExtIEsValueExtensionTable) s10.NGENBExtIEsExtFieldValueCodec {
	if !*s00.BridgeNGENBExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NGENBExtIEsExtFieldValueCodec{}
	}
	return func() s10.NGENBExtIEsExtFieldValueCodec {
		sealed := s10.NGENBExtIEsExtFieldValueCodec{}
		*s10.BridgeNGENBExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NGENBExtIEsExtField, error) {
			var field s10.NGENBExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNGENBExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NGENBExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNGENBExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NGENBExtIEsExtField, options aper.DecodeState) (s10.NGENBExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNGENBExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NGENBExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNGENBExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNGENBExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NRCGIExtIEsValueExtensionFieldTableCodec(table s00.NRCGIExtIEsValueExtensionTable) s10.NRCGIExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRCGIExtIEsExtFieldValueCodec{}
	}
	return func() s10.NRCGIExtIEsExtFieldValueCodec {
		sealed := s10.NRCGIExtIEsExtFieldValueCodec{}
		*s10.BridgeNRCGIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRCGIExtIEsExtField, error) {
			var field s10.NRCGIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNRCGIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NRCGIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNRCGIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NRCGIExtIEsExtField, options aper.DecodeState) (s10.NRCGIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNRCGIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NRCGIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRCGIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NRUESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec(table s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable) s10.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec{}
	}
	return func() s10.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec {
		sealed := s10.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec{}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRUESecurityCapabilitiesExtIEsExtField, error) {
			var field s10.NRUESecurityCapabilitiesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NRUESecurityCapabilitiesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NRUESecurityCapabilitiesExtIEsExtField, options aper.DecodeState) (s10.NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NRUESecurityCapabilitiesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionFieldTableCodec(table s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable) s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec{}
	}
	return func() s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec {
		sealed := s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec{}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, error) {
			var field s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, options aper.DecodeState) (s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NRV2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable) s10.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s10.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec {
		sealed := s10.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec{}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRV2XServicesAuthorizedExtIEsExtField, error) {
			var field s10.NRV2XServicesAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.NRV2XServicesAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.NRV2XServicesAuthorizedExtIEsExtField, options aper.DecodeState) (s10.NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.NRV2XServicesAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PC5FlowBitRatesExtIEsValueExtensionFieldTableCodec(table s00.PC5FlowBitRatesExtIEsValueExtensionTable) s10.PC5FlowBitRatesExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5FlowBitRatesExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5FlowBitRatesExtIEsExtFieldValueCodec{}
	}
	return func() s10.PC5FlowBitRatesExtIEsExtFieldValueCodec {
		sealed := s10.PC5FlowBitRatesExtIEsExtFieldValueCodec{}
		*s10.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5FlowBitRatesExtIEsExtField, error) {
			var field s10.PC5FlowBitRatesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PC5FlowBitRatesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PC5FlowBitRatesExtIEsExtField, options aper.DecodeState) (s10.PC5FlowBitRatesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PC5FlowBitRatesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PC5QoSFlowItemExtIEsValueExtensionFieldTableCodec(table s00.PC5QoSFlowItemExtIEsValueExtensionTable) s10.PC5QoSFlowItemExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSFlowItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.PC5QoSFlowItemExtIEsExtFieldValueCodec {
		sealed := s10.PC5QoSFlowItemExtIEsExtFieldValueCodec{}
		*s10.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtField, error) {
			var field s10.PC5QoSFlowItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PC5QoSFlowItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtField, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PC5QoSParametersExtIEsValueExtensionFieldTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable) s10.PC5QoSParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSParametersExtIEsExtFieldValueCodec{}
	}
	return func() s10.PC5QoSParametersExtIEsExtFieldValueCodec {
		sealed := s10.PC5QoSParametersExtIEsExtFieldValueCodec{}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtField, error) {
			var field s10.PC5QoSParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PC5QoSParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSParametersExtIEsExtField, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable) s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
		sealed := s10.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtField, error) {
			var field s10.PLMNAreaBasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PLMNAreaBasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtField, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PSCellInformationExtIEsValueExtensionFieldTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable) s10.PSCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PSCellInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PSCellInformationExtIEsExtFieldValueCodec {
		sealed := s10.PSCellInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PSCellInformationExtIEsExtField, error) {
			var field s10.PSCellInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PSCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PSCellInformationExtIEsExtField, options aper.DecodeState) (s10.PSCellInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PSCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePSCellInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PagingAttemptInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable) s10.PagingAttemptInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingAttemptInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PagingAttemptInformationExtIEsExtFieldValueCodec {
		sealed := s10.PagingAttemptInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtField, error) {
			var field s10.PagingAttemptInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PagingAttemptInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtField, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func PagingEDRXInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingEDRXInformationExtIEsValueExtensionTable) s10.PagingEDRXInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingEDRXInformationExtIEsExtFieldValueCodec{}
	}
	return func() s10.PagingEDRXInformationExtIEsExtFieldValueCodec {
		sealed := s10.PagingEDRXInformationExtIEsExtFieldValueCodec{}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtField, error) {
			var field s10.PagingEDRXInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.PagingEDRXInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtField, options aper.DecodeState) (s10.PagingEDRXInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.PagingEDRXInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func CellIDBroadcastItemExtIEsValueExtensionTableCodec(table s00.CellIDBroadcastItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CellIDBroadcastItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellIDBroadcastItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CellIDBroadcastItemExtIEsExtContainerValueCodec {
		sealed := s07.CellIDBroadcastItemExtIEsExtContainerValueCodec{}
		*s07.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellIDBroadcastItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CellIDBroadcastItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CellIDBroadcastItemExtIEsExtField
					if err := s07.BridgeCellIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CellIDBroadcastItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCellIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CellIDBroadcastItemExtIEsExtContainer, options aper.DecodeState) (s07.CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s12.BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CellIDBroadcastItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CellIDCancelledItemExtIEsValueExtensionTableCodec(table s00.CellIDCancelledItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CellIDCancelledItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellIDCancelledItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CellIDCancelledItemExtIEsExtContainerValueCodec {
		sealed := s07.CellIDCancelledItemExtIEsExtContainerValueCodec{}
		*s07.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellIDCancelledItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CellIDCancelledItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CellIDCancelledItemExtIEsExtField
					if err := s07.BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CellIDCancelledItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CellIDCancelledItemExtIEsExtContainer, options aper.DecodeState) (s07.CellIDCancelledItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CellIDCancelledItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableCodec(table s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec {
		sealed := s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec{}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
					if err := s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, options aper.DecodeState) (s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CellTypeExtIEsValueExtensionTableCodec(table s00.CellTypeExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CellTypeExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CellTypeExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CellTypeExtIEsExtContainerValueCodec {
		sealed := s07.CellTypeExtIEsExtContainerValueCodec{}
		*s07.BridgeCellTypeExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CellTypeExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CellTypeExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CellTypeExtIEsExtField
					if err := s07.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCellTypeExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CellTypeExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCellTypeExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CellTypeExtIEsExtContainer, options aper.DecodeState) (s07.CellTypeExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCellTypeExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CellTypeExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCellTypeExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CompletedCellinEAIItemExtIEsValueExtensionTableCodec(table s00.CompletedCellinEAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CompletedCellinEAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCompletedCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CompletedCellinEAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CompletedCellinEAIItemExtIEsExtContainerValueCodec {
		sealed := s07.CompletedCellinEAIItemExtIEsExtContainerValueCodec{}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CompletedCellinEAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CompletedCellinEAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CompletedCellinEAIItemExtIEsExtField
					if err := s07.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CompletedCellinEAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CompletedCellinEAIItemExtIEsExtContainer, options aper.DecodeState) (s07.CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CompletedCellinEAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CompletedCellinTAIItemExtIEsValueExtensionTableCodec(table s00.CompletedCellinTAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CompletedCellinTAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCompletedCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CompletedCellinTAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CompletedCellinTAIItemExtIEsExtContainerValueCodec {
		sealed := s07.CompletedCellinTAIItemExtIEsExtContainerValueCodec{}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CompletedCellinTAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CompletedCellinTAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CompletedCellinTAIItemExtIEsExtField
					if err := s07.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CompletedCellinTAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CompletedCellinTAIItemExtIEsExtContainer, options aper.DecodeState) (s07.CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CompletedCellinTAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ConnectedengNBItemExtIEsValueExtensionTableCodec(table s00.ConnectedengNBItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.ConnectedengNBItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeConnectedengNBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.ConnectedengNBItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.ConnectedengNBItemExtIEsExtContainerValueCodec {
		sealed := s07.ConnectedengNBItemExtIEsExtContainerValueCodec{}
		*s07.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.ConnectedengNBItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.ConnectedengNBItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.ConnectedengNBItemExtIEsExtField
					if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.ConnectedengNBItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.ConnectedengNBItemExtIEsExtContainer, options aper.DecodeState) (s07.ConnectedengNBItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.ConnectedengNBItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ContextatSourceExtIEsValueExtensionTableCodec(table s00.ContextatSourceExtIEsValueExtensionTable, bounds aper.ListBounds) s07.ContextatSourceExtIEsExtContainerValueCodec {
	if !*s00.BridgeContextatSourceExtIEsValueExtensionTableFieldBound(&table) {
		return s07.ContextatSourceExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.ContextatSourceExtIEsExtContainerValueCodec {
		sealed := s07.ContextatSourceExtIEsExtContainerValueCodec{}
		*s07.BridgeContextatSourceExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.ContextatSourceExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.ContextatSourceExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.ContextatSourceExtIEsExtField
					if err := s07.BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeContextatSourceExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.ContextatSourceExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeContextatSourceExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.ContextatSourceExtIEsExtContainer, options aper.DecodeState) (s07.ContextatSourceExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeContextatSourceExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.ContextatSourceExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeContextatSourceExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CriticalityDiagnosticsExtIEsValueExtensionTableCodec(table s00.CriticalityDiagnosticsExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CriticalityDiagnosticsExtIEsExtContainerValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CriticalityDiagnosticsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CriticalityDiagnosticsExtIEsExtContainerValueCodec {
		sealed := s07.CriticalityDiagnosticsExtIEsExtContainerValueCodec{}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CriticalityDiagnosticsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CriticalityDiagnosticsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CriticalityDiagnosticsExtIEsExtField
					if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CriticalityDiagnosticsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CriticalityDiagnosticsExtIEsExtContainer, options aper.DecodeState) (s07.CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CriticalityDiagnosticsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func CriticalityDiagnosticsIEItemExtIEsValueExtensionTableCodec(table s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable, bounds aper.ListBounds) s07.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsIEItemExtIEsValueExtensionTableFieldBound(&table) {
		return s07.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec {
		sealed := s07.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec{}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.CriticalityDiagnosticsIEItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.CriticalityDiagnosticsIEItemExtIEsExtField
					if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, options aper.DecodeState) (s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.CriticalityDiagnosticsIEItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DAPSRequestInfoExtIEsValueExtensionTableCodec(table s00.DAPSRequestInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s07.DAPSRequestInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSRequestInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s07.DAPSRequestInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s07.DAPSRequestInfoExtIEsExtContainerValueCodec {
		sealed := s07.DAPSRequestInfoExtIEsExtContainerValueCodec{}
		*s07.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.DAPSRequestInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s07.DAPSRequestInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s07.DAPSRequestInfoExtIEsExtField
					if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s07.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s07.DAPSRequestInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s07.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s07.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s07.DAPSRequestInfoExtIEsExtContainer, options aper.DecodeState) (s07.DAPSRequestInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s07.DAPSRequestInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s07.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoExtIEsValueExtensionTableCodec(table s00.DAPSResponseInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s08.DAPSResponseInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DAPSResponseInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DAPSResponseInfoExtIEsExtContainerValueCodec {
		sealed := s08.DAPSResponseInfoExtIEsExtContainerValueCodec{}
		*s08.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DAPSResponseInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DAPSResponseInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DAPSResponseInfoExtIEsExtField
					if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.DAPSResponseInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.DAPSResponseInfoExtIEsExtContainer, options aper.DecodeState) (s08.DAPSResponseInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.DAPSResponseInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DAPSResponseInfoItemExtIEsValueExtensionTableCodec(table s00.DAPSResponseInfoItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.DAPSResponseInfoItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DAPSResponseInfoItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DAPSResponseInfoItemExtIEsExtContainerValueCodec {
		sealed := s08.DAPSResponseInfoItemExtIEsExtContainerValueCodec{}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DAPSResponseInfoItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DAPSResponseInfoItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DAPSResponseInfoItemExtIEsExtField
					if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.DAPSResponseInfoItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.DAPSResponseInfoItemExtIEsExtContainer, options aper.DecodeState) (s08.DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.DAPSResponseInfoItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DLCPSecurityInformationExtIEsValueExtensionTableCodec(table s00.DLCPSecurityInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s08.DLCPSecurityInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeDLCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.DLCPSecurityInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DLCPSecurityInformationExtIEsExtContainerValueCodec {
		sealed := s08.DLCPSecurityInformationExtIEsExtContainerValueCodec{}
		*s08.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DLCPSecurityInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DLCPSecurityInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DLCPSecurityInformationExtIEsExtField
					if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.DLCPSecurityInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.DLCPSecurityInformationExtIEsExtContainer, options aper.DecodeState) (s08.DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.DLCPSecurityInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBStatusTransferTransparentContainerExtIEsValueExtensionTableCodec(table s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
		sealed := s08.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENBStatusTransferTransparentContainerExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENBStatusTransferTransparentContainerExtIEsExtField
					if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, options aper.DecodeState) (s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENBStatusTransferTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBX2ExtTLAExtIEsValueExtensionTableCodec(table s00.ENBX2ExtTLAExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENBX2ExtTLAExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBX2ExtTLAExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENBX2ExtTLAExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENBX2ExtTLAExtIEsExtContainerValueCodec {
		sealed := s08.ENBX2ExtTLAExtIEsExtContainerValueCodec{}
		*s08.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENBX2ExtTLAExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENBX2ExtTLAExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENBX2ExtTLAExtIEsExtField
					if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENBX2ExtTLAExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENBX2ExtTLAExtIEsExtContainer, options aper.DecodeState) (s08.ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENBX2ExtTLAExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONConfigurationTransferExtIEsValueExtensionTableCodec(table s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec {
		sealed := s08.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec{}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONConfigurationTransferExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENDCSONConfigurationTransferExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENDCSONConfigurationTransferExtIEsExtField
					if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENDCSONConfigurationTransferExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONConfigurationTransferExtIEsExtContainer, options aper.DecodeState) (s08.ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONConfigurationTransferExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONeNBIdentificationExtIEsValueExtensionTableCodec(table s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONeNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec {
		sealed := s08.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec{}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONeNBIdentificationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENDCSONeNBIdentificationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENDCSONeNBIdentificationExtIEsExtField
					if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENDCSONeNBIdentificationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONeNBIdentificationExtIEsExtContainer, options aper.DecodeState) (s08.ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONeNBIdentificationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENDCSONengNBIdentificationExtIEsValueExtensionTableCodec(table s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONengNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec {
		sealed := s08.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec{}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCSONengNBIdentificationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENDCSONengNBIdentificationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENDCSONengNBIdentificationExtIEsExtField
					if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENDCSONengNBIdentificationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENDCSONengNBIdentificationExtIEsExtContainer, options aper.DecodeState) (s08.ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENDCSONengNBIdentificationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENDCTransferTypeReplyExtIEsValueExtensionTableCodec(table s00.ENDCTransferTypeReplyExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENDCTransferTypeReplyExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCTransferTypeReplyExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCTransferTypeReplyExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENDCTransferTypeReplyExtIEsExtContainerValueCodec {
		sealed := s08.ENDCTransferTypeReplyExtIEsExtContainerValueCodec{}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCTransferTypeReplyExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENDCTransferTypeReplyExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENDCTransferTypeReplyExtIEsExtField
					if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENDCTransferTypeReplyExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENDCTransferTypeReplyExtIEsExtContainer, options aper.DecodeState) (s08.ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENDCTransferTypeReplyExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENDCTransferTypeRequestExtIEsValueExtensionTableCodec(table s00.ENDCTransferTypeRequestExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ENDCTransferTypeRequestExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCTransferTypeRequestExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ENDCTransferTypeRequestExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ENDCTransferTypeRequestExtIEsExtContainerValueCodec {
		sealed := s08.ENDCTransferTypeRequestExtIEsExtContainerValueCodec{}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ENDCTransferTypeRequestExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ENDCTransferTypeRequestExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ENDCTransferTypeRequestExtIEsExtField
					if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ENDCTransferTypeRequestExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ENDCTransferTypeRequestExtIEsExtContainer, options aper.DecodeState) (s08.ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ENDCTransferTypeRequestExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABAdmittedItemExtIEsValueExtensionTableCodec(table s00.ERABAdmittedItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABAdmittedItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABAdmittedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABAdmittedItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABAdmittedItemExtIEsExtContainerValueCodec {
		sealed := s08.ERABAdmittedItemExtIEsExtContainerValueCodec{}
		*s08.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABAdmittedItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABAdmittedItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABAdmittedItemExtIEsExtField
					if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABAdmittedItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABAdmittedItemExtIEsExtContainer, options aper.DecodeState) (s08.ERABAdmittedItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABAdmittedItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABDataForwardingItemExtIEsValueExtensionTableCodec(table s00.ERABDataForwardingItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABDataForwardingItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABDataForwardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABDataForwardingItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABDataForwardingItemExtIEsExtContainerValueCodec {
		sealed := s08.ERABDataForwardingItemExtIEsExtContainerValueCodec{}
		*s08.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABDataForwardingItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABDataForwardingItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABDataForwardingItemExtIEsExtField
					if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABDataForwardingItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABDataForwardingItemExtIEsExtContainer, options aper.DecodeState) (s08.ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABDataForwardingItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeReqExtIEsValueExtensionTableCodec(table s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec {
		sealed := s08.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec{}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABFailedToResumeItemResumeReqExtIEsExtField
					if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToResumeItemResumeResExtIEsValueExtensionTableCodec(table s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec {
		sealed := s08.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec{}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABFailedToResumeItemResumeResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABFailedToResumeItemResumeResExtIEsExtField
					if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, options aper.DecodeState) (s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableCodec(table s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec {
		sealed := s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec{}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABFailedToSetupItemHOReqAckExtIEsExtField
					if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, options aper.DecodeState) (s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABItemExtIEsValueExtensionTableCodec(table s00.ERABItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABItemExtIEsExtContainerValueCodec {
		sealed := s08.ERABItemExtIEsExtContainerValueCodec{}
		*s08.BridgeERABItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABItemExtIEsExtField
					if err := s08.BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABItemExtIEsExtContainer, options aper.DecodeState) (s08.ERABItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModConfExtIEsValueExtensionTableCodec(table s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec {
		sealed := s08.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec{}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABModifyItemBearerModConfExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABModifyItemBearerModConfExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABModifyItemBearerModConfExtIEsExtField
					if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABModifyItemBearerModConfExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABModifyItemBearerModConfExtIEsExtContainer, options aper.DecodeState) (s08.ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABModifyItemBearerModConfExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABModifyItemBearerModResExtIEsValueExtensionTableCodec(table s00.ERABModifyItemBearerModResExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABModifyItemBearerModResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABModifyItemBearerModResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABModifyItemBearerModResExtIEsExtContainerValueCodec {
		sealed := s08.ERABModifyItemBearerModResExtIEsExtContainerValueCodec{}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABModifyItemBearerModResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABModifyItemBearerModResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABModifyItemBearerModResExtIEsExtField
					if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABModifyItemBearerModResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABModifyItemBearerModResExtIEsExtContainer, options aper.DecodeState) (s08.ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABModifyItemBearerModResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
		sealed := s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField
					if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, options aper.DecodeState) (s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABQoSParametersExtIEsValueExtensionTableCodec(table s00.ERABQoSParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABQoSParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABQoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABQoSParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABQoSParametersExtIEsExtContainerValueCodec {
		sealed := s08.ERABQoSParametersExtIEsExtContainerValueCodec{}
		*s08.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABQoSParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABQoSParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABQoSParametersExtIEsExtField
					if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABQoSParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABQoSParametersExtIEsExtContainer, options aper.DecodeState) (s08.ERABQoSParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABQoSParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABReleaseItemBearerRelCompExtIEsValueExtensionTableCodec(table s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec {
		sealed := s08.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec{}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABReleaseItemBearerRelCompExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABReleaseItemBearerRelCompExtIEsExtField
					if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, options aper.DecodeState) (s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSecurityResultItemExtIEsValueExtensionTableCodec(table s00.ERABSecurityResultItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABSecurityResultItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSecurityResultItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABSecurityResultItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABSecurityResultItemExtIEsExtContainerValueCodec {
		sealed := s08.ERABSecurityResultItemExtIEsExtContainerValueCodec{}
		*s08.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSecurityResultItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABSecurityResultItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABSecurityResultItemExtIEsExtField
					if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABSecurityResultItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABSecurityResultItemExtIEsExtContainer, options aper.DecodeState) (s08.ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABSecurityResultItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupItemBearerSUResExtIEsValueExtensionTableCodec(table s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec {
		sealed := s08.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec{}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSetupItemBearerSUResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABSetupItemBearerSUResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABSetupItemBearerSUResExtIEsExtField
					if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABSetupItemBearerSUResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABSetupItemBearerSUResExtIEsExtContainer, options aper.DecodeState) (s08.ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABSetupItemBearerSUResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupItemCtxtSUResExtIEsValueExtensionTableCodec(table s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable, bounds aper.ListBounds) s08.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s08.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec {
		sealed := s08.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec{}
		*s08.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.ERABSetupItemCtxtSUResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.ERABSetupItemCtxtSUResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.ERABSetupItemCtxtSUResExtIEsExtField
					if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.ERABSetupItemCtxtSUResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.ERABSetupItemCtxtSUResExtIEsExtContainer, options aper.DecodeState) (s08.ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.ERABSetupItemCtxtSUResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec(table s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
		sealed := s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ERABToBeModifiedItemBearerModIndExtIEsExtField
					if err := s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, options aper.DecodeState) (s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeSwitchedULItemExtIEsValueExtensionTableCodec(table s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec {
		sealed := s09.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec{}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeSwitchedULItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ERABToBeSwitchedULItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ERABToBeSwitchedULItemExtIEsExtField
					if err := s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ERABToBeSwitchedULItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeSwitchedULItemExtIEsExtContainer, options aper.DecodeState) (s09.ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeSwitchedULItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABToBeUpdatedItemExtIEsValueExtensionTableCodec(table s00.ERABToBeUpdatedItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ERABToBeUpdatedItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABToBeUpdatedItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ERABToBeUpdatedItemExtIEsExtContainerValueCodec {
		sealed := s09.ERABToBeUpdatedItemExtIEsExtContainerValueCodec{}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABToBeUpdatedItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ERABToBeUpdatedItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ERABToBeUpdatedItemExtIEsExtField
					if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ERABToBeUpdatedItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ERABToBeUpdatedItemExtIEsExtContainer, options aper.DecodeState) (s09.ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ERABToBeUpdatedItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABUsageReportItemExtIEsValueExtensionTableCodec(table s00.ERABUsageReportItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ERABUsageReportItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ERABUsageReportItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ERABUsageReportItemExtIEsExtContainerValueCodec {
		sealed := s09.ERABUsageReportItemExtIEsExtContainerValueCodec{}
		*s09.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ERABUsageReportItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ERABUsageReportItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ERABUsageReportItemExtIEsExtField
					if err := s09.BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ERABUsageReportItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ERABUsageReportItemExtIEsExtContainer, options aper.DecodeState) (s09.ERABUsageReportItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ERABUsageReportItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EUTRANCGIExtIEsValueExtensionTableCodec(table s00.EUTRANCGIExtIEsValueExtensionTable, bounds aper.ListBounds) s09.EUTRANCGIExtIEsExtContainerValueCodec {
	if !*s00.BridgeEUTRANCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EUTRANCGIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.EUTRANCGIExtIEsExtContainerValueCodec {
		sealed := s09.EUTRANCGIExtIEsExtContainerValueCodec{}
		*s09.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EUTRANCGIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.EUTRANCGIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.EUTRANCGIExtIEsExtField
					if err := s09.BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.EUTRANCGIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.EUTRANCGIExtIEsExtContainer, options aper.DecodeState) (s09.EUTRANCGIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.EUTRANCGIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EmergencyAreaIDBroadcastItemExtIEsValueExtensionTableCodec(table s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeEmergencyAreaIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec {
		sealed := s09.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec{}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.EmergencyAreaIDBroadcastItemExtIEsExtField
					if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, options aper.DecodeState) (s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.EmergencyAreaIDBroadcastItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EmergencyAreaIDCancelledItemExtIEsValueExtensionTableCodec(table s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeEmergencyAreaIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec {
		sealed := s09.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec{}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.EmergencyAreaIDCancelledItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.EmergencyAreaIDCancelledItemExtIEsExtField
					if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, options aper.DecodeState) (s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.EmergencyAreaIDCancelledItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EventL1LoggedMDTConfigExtIEsValueExtensionTableCodec(table s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable, bounds aper.ListBounds) s09.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec {
	if !*s00.BridgeEventL1LoggedMDTConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s09.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec {
		sealed := s09.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec{}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventL1LoggedMDTConfigExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.EventL1LoggedMDTConfigExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.EventL1LoggedMDTConfigExtIEsExtField
					if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.EventL1LoggedMDTConfigExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.EventL1LoggedMDTConfigExtIEsExtContainer, options aper.DecodeState) (s09.EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.EventL1LoggedMDTConfigExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ExpectedUEActivityBehaviourExtIEsValueExtensionTableCodec(table s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec {
	if !*s00.BridgeExpectedUEActivityBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec {
		sealed := s09.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec{}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ExpectedUEActivityBehaviourExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ExpectedUEActivityBehaviourExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ExpectedUEActivityBehaviourExtIEsExtField
					if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ExpectedUEActivityBehaviourExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ExpectedUEActivityBehaviourExtIEsExtContainer, options aper.DecodeState) (s09.ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ExpectedUEActivityBehaviourExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ExpectedUEBehaviourExtIEsValueExtensionTableCodec(table s00.ExpectedUEBehaviourExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ExpectedUEBehaviourExtIEsExtContainerValueCodec {
	if !*s00.BridgeExpectedUEBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ExpectedUEBehaviourExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ExpectedUEBehaviourExtIEsExtContainerValueCodec {
		sealed := s09.ExpectedUEBehaviourExtIEsExtContainerValueCodec{}
		*s09.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ExpectedUEBehaviourExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ExpectedUEBehaviourExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ExpectedUEBehaviourExtIEsExtField
					if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ExpectedUEBehaviourExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ExpectedUEBehaviourExtIEsExtContainer, options aper.DecodeState) (s09.ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ExpectedUEBehaviourExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func FiveGSTAIExtIEsValueExtensionTableCodec(table s00.FiveGSTAIExtIEsValueExtensionTable, bounds aper.ListBounds) s09.FiveGSTAIExtIEsExtContainerValueCodec {
	if !*s00.BridgeFiveGSTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.FiveGSTAIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.FiveGSTAIExtIEsExtContainerValueCodec {
		sealed := s09.FiveGSTAIExtIEsExtContainerValueCodec{}
		*s09.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.FiveGSTAIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.FiveGSTAIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.FiveGSTAIExtIEsExtField
					if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.FiveGSTAIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.FiveGSTAIExtIEsExtContainer, options aper.DecodeState) (s09.FiveGSTAIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.FiveGSTAIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ForbiddenLAsItemExtIEsValueExtensionTableCodec(table s00.ForbiddenLAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ForbiddenLAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeForbiddenLAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ForbiddenLAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ForbiddenLAsItemExtIEsExtContainerValueCodec {
		sealed := s09.ForbiddenLAsItemExtIEsExtContainerValueCodec{}
		*s09.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ForbiddenLAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ForbiddenLAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ForbiddenLAsItemExtIEsExtField
					if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ForbiddenLAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ForbiddenLAsItemExtIEsExtContainer, options aper.DecodeState) (s09.ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ForbiddenLAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ForbiddenTAsItemExtIEsValueExtensionTableCodec(table s00.ForbiddenTAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ForbiddenTAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeForbiddenTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ForbiddenTAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ForbiddenTAsItemExtIEsExtContainerValueCodec {
		sealed := s09.ForbiddenTAsItemExtIEsExtContainerValueCodec{}
		*s09.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ForbiddenTAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ForbiddenTAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ForbiddenTAsItemExtIEsExtField
					if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ForbiddenTAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ForbiddenTAsItemExtIEsExtContainer, options aper.DecodeState) (s09.ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ForbiddenTAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GBRQosInformationExtIEsValueExtensionTableCodec(table s00.GBRQosInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GBRQosInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeGBRQosInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GBRQosInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GBRQosInformationExtIEsExtContainerValueCodec {
		sealed := s09.GBRQosInformationExtIEsExtContainerValueCodec{}
		*s09.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GBRQosInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GBRQosInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GBRQosInformationExtIEsExtField
					if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GBRQosInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GBRQosInformationExtIEsExtContainer, options aper.DecodeState) (s09.GBRQosInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GBRQosInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GERANCellIDExtIEsValueExtensionTableCodec(table s00.GERANCellIDExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GERANCellIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGERANCellIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GERANCellIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GERANCellIDExtIEsExtContainerValueCodec {
		sealed := s09.GERANCellIDExtIEsExtContainerValueCodec{}
		*s09.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GERANCellIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GERANCellIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GERANCellIDExtIEsExtField
					if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GERANCellIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GERANCellIDExtIEsExtContainer, options aper.DecodeState) (s09.GERANCellIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GERANCellIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GNBExtIEsValueExtensionTableCodec(table s00.GNBExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GNBExtIEsExtContainerValueCodec {
	if !*s00.BridgeGNBExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GNBExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GNBExtIEsExtContainerValueCodec {
		sealed := s09.GNBExtIEsExtContainerValueCodec{}
		*s09.BridgeGNBExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GNBExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GNBExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GNBExtIEsExtField
					if err := s09.BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGNBExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GNBExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGNBExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GNBExtIEsExtContainer, options aper.DecodeState) (s09.GNBExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGNBExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGNBExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GNBExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGNBExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGNBExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GUMMEIExtIEsValueExtensionTableCodec(table s00.GUMMEIExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GUMMEIExtIEsExtContainerValueCodec {
	if !*s00.BridgeGUMMEIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GUMMEIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GUMMEIExtIEsExtContainerValueCodec {
		sealed := s09.GUMMEIExtIEsExtContainerValueCodec{}
		*s09.BridgeGUMMEIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GUMMEIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GUMMEIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GUMMEIExtIEsExtField
					if err := s09.BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGUMMEIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GUMMEIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGUMMEIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GUMMEIExtIEsExtContainer, options aper.DecodeState) (s09.GUMMEIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGUMMEIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GUMMEIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGUMMEIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GlobalENBIDExtIEsValueExtensionTableCodec(table s00.GlobalENBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GlobalENBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalENBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalENBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GlobalENBIDExtIEsExtContainerValueCodec {
		sealed := s09.GlobalENBIDExtIEsExtContainerValueCodec{}
		*s09.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalENBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GlobalENBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GlobalENBIDExtIEsExtField
					if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GlobalENBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GlobalENBIDExtIEsExtContainer, options aper.DecodeState) (s09.GlobalENBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GlobalENBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GlobalEnGNBIDExtIEsValueExtensionTableCodec(table s00.GlobalEnGNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GlobalEnGNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalEnGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalEnGNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GlobalEnGNBIDExtIEsExtContainerValueCodec {
		sealed := s09.GlobalEnGNBIDExtIEsExtContainerValueCodec{}
		*s09.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalEnGNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GlobalEnGNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GlobalEnGNBIDExtIEsExtField
					if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GlobalEnGNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GlobalEnGNBIDExtIEsExtContainer, options aper.DecodeState) (s09.GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GlobalEnGNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func GlobalGNBIDExtIEsValueExtensionTableCodec(table s00.GlobalGNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s09.GlobalGNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s09.GlobalGNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.GlobalGNBIDExtIEsExtContainerValueCodec {
		sealed := s09.GlobalGNBIDExtIEsExtContainerValueCodec{}
		*s09.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.GlobalGNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.GlobalGNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.GlobalGNBIDExtIEsExtField
					if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.GlobalGNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.GlobalGNBIDExtIEsExtContainer, options aper.DecodeState) (s09.GlobalGNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.GlobalGNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func InformationForCECapableUEsExtIEsValueExtensionTableCodec(table s00.InformationForCECapableUEsExtIEsValueExtensionTable, bounds aper.ListBounds) s09.InformationForCECapableUEsExtIEsExtContainerValueCodec {
	if !*s00.BridgeInformationForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InformationForCECapableUEsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.InformationForCECapableUEsExtIEsExtContainerValueCodec {
		sealed := s09.InformationForCECapableUEsExtIEsExtContainerValueCodec{}
		*s09.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InformationForCECapableUEsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.InformationForCECapableUEsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.InformationForCECapableUEsExtIEsExtField
					if err := s09.BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.InformationForCECapableUEsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.InformationForCECapableUEsExtIEsExtContainer, options aper.DecodeState) (s09.InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.InformationForCECapableUEsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableCodec(table s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec {
		sealed := s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec{}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
					if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, options aper.DecodeState) (s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func InterSystemMeasurementItemExtIEsValueExtensionTableCodec(table s00.InterSystemMeasurementItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.InterSystemMeasurementItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeInterSystemMeasurementItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InterSystemMeasurementItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.InterSystemMeasurementItemExtIEsExtContainerValueCodec {
		sealed := s09.InterSystemMeasurementItemExtIEsExtContainerValueCodec{}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InterSystemMeasurementItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.InterSystemMeasurementItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.InterSystemMeasurementItemExtIEsExtField
					if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.InterSystemMeasurementItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.InterSystemMeasurementItemExtIEsExtContainer, options aper.DecodeState) (s09.InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.InterSystemMeasurementItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func InterSystemMeasurementParametersExtIEsValueExtensionTableCodec(table s00.InterSystemMeasurementParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s09.InterSystemMeasurementParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgeInterSystemMeasurementParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s09.InterSystemMeasurementParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.InterSystemMeasurementParametersExtIEsExtContainerValueCodec {
		sealed := s09.InterSystemMeasurementParametersExtIEsExtContainerValueCodec{}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.InterSystemMeasurementParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.InterSystemMeasurementParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.InterSystemMeasurementParametersExtIEsExtField
					if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.InterSystemMeasurementParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.InterSystemMeasurementParametersExtIEsExtContainer, options aper.DecodeState) (s09.InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.InterSystemMeasurementParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func IntersystemMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeIntersystemMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s09.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.IntersystemMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.IntersystemMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.IntersystemMeasurementConfigurationExtIEsExtField
					if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.IntersystemMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.IntersystemMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s09.IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.IntersystemMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LAIExtIEsValueExtensionTableCodec(table s00.LAIExtIEsValueExtensionTable, bounds aper.ListBounds) s09.LAIExtIEsExtContainerValueCodec {
	if !*s00.BridgeLAIExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LAIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.LAIExtIEsExtContainerValueCodec {
		sealed := s09.LAIExtIEsExtContainerValueCodec{}
		*s09.BridgeLAIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LAIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.LAIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.LAIExtIEsExtField
					if err := s09.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeLAIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.LAIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeLAIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.LAIExtIEsExtContainer, options aper.DecodeState) (s09.LAIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeLAIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.LAIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLAIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LTENTNTAIInformationExtIEsValueExtensionTableCodec(table s00.LTENTNTAIInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.LTENTNTAIInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeLTENTNTAIInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LTENTNTAIInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.LTENTNTAIInformationExtIEsExtContainerValueCodec {
		sealed := s09.LTENTNTAIInformationExtIEsExtContainerValueCodec{}
		*s09.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LTENTNTAIInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.LTENTNTAIInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.LTENTNTAIInformationExtIEsExtField
					if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.LTENTNTAIInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.LTENTNTAIInformationExtIEsExtContainer, options aper.DecodeState) (s09.LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.LTENTNTAIInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LastVisitedPSCellInformationExtIEsValueExtensionTableCodec(table s00.LastVisitedPSCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.LastVisitedPSCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeLastVisitedPSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LastVisitedPSCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.LastVisitedPSCellInformationExtIEsExtContainerValueCodec {
		sealed := s09.LastVisitedPSCellInformationExtIEsExtContainerValueCodec{}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LastVisitedPSCellInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.LastVisitedPSCellInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.LastVisitedPSCellInformationExtIEsExtField
					if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.LastVisitedPSCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.LastVisitedPSCellInformationExtIEsExtContainer, options aper.DecodeState) (s09.LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.LastVisitedPSCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ListeningSubframePatternExtIEsValueExtensionTableCodec(table s00.ListeningSubframePatternExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ListeningSubframePatternExtIEsExtContainerValueCodec {
	if !*s00.BridgeListeningSubframePatternExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ListeningSubframePatternExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ListeningSubframePatternExtIEsExtContainerValueCodec {
		sealed := s09.ListeningSubframePatternExtIEsExtContainerValueCodec{}
		*s09.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ListeningSubframePatternExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ListeningSubframePatternExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ListeningSubframePatternExtIEsExtField
					if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ListeningSubframePatternExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ListeningSubframePatternExtIEsExtContainer, options aper.DecodeState) (s09.ListeningSubframePatternExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ListeningSubframePatternExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LoggedMBSFNMDTExtIEsValueExtensionTableCodec(table s00.LoggedMBSFNMDTExtIEsValueExtensionTable, bounds aper.ListBounds) s09.LoggedMBSFNMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeLoggedMBSFNMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s09.LoggedMBSFNMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.LoggedMBSFNMDTExtIEsExtContainerValueCodec {
		sealed := s09.LoggedMBSFNMDTExtIEsExtContainerValueCodec{}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.LoggedMBSFNMDTExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.LoggedMBSFNMDTExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.LoggedMBSFNMDTExtIEsExtField
					if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.LoggedMBSFNMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.LoggedMBSFNMDTExtIEsExtContainer, options aper.DecodeState) (s09.LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.LoggedMBSFNMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M1PeriodicReportingExtIEsValueExtensionTableCodec(table s00.M1PeriodicReportingExtIEsValueExtensionTable, bounds aper.ListBounds) s09.M1PeriodicReportingExtIEsExtContainerValueCodec {
	if !*s00.BridgeM1PeriodicReportingExtIEsValueExtensionTableFieldBound(&table) {
		return s09.M1PeriodicReportingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.M1PeriodicReportingExtIEsExtContainerValueCodec {
		sealed := s09.M1PeriodicReportingExtIEsExtContainerValueCodec{}
		*s09.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.M1PeriodicReportingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.M1PeriodicReportingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.M1PeriodicReportingExtIEsExtField
					if err := s09.BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.M1PeriodicReportingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.M1PeriodicReportingExtIEsExtContainer, options aper.DecodeState) (s09.M1PeriodicReportingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.M1PeriodicReportingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M1ThresholdEventA2ExtIEsValueExtensionTableCodec(table s00.M1ThresholdEventA2ExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M1ThresholdEventA2ExtIEsExtContainerValueCodec {
	if !*s00.BridgeM1ThresholdEventA2ExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M1ThresholdEventA2ExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M1ThresholdEventA2ExtIEsExtContainerValueCodec {
		sealed := s10.M1ThresholdEventA2ExtIEsExtContainerValueCodec{}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M1ThresholdEventA2ExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M1ThresholdEventA2ExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M1ThresholdEventA2ExtIEsExtField
					if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M1ThresholdEventA2ExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M1ThresholdEventA2ExtIEsExtContainer, options aper.DecodeState) (s10.M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M1ThresholdEventA2ExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M3ConfigurationExtIEsValueExtensionTableCodec(table s00.M3ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M3ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM3ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M3ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M3ConfigurationExtIEsExtContainerValueCodec {
		sealed := s10.M3ConfigurationExtIEsExtContainerValueCodec{}
		*s10.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M3ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M3ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M3ConfigurationExtIEsExtField
					if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M3ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M3ConfigurationExtIEsExtContainer, options aper.DecodeState) (s10.M3ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M3ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M4ConfigurationExtIEsValueExtensionTableCodec(table s00.M4ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M4ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM4ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M4ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M4ConfigurationExtIEsExtContainerValueCodec {
		sealed := s10.M4ConfigurationExtIEsExtContainerValueCodec{}
		*s10.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M4ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M4ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M4ConfigurationExtIEsExtField
					if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M4ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M4ConfigurationExtIEsExtContainer, options aper.DecodeState) (s10.M4ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M4ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M5ConfigurationExtIEsValueExtensionTableCodec(table s00.M5ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M5ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM5ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M5ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M5ConfigurationExtIEsExtContainerValueCodec {
		sealed := s10.M5ConfigurationExtIEsExtContainerValueCodec{}
		*s10.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M5ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M5ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M5ConfigurationExtIEsExtField
					if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M5ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M5ConfigurationExtIEsExtContainer, options aper.DecodeState) (s10.M5ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M5ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M6ConfigurationExtIEsValueExtensionTableCodec(table s00.M6ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M6ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM6ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M6ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M6ConfigurationExtIEsExtContainerValueCodec {
		sealed := s10.M6ConfigurationExtIEsExtContainerValueCodec{}
		*s10.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M6ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M6ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M6ConfigurationExtIEsExtField
					if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M6ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M6ConfigurationExtIEsExtContainer, options aper.DecodeState) (s10.M6ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M6ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func M7ConfigurationExtIEsValueExtensionTableCodec(table s00.M7ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.M7ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM7ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.M7ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.M7ConfigurationExtIEsExtContainerValueCodec {
		sealed := s10.M7ConfigurationExtIEsExtContainerValueCodec{}
		*s10.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.M7ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.M7ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.M7ConfigurationExtIEsExtField
					if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.M7ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.M7ConfigurationExtIEsExtContainer, options aper.DecodeState) (s10.M7ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.M7ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MBSFNResultToLogInfoExtIEsValueExtensionTableCodec(table s00.MBSFNResultToLogInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s10.MBSFNResultToLogInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeMBSFNResultToLogInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s10.MBSFNResultToLogInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.MBSFNResultToLogInfoExtIEsExtContainerValueCodec {
		sealed := s10.MBSFNResultToLogInfoExtIEsExtContainerValueCodec{}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MBSFNResultToLogInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.MBSFNResultToLogInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.MBSFNResultToLogInfoExtIEsExtField
					if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.MBSFNResultToLogInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.MBSFNResultToLogInfoExtIEsExtContainer, options aper.DecodeState) (s10.MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.MBSFNResultToLogInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MutingPatternInformationExtIEsValueExtensionTableCodec(table s00.MutingPatternInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.MutingPatternInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeMutingPatternInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.MutingPatternInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.MutingPatternInformationExtIEsExtContainerValueCodec {
		sealed := s10.MutingPatternInformationExtIEsExtContainerValueCodec{}
		*s10.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MutingPatternInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.MutingPatternInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.MutingPatternInformationExtIEsExtField
					if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.MutingPatternInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.MutingPatternInformationExtIEsExtContainer, options aper.DecodeState) (s10.MutingPatternInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.MutingPatternInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NBIoTPagingEDRXInformationExtIEsValueExtensionTableCodec(table s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeNBIoTPagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec {
		sealed := s10.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec{}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NBIoTPagingEDRXInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NBIoTPagingEDRXInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NBIoTPagingEDRXInformationExtIEsExtField
					if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NBIoTPagingEDRXInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NBIoTPagingEDRXInformationExtIEsExtContainer, options aper.DecodeState) (s10.NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NBIoTPagingEDRXInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NGENBExtIEsValueExtensionTableCodec(table s00.NGENBExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NGENBExtIEsExtContainerValueCodec {
	if !*s00.BridgeNGENBExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NGENBExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NGENBExtIEsExtContainerValueCodec {
		sealed := s10.NGENBExtIEsExtContainerValueCodec{}
		*s10.BridgeNGENBExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NGENBExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NGENBExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NGENBExtIEsExtField
					if err := s10.BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNGENBExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NGENBExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNGENBExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NGENBExtIEsExtContainer, options aper.DecodeState) (s10.NGENBExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNGENBExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NGENBExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNGENBExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNGENBExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NRCGIExtIEsValueExtensionTableCodec(table s00.NRCGIExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NRCGIExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRCGIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NRCGIExtIEsExtContainerValueCodec {
		sealed := s10.NRCGIExtIEsExtContainerValueCodec{}
		*s10.BridgeNRCGIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRCGIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NRCGIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NRCGIExtIEsExtField
					if err := s10.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNRCGIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NRCGIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNRCGIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NRCGIExtIEsExtContainer, options aper.DecodeState) (s10.NRCGIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNRCGIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NRCGIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRCGIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NRUESecurityCapabilitiesExtIEsValueExtensionTableCodec(table s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec {
		sealed := s10.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec{}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRUESecurityCapabilitiesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NRUESecurityCapabilitiesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NRUESecurityCapabilitiesExtIEsExtField
					if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NRUESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NRUESecurityCapabilitiesExtIEsExtContainer, options aper.DecodeState) (s10.NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NRUESecurityCapabilitiesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableCodec(table s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec {
		sealed := s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec{}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
					if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, options aper.DecodeState) (s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NRV2XServicesAuthorizedExtIEsValueExtensionTableCodec(table s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s10.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s10.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec {
		sealed := s10.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec{}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NRV2XServicesAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NRV2XServicesAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NRV2XServicesAuthorizedExtIEsExtField
					if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.NRV2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.NRV2XServicesAuthorizedExtIEsExtContainer, options aper.DecodeState) (s10.NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.NRV2XServicesAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PC5FlowBitRatesExtIEsValueExtensionTableCodec(table s00.PC5FlowBitRatesExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PC5FlowBitRatesExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5FlowBitRatesExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5FlowBitRatesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PC5FlowBitRatesExtIEsExtContainerValueCodec {
		sealed := s10.PC5FlowBitRatesExtIEsExtContainerValueCodec{}
		*s10.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5FlowBitRatesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PC5FlowBitRatesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PC5FlowBitRatesExtIEsExtField
					if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PC5FlowBitRatesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PC5FlowBitRatesExtIEsExtContainer, options aper.DecodeState) (s10.PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PC5FlowBitRatesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PC5QoSFlowItemExtIEsValueExtensionTableCodec(table s00.PC5QoSFlowItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PC5QoSFlowItemExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PC5QoSFlowItemExtIEsExtContainerValueCodec {
		sealed := s10.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PC5QoSFlowItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PC5QoSFlowItemExtIEsExtField
					if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PC5QoSFlowItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtContainer, options aper.DecodeState) (s10.PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSFlowItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PC5QoSParametersExtIEsValueExtensionTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PC5QoSParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PC5QoSParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PC5QoSParametersExtIEsExtContainerValueCodec {
		sealed := s10.PC5QoSParametersExtIEsExtContainerValueCodec{}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PC5QoSParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PC5QoSParametersExtIEsExtField
					if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PC5QoSParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PC5QoSParametersExtIEsExtContainer, options aper.DecodeState) (s10.PC5QoSParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PC5QoSParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PLMNAreaBasedQMCExtIEsValueExtensionTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
		sealed := s10.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PLMNAreaBasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PLMNAreaBasedQMCExtIEsExtField
					if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PLMNAreaBasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtContainer, options aper.DecodeState) (s10.PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PLMNAreaBasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PSCellInformationExtIEsValueExtensionTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PSCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PSCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PSCellInformationExtIEsExtContainerValueCodec {
		sealed := s10.PSCellInformationExtIEsExtContainerValueCodec{}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PSCellInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PSCellInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PSCellInformationExtIEsExtField
					if err := s10.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PSCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PSCellInformationExtIEsExtContainer, options aper.DecodeState) (s10.PSCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PSCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePSCellInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func PagingAttemptInformationExtIEsValueExtensionTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s10.PagingAttemptInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s10.PagingAttemptInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.PagingAttemptInformationExtIEsExtContainerValueCodec {
		sealed := s10.PagingAttemptInformationExtIEsExtContainerValueCodec{}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.PagingAttemptInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.PagingAttemptInformationExtIEsExtField
					if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.PagingAttemptInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtContainer, options aper.DecodeState) (s10.PagingAttemptInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.PagingAttemptInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DeactivateTraceIEValueIEFieldTableCodec(table s00.DeactivateTraceIEValueIETable) s08.DeactivateTraceIEFieldValueCodec {
	if !*s00.BridgeDeactivateTraceIEValueIETableFieldBound(&table) {
		return s08.DeactivateTraceIEFieldValueCodec{}
	}
	return func() s08.DeactivateTraceIEFieldValueCodec {
		sealed := s08.DeactivateTraceIEFieldValueCodec{}
		*s08.BridgeDeactivateTraceIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DeactivateTraceIEField, error) {
			var field s08.DeactivateTraceIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDeactivateTraceIEFieldValueCodecFieldEncode(&sealed) = func(field s08.DeactivateTraceIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDeactivateTraceIEFieldValueCodecFieldCapture(&sealed) = func(v s08.DeactivateTraceIEField, options aper.DecodeState) (s08.DeactivateTraceIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s08.BridgeDeactivateTraceIEFieldValueCodecFieldCompare(&sealed) = func(v s08.DeactivateTraceIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDeactivateTraceIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s08.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s08.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEField, error) {
			var field s08.DownlinkNonUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s08.DownlinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeDownlinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s08.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s08.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s08.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEField, error) {
			var field s08.DownlinkUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s08.DownlinkUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EventTriggerExtIEValueIEFieldTableCodec(table s00.EventTriggerExtIEValueIETable) s09.EventTriggerExtIEFieldValueCodec {
	if !*s00.BridgeEventTriggerExtIEValueIETableFieldBound(&table) {
		return s09.EventTriggerExtIEFieldValueCodec{}
	}
	return func() s09.EventTriggerExtIEFieldValueCodec {
		sealed := s09.EventTriggerExtIEFieldValueCodec{}
		*s09.BridgeEventTriggerExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventTriggerExtIEField, error) {
			var field s09.EventTriggerExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeEventTriggerExtIEFieldValueCodecFieldEncode(&sealed) = func(field s09.EventTriggerExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeEventTriggerExtIEFieldValueCodecFieldCapture(&sealed) = func(v s09.EventTriggerExtIEField, options aper.DecodeState) (s09.EventTriggerExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s09.BridgeEventTriggerExtIEFieldValueCodecFieldCompare(&sealed) = func(v s09.EventTriggerExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventTriggerExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverSuccessIEValueIEFieldTableCodec(table s00.HandoverSuccessIEValueIETable) s09.HandoverSuccessIEFieldValueCodec {
	if !*s00.BridgeHandoverSuccessIEValueIETableFieldBound(&table) {
		return s09.HandoverSuccessIEFieldValueCodec{}
	}
	return func() s09.HandoverSuccessIEFieldValueCodec {
		sealed := s09.HandoverSuccessIEFieldValueCodec{}
		*s09.BridgeHandoverSuccessIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.HandoverSuccessIEField, error) {
			var field s09.HandoverSuccessIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s09.BridgeHandoverSuccessIEFieldValueCodecFieldEncode(&sealed) = func(field s09.HandoverSuccessIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeHandoverSuccessIEFieldValueCodecFieldCapture(&sealed) = func(v s09.HandoverSuccessIEField, options aper.DecodeState) (s09.HandoverSuccessIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s09.BridgeHandoverSuccessIEFieldValueCodecFieldCompare(&sealed) = func(v s09.HandoverSuccessIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeHandoverSuccessIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MMECPRelocationIndicationIEValueIEFieldTableCodec(table s00.MMECPRelocationIndicationIEValueIETable) s10.MMECPRelocationIndicationIEFieldValueCodec {
	if !*s00.BridgeMMECPRelocationIndicationIEValueIETableFieldBound(&table) {
		return s10.MMECPRelocationIndicationIEFieldValueCodec{}
	}
	return func() s10.MMECPRelocationIndicationIEFieldValueCodec {
		sealed := s10.MMECPRelocationIndicationIEFieldValueCodec{}
		*s10.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MMECPRelocationIndicationIEField, error) {
			var field s10.MMECPRelocationIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s10.MMECPRelocationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s10.MMECPRelocationIndicationIEField, options aper.DecodeState) (s10.MMECPRelocationIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s10.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s10.MMECPRelocationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MeasurementThresholdL1LoggedMDTExtIEValueIEFieldTableCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s10.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec {
	if !*s00.BridgeMeasurementThresholdL1LoggedMDTExtIEValueIETableFieldBound(&table) {
		return s10.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec{}
	}
	return func() s10.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec {
		sealed := s10.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec{}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEField, error) {
			var field s10.MeasurementThresholdL1LoggedMDTExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldEncode(&sealed) = func(field s10.MeasurementThresholdL1LoggedMDTExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCapture(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEField, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCompare(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NASDeliveryIndicationIEValueIEFieldTableCodec(table s00.NASDeliveryIndicationIEValueIETable) s10.NASDeliveryIndicationIEFieldValueCodec {
	if !*s00.BridgeNASDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s10.NASDeliveryIndicationIEFieldValueCodec{}
	}
	return func() s10.NASDeliveryIndicationIEFieldValueCodec {
		sealed := s10.NASDeliveryIndicationIEFieldValueCodec{}
		*s10.BridgeNASDeliveryIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NASDeliveryIndicationIEField, error) {
			var field s10.NASDeliveryIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s10.BridgeNASDeliveryIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s10.NASDeliveryIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeNASDeliveryIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s10.NASDeliveryIndicationIEField, options aper.DecodeState) (s10.NASDeliveryIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s10.BridgeNASDeliveryIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s10.NASDeliveryIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNASDeliveryIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DeactivateTraceIEValueIETableCodec(table s00.DeactivateTraceIEValueIETable, bounds aper.ListBounds) s08.DeactivateTraceIEContainerValueCodec {
	if !*s00.BridgeDeactivateTraceIEValueIETableFieldBound(&table) {
		return s08.DeactivateTraceIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DeactivateTraceIEContainerValueCodec {
		sealed := s08.DeactivateTraceIEContainerValueCodec{}
		*s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DeactivateTraceIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DeactivateTraceIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DeactivateTraceIEField
					if err := s08.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&sealed) = func(fields s08.DeactivateTraceIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDeactivateTraceIEContainerValueCodecFieldCapture(&sealed) = func(v s08.DeactivateTraceIEContainer, options aper.DecodeState) (s08.DeactivateTraceIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDeactivateTraceIEContainerValueCodecFieldCompare(&sealed) = func(v s08.DeactivateTraceIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDeactivateTraceIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s08.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s08.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DownlinkNonUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DownlinkNonUEAssociatedLPPaTransportIEField
					if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s08.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeDownlinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s08.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s08.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.DownlinkUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.DownlinkUEAssociatedLPPaTransportIEField
					if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s08.DownlinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EventTriggerExtIEValueIETableCodec(table s00.EventTriggerExtIEValueIETable, bounds aper.ListBounds) s09.EventTriggerExtIEContainerValueCodec {
	if !*s00.BridgeEventTriggerExtIEValueIETableFieldBound(&table) {
		return s09.EventTriggerExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.EventTriggerExtIEContainerValueCodec {
		sealed := s09.EventTriggerExtIEContainerValueCodec{}
		*s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventTriggerExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.EventTriggerExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.EventTriggerExtIEField
					if err := s09.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s09.EventTriggerExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeEventTriggerExtIEContainerValueCodecFieldCapture(&sealed) = func(v s09.EventTriggerExtIEContainer, options aper.DecodeState) (s09.EventTriggerExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEventTriggerExtIEContainerValueCodecFieldCompare(&sealed) = func(v s09.EventTriggerExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventTriggerExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func HandoverSuccessIEValueIETableCodec(table s00.HandoverSuccessIEValueIETable, bounds aper.ListBounds) s09.HandoverSuccessIEContainerValueCodec {
	if !*s00.BridgeHandoverSuccessIEValueIETableFieldBound(&table) {
		return s09.HandoverSuccessIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.HandoverSuccessIEContainerValueCodec {
		sealed := s09.HandoverSuccessIEContainerValueCodec{}
		*s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.HandoverSuccessIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.HandoverSuccessIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.HandoverSuccessIEField
					if err := s09.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s09.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&sealed) = func(fields s09.HandoverSuccessIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeHandoverSuccessIEContainerValueCodecFieldCapture(&sealed) = func(v s09.HandoverSuccessIEContainer, options aper.DecodeState) (s09.HandoverSuccessIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeHandoverSuccessIEContainerValueCodecFieldCompare(&sealed) = func(v s09.HandoverSuccessIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeHandoverSuccessIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MMECPRelocationIndicationIEValueIETableCodec(table s00.MMECPRelocationIndicationIEValueIETable, bounds aper.ListBounds) s10.MMECPRelocationIndicationIEContainerValueCodec {
	if !*s00.BridgeMMECPRelocationIndicationIEValueIETableFieldBound(&table) {
		return s10.MMECPRelocationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.MMECPRelocationIndicationIEContainerValueCodec {
		sealed := s10.MMECPRelocationIndicationIEContainerValueCodec{}
		*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MMECPRelocationIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.MMECPRelocationIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.MMECPRelocationIndicationIEField
					if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s10.MMECPRelocationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s10.MMECPRelocationIndicationIEContainer, options aper.DecodeState) (s10.MMECPRelocationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s10.MMECPRelocationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable, bounds aper.ListBounds) s10.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec {
	if !*s00.BridgeMeasurementThresholdL1LoggedMDTExtIEValueIETableFieldBound(&table) {
		return s10.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec {
		sealed := s10.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec{}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.MeasurementThresholdL1LoggedMDTExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.MeasurementThresholdL1LoggedMDTExtIEField
					if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s10.MeasurementThresholdL1LoggedMDTExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCapture(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEContainer, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCompare(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NASDeliveryIndicationIEValueIETableCodec(table s00.NASDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s10.NASDeliveryIndicationIEContainerValueCodec {
	if !*s00.BridgeNASDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s10.NASDeliveryIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.NASDeliveryIndicationIEContainerValueCodec {
		sealed := s10.NASDeliveryIndicationIEContainerValueCodec{}
		*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NASDeliveryIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.NASDeliveryIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.NASDeliveryIndicationIEField
					if err := s10.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s10.NASDeliveryIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s10.NASDeliveryIndicationIEContainer, options aper.DecodeState) (s10.NASDeliveryIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s10.NASDeliveryIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DeactivateTraceIEValueProtocolErrorIEContainerListCodec(table s00.DeactivateTraceIEValueIETable) s08.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s08.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s08.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec{}
		*s08.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DeactivateTraceIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DeactivateTraceIEValueProtocolErrorIEContainerList(value), err
		}
		*s08.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DeactivateTraceIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s08.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s08.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DeactivateTraceIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s08.DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DeactivateTraceIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList(value), err
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList(value), err
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func EventTriggerExtIEValueProtocolErrorIEContainerListCodec(table s00.EventTriggerExtIEValueIETable) s09.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s09.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s09.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s09.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventTriggerExtIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.EventTriggerExtIEValueProtocolErrorIEContainerList(value), err
		}
		*s09.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.EventTriggerExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s09.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s09.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.EventTriggerExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s09.EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.EventTriggerExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverSuccessIEValueProtocolErrorIEContainerListCodec(table s00.HandoverSuccessIEValueIETable) s09.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s09.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s09.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec{}
		*s09.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.HandoverSuccessIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.HandoverSuccessIEValueProtocolErrorIEContainerList(value), err
		}
		*s09.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.HandoverSuccessIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s09.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s09.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.HandoverSuccessIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s09.HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.HandoverSuccessIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MMECPRelocationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable) s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s10.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList(value), err
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s10.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func NASDeliveryIndicationIEValueProtocolErrorIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable) s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s10.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func DeactivateTraceIEValueProtocolIEContainerListCodec(table s00.DeactivateTraceIEValueIETable, bounds aper.ListBounds) s08.DeactivateTraceIEValueProtocolIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, bounds)
	if *s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DeactivateTraceIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s08.DeactivateTraceIEValueProtocolIEContainerListValueCodec {
		sealed := s08.DeactivateTraceIEValueProtocolIEContainerListValueCodec{}
		*s08.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DeactivateTraceIEValueProtocolIEContainerList, error) {
			value, err := (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DeactivateTraceIEValueProtocolIEContainerList(value), err
		}
		*s08.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DeactivateTraceIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s08.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s08.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DeactivateTraceIEValueProtocolIEContainerList, options aper.DecodeState) (s08.DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s08.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DeactivateTraceIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList(value), err
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			value, err := (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList(value), err
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s08.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s08.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func EventTriggerExtIEValueProtocolIEContainerListCodec(table s00.EventTriggerExtIEValueIETable, bounds aper.ListBounds) s09.EventTriggerExtIEValueProtocolIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, bounds)
	if *s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.EventTriggerExtIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s09.EventTriggerExtIEValueProtocolIEContainerListValueCodec {
		sealed := s09.EventTriggerExtIEValueProtocolIEContainerListValueCodec{}
		*s09.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.EventTriggerExtIEValueProtocolIEContainerList, error) {
			value, err := (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.EventTriggerExtIEValueProtocolIEContainerList(value), err
		}
		*s09.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.EventTriggerExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s09.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s09.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.EventTriggerExtIEValueProtocolIEContainerList, options aper.DecodeState) (s09.EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s09.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.EventTriggerExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func HandoverSuccessIEValueProtocolIEContainerListCodec(table s00.HandoverSuccessIEValueIETable, bounds aper.ListBounds) s09.HandoverSuccessIEValueProtocolIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, bounds)
	if *s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.HandoverSuccessIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s09.HandoverSuccessIEValueProtocolIEContainerListValueCodec {
		sealed := s09.HandoverSuccessIEValueProtocolIEContainerListValueCodec{}
		*s09.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.HandoverSuccessIEValueProtocolIEContainerList, error) {
			value, err := (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s09.HandoverSuccessIEValueProtocolIEContainerList(value), err
		}
		*s09.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.HandoverSuccessIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s09.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s09.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.HandoverSuccessIEValueProtocolIEContainerList, options aper.DecodeState) (s09.HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s09.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.HandoverSuccessIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MMECPRelocationIndicationIEValueProtocolIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable, bounds aper.ListBounds) s10.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, bounds)
	if *s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s10.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s10.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MMECPRelocationIndicationIEValueProtocolIEContainerList(value), err
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s10.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable, bounds aper.ListBounds) s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, bounds)
	if *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec {
		sealed := s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec{}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, error) {
			value, err := (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList(value), err
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s10.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, options aper.DecodeState) (s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func NASDeliveryIndicationIEValueProtocolIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s10.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, bounds)
	if *s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s10.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s10.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s10.NASDeliveryIndicationIEValueProtocolIEContainerList(value), err
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.NASDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s10.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.NASDeliveryIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s10.NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.NASDeliveryIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(v *s09.InformationForCECapableUEsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeInformationForCECapableUEsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeInformationForCECapableUEsExtIEsExtFieldFieldReplay(v), *s09.BridgeInformationForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(v *s09.InformationForCECapableUEsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeInformationForCECapableUEsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeInformationForCECapableUEsExtIEsExtFieldFieldReplay(v), *s09.BridgeInformationForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CellIDCancelledItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellIDCancelledItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCellIDCancelledItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCellIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(v *s07.CellIDCancelledItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellIDCancelledItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCellIDCancelledItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCellIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldReplay(v), *s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(v *s07.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldReplay(v), *s07.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CellTypeExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellTypeExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCellTypeExtIEsExtFieldFieldReplay(v), *s07.BridgeCellTypeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionField(v *s07.CellTypeExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellTypeExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCellTypeExtIEsExtFieldFieldReplay(v), *s07.BridgeCellTypeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CompletedCellinEAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCompletedCellinEAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s07.CompletedCellinEAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCompletedCellinEAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CompletedCellinTAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCompletedCellinTAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s07.CompletedCellinTAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCompletedCellinTAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionField(v *s07.ConnectedengNBItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeConnectedengNBItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeConnectedengNBItemExtIEsExtFieldFieldReplay(v), *s07.BridgeConnectedengNBItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionField(v *s07.ConnectedengNBItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeConnectedengNBItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeConnectedengNBItemExtIEsExtFieldFieldReplay(v), *s07.BridgeConnectedengNBItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionField(v *s07.ContextatSourceExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeContextatSourceExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeContextatSourceExtIEsExtFieldFieldReplay(v), *s07.BridgeContextatSourceExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionField(v *s07.ContextatSourceExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeContextatSourceExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeContextatSourceExtIEsExtFieldFieldReplay(v), *s07.BridgeContextatSourceExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s07.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionField(v *s07.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s07.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionField(v *s07.CriticalityDiagnosticsIEItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionField(v *s07.CriticalityDiagnosticsIEItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldReplay(v), *s07.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s07.DAPSRequestInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDAPSRequestInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s07.BridgeDAPSRequestInfoExtIEsExtFieldFieldReplay(v), *s07.BridgeDAPSRequestInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionField(v *s07.DAPSRequestInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDAPSRequestInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s07.BridgeDAPSRequestInfoExtIEsExtFieldFieldReplay(v), *s07.BridgeDAPSRequestInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s08.DAPSResponseInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDAPSResponseInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeDAPSResponseInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeDAPSResponseInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionField(v *s08.DAPSResponseInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDAPSResponseInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeDAPSResponseInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeDAPSResponseInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.DAPSResponseInfoItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDAPSResponseInfoItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldReplay(v), *s08.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.DAPSResponseInfoItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDAPSResponseInfoItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldReplay(v), *s08.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s08.DLCPSecurityInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDLCPSecurityInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeDLCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s08.BridgeDLCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(v *s08.DLCPSecurityInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDLCPSecurityInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeDLCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s08.BridgeDLCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// deactivateTraceIEValueProtocolOpenValue is the concrete protocolOpenValue[DeactivateTraceIEValue].
type DeactivateTraceIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.DeactivateTraceIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.DeactivateTraceIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(v *s08.DeactivateTraceIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s08.BridgeDeactivateTraceIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s08.BridgeDeactivateTraceIEFieldFieldReplay(v), *s08.BridgeDeactivateTraceIEFieldFieldWithoutReplay(v))
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(v *s08.DeactivateTraceIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeDeactivateTraceIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s08.BridgeDeactivateTraceIEFieldFieldReplay(v), *s08.BridgeDeactivateTraceIEFieldFieldWithoutReplay(v))
}

// downlinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkNonUEAssociatedLPPaTransportIEValue].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.DownlinkNonUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.DownlinkNonUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s08.DownlinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s08.DownlinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}

// downlinkUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkUEAssociatedLPPaTransportIEValue].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.DownlinkUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.DownlinkUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s08.DownlinkUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s08.DownlinkUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENBStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v), *s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENBStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v), *s08.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENBX2ExtTLAExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENBX2ExtTLAExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENBX2ExtTLAExtIEsExtFieldFieldReplay(v), *s08.BridgeENBX2ExtTLAExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENBX2ExtTLAExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENBX2ExtTLAExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENBX2ExtTLAExtIEsExtFieldFieldReplay(v), *s08.BridgeENBX2ExtTLAExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENDCSONConfigurationTransferExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENDCSONConfigurationTransferExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENDCSONConfigurationTransferExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENDCSONConfigurationTransferExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENDCSONeNBIdentificationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENDCSONeNBIdentificationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENDCSONeNBIdentificationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENDCSONeNBIdentificationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENDCSONengNBIdentificationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENDCSONengNBIdentificationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENDCSONengNBIdentificationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENDCSONengNBIdentificationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENDCTransferTypeReplyExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENDCTransferTypeReplyExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENDCTransferTypeReplyExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENDCTransferTypeReplyExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ENDCTransferTypeRequestExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeENDCTransferTypeRequestExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionField(v *s08.ENDCTransferTypeRequestExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeENDCTransferTypeRequestExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldReplay(v), *s08.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABAdmittedItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABAdmittedItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABAdmittedItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABAdmittedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABAdmittedItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABAdmittedItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABAdmittedItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABAdmittedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABDataForwardingItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABDataForwardingItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABDataForwardingItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABDataForwardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABDataForwardingItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABDataForwardingItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABDataForwardingItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABDataForwardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABFailedToResumeItemResumeReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABFailedToResumeItemResumeReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABFailedToResumeItemResumeResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABFailedToResumeItemResumeResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABFailedToSetupItemHOReqAckExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldReplay(v), *s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABItemExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABQoSParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABQoSParametersExtIEsValue].
type ERABQoSParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.ERABQoSParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.ERABQoSParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABQoSParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s08.BridgeERABQoSParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABQoSParametersExtIEsExtFieldFieldReplay(v), *s08.BridgeERABQoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABQoSParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeERABQoSParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABQoSParametersExtIEsExtFieldFieldReplay(v), *s08.BridgeERABQoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABModifyItemBearerModConfExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABModifyItemBearerModConfExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldReplay(v), *s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABModifyItemBearerModConfExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABModifyItemBearerModConfExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldReplay(v), *s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABModifyItemBearerModResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABModifyItemBearerModResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABModifyItemBearerModResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABModifyItemBearerModResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABReleaseItemBearerRelCompExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldReplay(v), *s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABReleaseItemBearerRelCompExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldReplay(v), *s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABSecurityResultItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeERABSecurityResultItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABSecurityResultItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSecurityResultItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABSecurityResultItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeERABSecurityResultItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABSecurityResultItemExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSecurityResultItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABSetupItemBearerSUResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABSetupItemBearerSUResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionField(v *s08.ERABSetupItemCtxtSUResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionField(v *s08.ERABSetupItemCtxtSUResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldReplay(v), *s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(v *s09.ERABToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ERABToBeSwitchedULItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ERABToBeSwitchedULItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ERABToBeUpdatedItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeUpdatedItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ERABToBeUpdatedItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeUpdatedItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ERABUsageReportItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABUsageReportItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeERABUsageReportItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ERABUsageReportItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABUsageReportItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeERABUsageReportItemExtIEsExtFieldFieldReplay(v), *s09.BridgeERABUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionField(v *s09.EUTRANCGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEUTRANCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeEUTRANCGIExtIEsExtFieldFieldReplay(v), *s09.BridgeEUTRANCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionField(v *s09.EUTRANCGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEUTRANCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeEUTRANCGIExtIEsExtFieldFieldReplay(v), *s09.BridgeEUTRANCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.EmergencyAreaIDBroadcastItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.EmergencyAreaIDBroadcastItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s09.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.EmergencyAreaIDCancelledItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldReplay(v), *s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.EmergencyAreaIDCancelledItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldReplay(v), *s09.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionField(v *s09.EventL1LoggedMDTConfigExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldReplay(v), *s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionField(v *s09.EventL1LoggedMDTConfigExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldReplay(v), *s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(v *s09.EventTriggerExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s04.BridgeEventTriggerExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s09.BridgeEventTriggerExtIEFieldFieldReplay(v), *s09.BridgeEventTriggerExtIEFieldFieldWithoutReplay(v))
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(v *s09.EventTriggerExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEventTriggerExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeEventTriggerExtIEFieldFieldReplay(v), *s09.BridgeEventTriggerExtIEFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ExpectedUEActivityBehaviourExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeExpectedUEActivityBehaviourExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldReplay(v), *s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionField(v *s09.ExpectedUEActivityBehaviourExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeExpectedUEActivityBehaviourExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldReplay(v), *s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ExpectedUEBehaviourExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeExpectedUEBehaviourExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeExpectedUEBehaviourExtIEsExtFieldFieldReplay(v), *s09.BridgeExpectedUEBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionField(v *s09.ExpectedUEBehaviourExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeExpectedUEBehaviourExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeExpectedUEBehaviourExtIEsExtFieldFieldReplay(v), *s09.BridgeExpectedUEBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionField(v *s09.FiveGSTAIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeFiveGSTAIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeFiveGSTAIExtIEsExtFieldFieldReplay(v), *s09.BridgeFiveGSTAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionField(v *s09.FiveGSTAIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeFiveGSTAIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeFiveGSTAIExtIEsExtFieldFieldReplay(v), *s09.BridgeFiveGSTAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ForbiddenLAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeForbiddenLAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeForbiddenLAsItemExtIEsExtFieldFieldReplay(v), *s09.BridgeForbiddenLAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ForbiddenLAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeForbiddenLAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeForbiddenLAsItemExtIEsExtFieldFieldReplay(v), *s09.BridgeForbiddenLAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ForbiddenTAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeForbiddenTAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeForbiddenTAsItemExtIEsExtFieldFieldReplay(v), *s09.BridgeForbiddenTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ForbiddenTAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeForbiddenTAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeForbiddenTAsItemExtIEsExtFieldFieldReplay(v), *s09.BridgeForbiddenTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GBRQosInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGBRQosInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGBRQosInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeGBRQosInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionField(v *s09.GBRQosInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGBRQosInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGBRQosInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeGBRQosInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GERANCellIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGERANCellIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGERANCellIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGERANCellIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionField(v *s09.GERANCellIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGERANCellIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGERANCellIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGERANCellIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGNBExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GNBExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGNBExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGNBExtIEsExtFieldFieldReplay(v), *s09.BridgeGNBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGNBExtIEsValueCompareS1APProtocolExtensionField(v *s09.GNBExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGNBExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGNBExtIEsExtFieldFieldReplay(v), *s09.BridgeGNBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GUMMEIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGUMMEIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGUMMEIExtIEsExtFieldFieldReplay(v), *s09.BridgeGUMMEIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionField(v *s09.GUMMEIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGUMMEIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGUMMEIExtIEsExtFieldFieldReplay(v), *s09.BridgeGUMMEIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GlobalENBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGlobalENBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGlobalENBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalENBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionField(v *s09.GlobalENBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGlobalENBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGlobalENBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalENBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GlobalEnGNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGlobalEnGNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGlobalEnGNBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalEnGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s09.GlobalEnGNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGlobalEnGNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGlobalEnGNBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalEnGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s09.GlobalGNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeGlobalGNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeGlobalGNBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s09.GlobalGNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeGlobalGNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeGlobalGNBIDExtIEsExtFieldFieldReplay(v), *s09.BridgeGlobalGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}

// handoverSuccessIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverSuccessIEValue].
type HandoverSuccessIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.HandoverSuccessIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.HandoverSuccessIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(v *s09.HandoverSuccessIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s09.BridgeHandoverSuccessIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s09.BridgeHandoverSuccessIEFieldFieldReplay(v), *s09.BridgeHandoverSuccessIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(v *s09.HandoverSuccessIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s09.BridgeHandoverSuccessIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeHandoverSuccessIEFieldFieldReplay(v), *s09.BridgeHandoverSuccessIEFieldFieldWithoutReplay(v))
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldReplay(v), *s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldReplay(v), *s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}

// interSystemMeasurementItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterSystemMeasurementItemExtIEsValue].
type InterSystemMeasurementItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.InterSystemMeasurementItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.InterSystemMeasurementItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.InterSystemMeasurementItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeInterSystemMeasurementItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldReplay(v), *s09.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.InterSystemMeasurementItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeInterSystemMeasurementItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldReplay(v), *s09.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldWithoutReplay(v))
}

// interSystemMeasurementParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterSystemMeasurementParametersExtIEsValue].
type InterSystemMeasurementParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.InterSystemMeasurementParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.InterSystemMeasurementParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s09.InterSystemMeasurementParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeInterSystemMeasurementParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldReplay(v), *s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionField(v *s09.InterSystemMeasurementParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeInterSystemMeasurementParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldReplay(v), *s09.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldWithoutReplay(v))
}

// intersystemMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[IntersystemMeasurementConfigurationExtIEsValue].
type IntersystemMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.IntersystemMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.IntersystemMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.IntersystemMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s09.IntersystemMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s09.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// lAIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LAIExtIEsValue].
type LAIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.LAIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.LAIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLAIExtIEsValueCaptureS1APProtocolExtensionField(v *s09.LAIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeLAIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeLAIExtIEsExtFieldFieldReplay(v), *s09.BridgeLAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLAIExtIEsValueCompareS1APProtocolExtensionField(v *s09.LAIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeLAIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeLAIExtIEsExtFieldFieldReplay(v), *s09.BridgeLAIExtIEsExtFieldFieldWithoutReplay(v))
}

// lTENTNTAIInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LTENTNTAIInformationExtIEsValue].
type LTENTNTAIInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.LTENTNTAIInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.LTENTNTAIInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.LTENTNTAIInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeLTENTNTAIInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeLTENTNTAIInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeLTENTNTAIInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionField(v *s09.LTENTNTAIInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeLTENTNTAIInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeLTENTNTAIInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeLTENTNTAIInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// lastVisitedPSCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LastVisitedPSCellInformationExtIEsValue].
type LastVisitedPSCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.LastVisitedPSCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.LastVisitedPSCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.LastVisitedPSCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeLastVisitedPSCellInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *s09.LastVisitedPSCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeLastVisitedPSCellInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// listeningSubframePatternExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ListeningSubframePatternExtIEsValue].
type ListeningSubframePatternExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.ListeningSubframePatternExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.ListeningSubframePatternExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ListeningSubframePatternExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeListeningSubframePatternExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeListeningSubframePatternExtIEsExtFieldFieldReplay(v), *s09.BridgeListeningSubframePatternExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionField(v *s09.ListeningSubframePatternExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeListeningSubframePatternExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeListeningSubframePatternExtIEsExtFieldFieldReplay(v), *s09.BridgeListeningSubframePatternExtIEsExtFieldFieldWithoutReplay(v))
}

// loggedMBSFNMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LoggedMBSFNMDTExtIEsValue].
type LoggedMBSFNMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.LoggedMBSFNMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.LoggedMBSFNMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s09.LoggedMBSFNMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeLoggedMBSFNMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldReplay(v), *s09.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionField(v *s09.LoggedMBSFNMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeLoggedMBSFNMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldReplay(v), *s09.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldWithoutReplay(v))
}

// m1PeriodicReportingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M1PeriodicReportingExtIEsValue].
type M1PeriodicReportingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.M1PeriodicReportingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.M1PeriodicReportingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionField(v *s09.M1PeriodicReportingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeM1PeriodicReportingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeM1PeriodicReportingExtIEsExtFieldFieldReplay(v), *s09.BridgeM1PeriodicReportingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionField(v *s09.M1PeriodicReportingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeM1PeriodicReportingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeM1PeriodicReportingExtIEsExtFieldFieldReplay(v), *s09.BridgeM1PeriodicReportingExtIEsExtFieldFieldWithoutReplay(v))
}

// m1ThresholdEventA2ExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M1ThresholdEventA2ExtIEsValue].
type M1ThresholdEventA2ExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.M1ThresholdEventA2ExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.M1ThresholdEventA2ExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M1ThresholdEventA2ExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeM1ThresholdEventA2ExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldReplay(v), *s10.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionField(v *s10.M1ThresholdEventA2ExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeM1ThresholdEventA2ExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldReplay(v), *s10.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldWithoutReplay(v))
}

// m3ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M3ConfigurationExtIEsValue].
type M3ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s04.M3ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s04.M3ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M3ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeM3ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM3ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM3ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s10.M3ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeM3ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM3ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM3ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// m4ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M4ConfigurationExtIEsValue].
type M4ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M4ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M4ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M4ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM4ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM4ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM4ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s10.M4ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM4ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM4ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM4ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// m5ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M5ConfigurationExtIEsValue].
type M5ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M5ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M5ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M5ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM5ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM5ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM5ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s10.M5ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM5ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM5ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM5ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// m6ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M6ConfigurationExtIEsValue].
type M6ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M6ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M6ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M6ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM6ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM6ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM6ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s10.M6ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM6ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM6ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM6ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// m7ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M7ConfigurationExtIEsValue].
type M7ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M7ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M7ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.M7ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM7ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeM7ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM7ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s10.M7ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM7ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeM7ConfigurationExtIEsExtFieldFieldReplay(v), *s10.BridgeM7ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// mBSFNResultToLogInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MBSFNResultToLogInfoExtIEsValue].
type MBSFNResultToLogInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.MBSFNResultToLogInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.MBSFNResultToLogInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s10.MBSFNResultToLogInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldReplay(v), *s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionField(v *s10.MBSFNResultToLogInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldReplay(v), *s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// mMECPRelocationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[MMECPRelocationIndicationIEValue].
type MMECPRelocationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.MMECPRelocationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.MMECPRelocationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(v *s10.MMECPRelocationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s10.BridgeMMECPRelocationIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s10.BridgeMMECPRelocationIndicationIEFieldFieldReplay(v), *s10.BridgeMMECPRelocationIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(v *s10.MMECPRelocationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s10.BridgeMMECPRelocationIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeMMECPRelocationIndicationIEFieldFieldReplay(v), *s10.BridgeMMECPRelocationIndicationIEFieldFieldWithoutReplay(v))
}

// measurementThresholdL1LoggedMDTExtIEValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementThresholdL1LoggedMDTExtIEValue].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.MeasurementThresholdL1LoggedMDTExtIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.MeasurementThresholdL1LoggedMDTExtIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(v *s10.MeasurementThresholdL1LoggedMDTExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s05.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldReplay(v), *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldWithoutReplay(v))
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(v *s10.MeasurementThresholdL1LoggedMDTExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldReplay(v), *s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldWithoutReplay(v))
}

// mutingPatternInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MutingPatternInformationExtIEsValue].
type MutingPatternInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.MutingPatternInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.MutingPatternInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.MutingPatternInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeMutingPatternInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeMutingPatternInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeMutingPatternInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.MutingPatternInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeMutingPatternInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeMutingPatternInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeMutingPatternInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// nASDeliveryIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[NASDeliveryIndicationIEValue].
type NASDeliveryIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.NASDeliveryIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.NASDeliveryIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(v *s10.NASDeliveryIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s10.BridgeNASDeliveryIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s10.BridgeNASDeliveryIndicationIEFieldFieldReplay(v), *s10.BridgeNASDeliveryIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(v *s10.NASDeliveryIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s10.BridgeNASDeliveryIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeNASDeliveryIndicationIEFieldFieldReplay(v), *s10.BridgeNASDeliveryIndicationIEFieldFieldWithoutReplay(v))
}

// nBIoTPagingEDRXInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NBIoTPagingEDRXInformationExtIEsValue].
type NBIoTPagingEDRXInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NBIoTPagingEDRXInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NBIoTPagingEDRXInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NBIoTPagingEDRXInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.NBIoTPagingEDRXInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// nGENBExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NGENBExtIEsValue].
type NGENBExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NGENBExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NGENBExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NGENBExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNGENBExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNGENBExtIEsExtFieldFieldReplay(v), *s10.BridgeNGENBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNGENBExtIEsValueCompareS1APProtocolExtensionField(v *s10.NGENBExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNGENBExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNGENBExtIEsExtFieldFieldReplay(v), *s10.BridgeNGENBExtIEsExtFieldFieldWithoutReplay(v))
}

// nRCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRCGIExtIEsValue].
type NRCGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NRCGIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NRCGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NRCGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNRCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s10.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionField(v *s10.NRCGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNRCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s10.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}

// nRUESecurityCapabilitiesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRUESecurityCapabilitiesExtIEsValue].
type NRUESecurityCapabilitiesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NRUESecurityCapabilitiesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NRUESecurityCapabilitiesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NRUESecurityCapabilitiesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNRUESecurityCapabilitiesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(v *s10.NRUESecurityCapabilitiesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNRUESecurityCapabilitiesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}

// nRUESidelinkAggregateMaximumBitrateExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRUESidelinkAggregateMaximumBitrateExtIEsValue].
type NRUESidelinkAggregateMaximumBitrateExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldReplay(v), *s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionField(v *s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldReplay(v), *s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldWithoutReplay(v))
}

// nRV2XServicesAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRV2XServicesAuthorizedExtIEsValue].
type NRV2XServicesAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.NRV2XServicesAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.NRV2XServicesAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s10.NRV2XServicesAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeNRV2XServicesAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s10.NRV2XServicesAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeNRV2XServicesAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5FlowBitRatesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5FlowBitRatesExtIEsValue].
type PC5FlowBitRatesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PC5FlowBitRatesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PC5FlowBitRatesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PC5FlowBitRatesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePC5FlowBitRatesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePC5FlowBitRatesExtIEsExtFieldFieldReplay(v), *s10.BridgePC5FlowBitRatesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionField(v *s10.PC5FlowBitRatesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePC5FlowBitRatesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePC5FlowBitRatesExtIEsExtFieldFieldReplay(v), *s10.BridgePC5FlowBitRatesExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5QoSFlowItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSFlowItemExtIEsValue].
type PC5QoSFlowItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PC5QoSFlowItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PC5QoSFlowItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PC5QoSFlowItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePC5QoSFlowItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePC5QoSFlowItemExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSFlowItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.PC5QoSFlowItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePC5QoSFlowItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePC5QoSFlowItemExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSFlowItemExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5QoSParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSParametersExtIEsValue].
type PC5QoSParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PC5QoSParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PC5QoSParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PC5QoSParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePC5QoSParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(v *s10.PC5QoSParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePC5QoSParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}

// pLMNAreaBasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PLMNAreaBasedQMCExtIEsValue].
type PLMNAreaBasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PLMNAreaBasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PLMNAreaBasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePLMNAreaBasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s10.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePLMNAreaBasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s10.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}

// pSCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PSCellInformationExtIEsValue].
type PSCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PSCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PSCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PSCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePSCellInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PSCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePSCellInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// pagingAttemptInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PagingAttemptInformationExtIEsValue].
type PagingAttemptInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.PagingAttemptInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.PagingAttemptInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PagingAttemptInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePagingAttemptInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PagingAttemptInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePagingAttemptInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s10.PagingEDRXInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgePagingEDRXInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(v *s10.PagingEDRXInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgePagingEDRXInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s10.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDeactivateTraceIEValueCaptureS1APERABIEContainerList(v *s08.DeactivateTraceIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APERABIEContainerList(v *s08.DeactivateTraceIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDeactivateTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventTriggerExtIEValueCaptureS1APERABIEContainerList(v *s09.EventTriggerExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APERABIEContainerList(v *s09.EventTriggerExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APERABIEContainerList(v *s09.HandoverSuccessIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverSuccessIEValueCompareS1APERABIEContainerList(v *s09.HandoverSuccessIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverSuccessIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APERABIEContainerList(v *s10.MMECPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APERABIEContainerList(v *s10.MMECPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APERABIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APERABIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APERABIEContainerList(v *s10.NASDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APERABIEContainerList(v *s10.NASDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainer(v *s09.EventTriggerExtIEContainer, s *aper.SemanticCapture) {
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
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainer(v *s09.EventTriggerExtIEContainer, s *aper.SemanticComparison) {
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
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainer(v *s10.MeasurementThresholdL1LoggedMDTExtIEContainer, s *aper.SemanticCapture) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainer(v *s10.MeasurementThresholdL1LoggedMDTExtIEContainer, s *aper.SemanticComparison) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDeactivateTraceIEValueCaptureS1APProtocolErrorIEContainerList(v *s08.DeactivateTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolErrorIEContainerList(v *s08.DeactivateTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDeactivateTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s09.EventTriggerExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolErrorIEContainerList(v *s09.EventTriggerExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolErrorIEContainerList(v *s09.HandoverSuccessIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolErrorIEContainerList(v *s09.HandoverSuccessIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverSuccessIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s10.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolErrorIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s10.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainerList(v *s08.DeactivateTraceIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainerList(v *s08.DeactivateTraceIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDeactivateTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainerList(v *s09.EventTriggerExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainerList(v *s09.EventTriggerExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainerList(v *s09.HandoverSuccessIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverSuccessIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainerList(v *s09.HandoverSuccessIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverSuccessIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(v *s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(v *s10.MMECPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainerList(v *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(v *s10.NASDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(v *s10.NASDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIESingleContainer(v *s08.DeactivateTraceIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIESingleContainer(v *s08.DeactivateTraceIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s08.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s08.DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIESingleContainer(v *s09.HandoverSuccessIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolIESingleContainer(v *s09.HandoverSuccessIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s10.MMECPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(v *s10.MMECPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s10.NASDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(v *s10.NASDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MarshalAPERBluetoothMeasConfigNameListTo appends a BluetoothMeasConfigNameList list to bb.
func BridgeMarshalAPERBluetoothMeasConfigNameListTo(list s00.BluetoothMeasConfigNameList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERBluetoothMeasConfigNameListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 248, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERBPLMNsTo appends a BPLMNs list to bb.
func BridgeMarshalAPERBPLMNsTo(list s00.BPLMNs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERBPLMNsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEREmergencyAreaIDListTo appends a EmergencyAreaIDList list to bb.
func BridgeMarshalAPEREmergencyAreaIDListTo(list s00.EmergencyAreaIDList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPEREmergencyAreaIDListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEREmergencyAreaIDListForRestartTo appends a EmergencyAreaIDListForRestart list to bb.
func BridgeMarshalAPEREmergencyAreaIDListForRestartTo(list s00.EmergencyAreaIDListForRestart, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPEREmergencyAreaIDListForRestartListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERENBX2TLAsTo appends a ENBX2TLAs list to bb.
func BridgeMarshalAPERENBX2TLAsTo(list s00.ENBX2TLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERENBX2TLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeBitStringAlignedExt(bb, elem.Bytes, elem.BitLength, 1, 160, true, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPEREPLMNsTo appends a EPLMNs list to bb.
func BridgeMarshalAPEREPLMNsTo(list s00.EPLMNs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPEREPLMNsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERForbiddenTACsTo appends a ForbiddenTACs list to bb.
func BridgeMarshalAPERForbiddenTACsTo(list s00.ForbiddenTACs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERForbiddenTACsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERForbiddenLACsTo appends a ForbiddenLACs list to bb.
func BridgeMarshalAPERForbiddenLACsTo(list s00.ForbiddenLACs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERForbiddenLACsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMDTPLMNListTo appends a MDTPLMNList list to bb.
func BridgeMarshalAPERMDTPLMNListTo(list s00.MDTPLMNList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERMDTPLMNListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPLMNListforQMCTo appends a PLMNListforQMC list to bb.
func BridgeMarshalAPERPLMNListforQMCTo(list s00.PLMNListforQMC, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERPLMNListforQMCListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERServedGroupIDsTo appends a ServedGroupIDs list to bb.
func BridgeMarshalAPERServedGroupIDsTo(list s00.ServedGroupIDs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERServedGroupIDsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERServedMMECsTo appends a ServedMMECs list to bb.
func BridgeMarshalAPERServedMMECsTo(list s00.ServedMMECs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERServedMMECsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 1, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERServedPLMNsTo appends a ServedPLMNs list to bb.
func BridgeMarshalAPERServedPLMNsTo(list s00.ServedPLMNs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERServedPLMNsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTACListInLTENTNTo appends a TACListInLTENTN list to bb.
func BridgeMarshalAPERTACListInLTENTNTo(list s00.TACListInLTENTN, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERTACListInLTENTNListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 12, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAListforMDTTo appends a TAListforMDT list to bb.
func BridgeMarshalAPERTAListforMDTTo(list s00.TAListforMDT, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERTAListforMDTListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAListforQMCTo appends a TAListforQMC list to bb.
func BridgeMarshalAPERTAListforQMCTo(list s00.TAListforQMC, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERTAListforQMCListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERWLANMeasConfigNameListTo appends a WLANMeasConfigNameList list to bb.
func BridgeMarshalAPERWLANMeasConfigNameListTo(list s00.WLANMeasConfigNameList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERWLANMeasConfigNameListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 32, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERENBX2GTPTLAsTo appends a ENBX2GTPTLAs list to bb.
func BridgeMarshalAPERENBX2GTPTLAsTo(list s00.ENBX2GTPTLAs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERENBX2GTPTLAsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeBitStringAlignedExt(bb, elem.Bytes, elem.BitLength, 1, 160, true, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERENBIndirectX2TransportLayerAddressesTo appends a ENBIndirectX2TransportLayerAddresses list to bb.
func BridgeMarshalAPERENBIndirectX2TransportLayerAddressesTo(list s00.ENBIndirectX2TransportLayerAddresses, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s00.BridgeAsn1cAPERENBIndirectX2TransportLayerAddressesListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeBitStringAlignedExt(bb, elem.Bytes, elem.BitLength, 1, 160, true, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

var BridgeKnownS1APIEIDs = map[s00.ProtocolIEID]struct{}{
	0:   {},
	1:   {},
	2:   {},
	4:   {},
	8:   {},
	12:  {},
	13:  {},
	14:  {},
	15:  {},
	16:  {},
	17:  {},
	18:  {},
	19:  {},
	20:  {},
	21:  {},
	22:  {},
	23:  {},
	24:  {},
	25:  {},
	26:  {},
	27:  {},
	28:  {},
	29:  {},
	30:  {},
	31:  {},
	32:  {},
	33:  {},
	34:  {},
	35:  {},
	36:  {},
	37:  {},
	39:  {},
	40:  {},
	41:  {},
	43:  {},
	44:  {},
	46:  {},
	47:  {},
	48:  {},
	50:  {},
	51:  {},
	52:  {},
	53:  {},
	58:  {},
	59:  {},
	60:  {},
	61:  {},
	64:  {},
	65:  {},
	66:  {},
	67:  {},
	69:  {},
	70:  {},
	71:  {},
	72:  {},
	73:  {},
	74:  {},
	75:  {},
	78:  {},
	79:  {},
	80:  {},
	83:  {},
	84:  {},
	86:  {},
	87:  {},
	88:  {},
	89:  {},
	90:  {},
	91:  {},
	92:  {},
	93:  {},
	94:  {},
	95:  {},
	96:  {},
	97:  {},
	98:  {},
	99:  {},
	100: {},
	101: {},
	102: {},
	104: {},
	105: {},
	106: {},
	107: {},
	108: {},
	109: {},
	110: {},
	111: {},
	112: {},
	113: {},
	114: {},
	115: {},
	116: {},
	117: {},
	118: {},
	119: {},
	120: {},
	121: {},
	122: {},
	123: {},
	124: {},
	125: {},
	127: {},
	128: {},
	129: {},
	130: {},
	131: {},
	132: {},
	133: {},
	134: {},
	135: {},
	136: {},
	137: {},
	138: {},
	139: {},
	140: {},
	141: {},
	142: {},
	143: {},
	144: {},
	145: {},
	146: {},
	147: {},
	148: {},
	149: {},
	150: {},
	151: {},
	152: {},
	153: {},
	154: {},
	155: {},
	156: {},
	157: {},
	158: {},
	159: {},
	160: {},
	161: {},
	162: {},
	163: {},
	164: {},
	165: {},
	166: {},
	167: {},
	168: {},
	169: {},
	170: {},
	171: {},
	172: {},
	173: {},
	174: {},
	175: {},
	176: {},
	177: {},
	178: {},
	179: {},
	180: {},
	181: {},
	182: {},
	183: {},
	184: {},
	185: {},
	186: {},
	187: {},
	188: {},
	189: {},
	190: {},
	191: {},
	192: {},
	193: {},
	194: {},
	195: {},
	196: {},
	197: {},
	198: {},
	199: {},
	200: {},
	201: {},
	202: {},
	203: {},
	204: {},
	205: {},
	206: {},
	207: {},
	208: {},
	209: {},
	210: {},
	211: {},
	212: {},
	213: {},
	214: {},
	215: {},
	216: {},
	217: {},
	218: {},
	219: {},
	220: {},
	221: {},
	222: {},
	223: {},
	224: {},
	225: {},
	226: {},
	227: {},
	228: {},
	230: {},
	231: {},
	232: {},
	233: {},
	234: {},
	235: {},
	236: {},
	237: {},
	238: {},
	239: {},
	240: {},
	241: {},
	242: {},
	243: {},
	244: {},
	245: {},
	246: {},
	247: {},
	248: {},
	249: {},
	250: {},
	251: {},
	252: {},
	253: {},
	254: {},
	255: {},
	256: {},
	257: {},
	258: {},
	259: {},
	260: {},
	261: {},
	262: {},
	263: {},
	264: {},
	265: {},
	266: {},
	267: {},
	268: {},
	269: {},
	270: {},
	271: {},
	272: {},
	273: {},
	274: {},
	275: {},
	276: {},
	277: {},
	278: {},
	280: {},
	281: {},
	282: {},
	283: {},
	284: {},
	285: {},
	286: {},
	287: {},
	288: {},
	290: {},
	291: {},
	292: {},
	293: {},
	294: {},
	295: {},
	296: {},
	297: {},
	298: {},
	299: {},
	300: {},
	301: {},
	302: {},
	303: {},
	304: {},
	305: {},
	306: {},
	307: {},
	308: {},
	309: {},
	310: {},
	311: {},
	312: {},
	313: {},
	314: {},
	315: {},
	316: {},
	317: {},
	318: {},
	319: {},
	320: {},
	321: {},
	322: {},
	323: {},
	324: {},
	325: {},
	326: {},
	327: {},
	328: {},
	329: {},
	330: {},
	331: {},
	332: {},
	334: {},
	335: {},
	336: {},
	337: {},
	339: {},
	340: {},
	341: {},
	342: {},
	343: {},
	344: {},
	345: {},
	346: {},
	347: {},
	348: {},
	349: {},
	350: {},
	351: {},
	352: {},
	353: {},
	354: {},
	355: {},
	356: {},
}
