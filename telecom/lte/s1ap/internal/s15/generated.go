// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s15 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s15

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.AdditionalGUTIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.AdditionalGUTIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.AllocationAndRetentionPriorityExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.AllocationAndRetentionPriorityExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.AssistanceDataForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.AssistanceDataForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.BluetoothMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.BluetoothMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCGIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CGIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCGIExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCGIExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CGIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCGIExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CNTypeRestrictionsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CNTypeRestrictionsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.COUNTValueExtendedExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.COUNTValueExtendedExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.COUNTvalueExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.COUNTvalueExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CSGIdListItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CSGIdListItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CSGMembershipInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CSGMembershipInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CancelledCellinEAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CancelledCellinEAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CancelledCellinTAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CancelledCellinTAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CellBasedMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CellBasedMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s08.CellBasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s08.CellBasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CellIDBroadcastItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CellIDBroadcastItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CellIDCancelledItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CellIDCancelledItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CellTypeExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CellTypeExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CompletedCellinEAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CompletedCellinEAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CompletedCellinTAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CompletedCellinTAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ConnectedengNBItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ConnectedengNBItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ContextatSourceExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ContextatSourceExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CriticalityDiagnosticsExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.DAPSRequestInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.DAPSRequestInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.DAPSResponseInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.DAPSResponseInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.DAPSResponseInfoItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.DAPSResponseInfoItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.DLCPSecurityInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.DLCPSecurityInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainer(v *s09.DeactivateTraceIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainer(v *s09.DeactivateTraceIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s09.DownlinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s09.DownlinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENBX2ExtTLAExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENBX2ExtTLAExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENDCSONConfigurationTransferExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENDCSONConfigurationTransferExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENDCSONeNBIdentificationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENDCSONeNBIdentificationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENDCSONengNBIdentificationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENDCSONengNBIdentificationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionContainer(v *s09.ENDCTransferTypeReplyExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionContainer(v *s09.ENDCTransferTypeReplyExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ENDCTransferTypeRequestExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ENDCTransferTypeRequestExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABAdmittedItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABAdmittedItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABDataForwardingItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABDataForwardingItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABQoSParametersExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABQoSParametersExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABModifyItemBearerModConfExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABModifyItemBearerModConfExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABModifyItemBearerModResExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABModifyItemBearerModResExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABSecurityResultItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABSecurityResultItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABSetupItemBearerSUResExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABSetupItemBearerSUResExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABSetupItemCtxtSUResExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABSetupItemCtxtSUResExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABToBeSwitchedULItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABToBeSwitchedULItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABToBeUpdatedItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABToBeUpdatedItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ERABUsageReportItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ERABUsageReportItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.EUTRANCGIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.EUTRANCGIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.EventL1LoggedMDTConfigExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.EventL1LoggedMDTConfigExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(v *s10.EventTriggerExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(v *s10.EventTriggerExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ExpectedUEActivityBehaviourExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ExpectedUEActivityBehaviourExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ExpectedUEBehaviourExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ExpectedUEBehaviourExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.FiveGSTAIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.FiveGSTAIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ForbiddenLAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ForbiddenLAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s10.ForbiddenTAsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s10.ForbiddenTAsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GBRQosInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GBRQosInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GERANCellIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GERANCellIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGNBExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GNBExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGNBExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GNBExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GUMMEIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GUMMEIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GlobalENBIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GlobalENBIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GlobalEnGNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GlobalEnGNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.GlobalGNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.GlobalGNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainer(v *s11.HandoverSuccessIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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

// WUSAssistanceInformationExtIEsExtContainer is ProtocolExtensionContainer {{WUS-Assistance-Information-ExtIEs}} of TS 36.413: a list of WUSAssistanceInformationExtIEsExtField values.
type WUSAssistanceInformationExtIEsExtContainer []s14.WUSAssistanceInformationExtIEsExtField

// DeactivateTraceIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{DeactivateTraceIEs}} codec of TS 36.413.
func DeactivateTraceIEValueERABIEContainerListCodec(table s00.DeactivateTraceIEValueIETable) s09.DeactivateTraceIEValueERABIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DeactivateTraceIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DeactivateTraceIEValueERABIEContainerListValueCodec {
		sealed := s09.DeactivateTraceIEValueERABIEContainerListValueCodec{}
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "DeactivateTraceIEValueERABIEContainerList"
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DeactivateTraceIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DeactivateTraceIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DeactivateTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DeactivateTraceIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DeactivateTraceIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s09.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DeactivateTraceIEValueERABIEContainerList, options aper.DecodeState) (s09.DeactivateTraceIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DeactivateTraceIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDeactivateTraceIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{DownlinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList"
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{DownlinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList"
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EventTriggerExtIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{EventTrigger-ExtIEs}} codec of TS 36.413.
func EventTriggerExtIEValueERABIEContainerListCodec(table s00.EventTriggerExtIEValueIETable) s10.EventTriggerExtIEValueERABIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.EventTriggerExtIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s10.EventTriggerExtIEValueERABIEContainerListValueCodec {
		sealed := s10.EventTriggerExtIEValueERABIEContainerListValueCodec{}
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "EventTriggerExtIEValueERABIEContainerList"
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventTriggerExtIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EventTriggerExtIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EventTriggerExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventTriggerExtIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.EventTriggerExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s10.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.EventTriggerExtIEValueERABIEContainerList, options aper.DecodeState) (s10.EventTriggerExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.EventTriggerExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventTriggerExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// AdditionalGUTIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Additional-GUTI-ExtIEs}} codec of TS 36.413.
func AdditionalGUTIExtIEsValueExtensionFieldTableCodec(table s00.AdditionalGUTIExtIEsValueExtensionTable) s08.AdditionalGUTIExtIEsExtFieldValueCodec {
	if !*s00.BridgeAdditionalGUTIExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AdditionalGUTIExtIEsExtFieldValueCodec{}
	}
	return func() s08.AdditionalGUTIExtIEsExtFieldValueCodec {
		sealed := s08.AdditionalGUTIExtIEsExtFieldValueCodec{}
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldPath(&sealed) = "AdditionalGUTIExtIEsExtField"
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AdditionalGUTIExtIEsExtField, error) {
			var field s08.AdditionalGUTIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeAdditionalGUTIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "AdditionalGUTIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "AdditionalGUTIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "AdditionalGUTIExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.AdditionalGUTIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeAdditionalGUTIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.AdditionalGUTIExtIEsExtField, options aper.DecodeState) (s08.AdditionalGUTIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.AdditionalGUTIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAdditionalGUTIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// AllocationAndRetentionPriorityExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{AllocationAndRetentionPriority-ExtIEs}} codec of TS 36.413.
func AllocationAndRetentionPriorityExtIEsValueExtensionFieldTableCodec(table s00.AllocationAndRetentionPriorityExtIEsValueExtensionTable) s08.AllocationAndRetentionPriorityExtIEsExtFieldValueCodec {
	if !*s00.BridgeAllocationAndRetentionPriorityExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AllocationAndRetentionPriorityExtIEsExtFieldValueCodec{}
	}
	return func() s08.AllocationAndRetentionPriorityExtIEsExtFieldValueCodec {
		sealed := s08.AllocationAndRetentionPriorityExtIEsExtFieldValueCodec{}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldPath(&sealed) = "AllocationAndRetentionPriorityExtIEsExtField"
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AllocationAndRetentionPriorityExtIEsExtField, error) {
			var field s08.AllocationAndRetentionPriorityExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "AllocationAndRetentionPriorityExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "AllocationAndRetentionPriorityExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "AllocationAndRetentionPriorityExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.AllocationAndRetentionPriorityExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.AllocationAndRetentionPriorityExtIEsExtField, options aper.DecodeState) (s08.AllocationAndRetentionPriorityExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.AllocationAndRetentionPriorityExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// AssistanceDataForPagingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{AssistanceDataForPaging-ExtIEs}} codec of TS 36.413.
func AssistanceDataForPagingExtIEsValueExtensionFieldTableCodec(table s00.AssistanceDataForPagingExtIEsValueExtensionTable) s08.AssistanceDataForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeAssistanceDataForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AssistanceDataForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s08.AssistanceDataForPagingExtIEsExtFieldValueCodec {
		sealed := s08.AssistanceDataForPagingExtIEsExtFieldValueCodec{}
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldPath(&sealed) = "AssistanceDataForPagingExtIEsExtField"
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AssistanceDataForPagingExtIEsExtField, error) {
			var field s08.AssistanceDataForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeAssistanceDataForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "AssistanceDataForPagingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "AssistanceDataForPagingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "AssistanceDataForPagingExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.AssistanceDataForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeAssistanceDataForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.AssistanceDataForPagingExtIEsExtField, options aper.DecodeState) (s08.AssistanceDataForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.AssistanceDataForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// AssistanceDataForRecommendedCellsExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{AssistanceDataForRecommendedCells-ExtIEs}} codec of TS 36.413.
func AssistanceDataForRecommendedCellsExtIEsValueExtensionFieldTableCodec(table s00.AssistanceDataForRecommendedCellsExtIEsValueExtensionTable) s08.AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec {
	if !*s00.BridgeAssistanceDataForRecommendedCellsExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec{}
	}
	return func() s08.AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec {
		sealed := s08.AssistanceDataForRecommendedCellsExtIEsExtFieldValueCodec{}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldPath(&sealed) = "AssistanceDataForRecommendedCellsExtIEsExtField"
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AssistanceDataForRecommendedCellsExtIEsExtField, error) {
			var field s08.AssistanceDataForRecommendedCellsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCellsExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "AssistanceDataForRecommendedCellsExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCellsExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.AssistanceDataForRecommendedCellsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.AssistanceDataForRecommendedCellsExtIEsExtField, options aper.DecodeState) (s08.AssistanceDataForRecommendedCellsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.AssistanceDataForRecommendedCellsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Bearers-SubjectToDLDiscarding-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemExtIEsValueExtensionFieldTableCodec(table s00.BearersSubjectToDLDiscardingItemExtIEsValueExtensionTable) s08.BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec {
		sealed := s08.BearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodec{}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemExtIEsExtField"
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BearersSubjectToDLDiscardingItemExtIEsExtField, error) {
			var field s08.BearersSubjectToDLDiscardingItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.BearersSubjectToDLDiscardingItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.BearersSubjectToDLDiscardingItemExtIEsExtField, options aper.DecodeState) (s08.BearersSubjectToDLDiscardingItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.BearersSubjectToDLDiscardingItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionFieldTableCodec(table s00.BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTable) s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec {
		sealed := s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodec{}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemExtIEsExtField"
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, error) {
			var field s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, options aper.DecodeState) (s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BluetoothMeasurementConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{BluetoothMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func BluetoothMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.BluetoothMeasurementConfigurationExtIEsValueExtensionTable) s08.BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeBluetoothMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s08.BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s08.BluetoothMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "BluetoothMeasurementConfigurationExtIEsExtField"
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BluetoothMeasurementConfigurationExtIEsExtField, error) {
			var field s08.BluetoothMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BluetoothMeasurementConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BluetoothMeasurementConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BluetoothMeasurementConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.BluetoothMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.BluetoothMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s08.BluetoothMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.BluetoothMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CGIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CGI-ExtIEs}} codec of TS 36.413.
func CGIExtIEsValueExtensionFieldTableCodec(table s00.CGIExtIEsValueExtensionTable) s08.CGIExtIEsExtFieldValueCodec {
	if !*s00.BridgeCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CGIExtIEsExtFieldValueCodec{}
	}
	return func() s08.CGIExtIEsExtFieldValueCodec {
		sealed := s08.CGIExtIEsExtFieldValueCodec{}
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldPath(&sealed) = "CGIExtIEsExtField"
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CGIExtIEsExtField, error) {
			var field s08.CGIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CGIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CGIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CGIExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CGIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CGIExtIEsExtField, options aper.DecodeState) (s08.CGIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCGIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CGIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCGIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCGIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CNTypeRestrictionsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CNTypeRestrictions-Item-ExtIEs}} codec of TS 36.413.
func CNTypeRestrictionsItemExtIEsValueExtensionFieldTableCodec(table s00.CNTypeRestrictionsItemExtIEsValueExtensionTable) s08.CNTypeRestrictionsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCNTypeRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CNTypeRestrictionsItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.CNTypeRestrictionsItemExtIEsExtFieldValueCodec {
		sealed := s08.CNTypeRestrictionsItemExtIEsExtFieldValueCodec{}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CNTypeRestrictionsItemExtIEsExtField"
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CNTypeRestrictionsItemExtIEsExtField, error) {
			var field s08.CNTypeRestrictionsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CNTypeRestrictionsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CNTypeRestrictionsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CNTypeRestrictionsItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CNTypeRestrictionsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CNTypeRestrictionsItemExtIEsExtField, options aper.DecodeState) (s08.CNTypeRestrictionsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CNTypeRestrictionsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// COUNTValueExtendedExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{COUNTValueExtended-ExtIEs}} codec of TS 36.413.
func COUNTValueExtendedExtIEsValueExtensionFieldTableCodec(table s00.COUNTValueExtendedExtIEsValueExtensionTable) s08.COUNTValueExtendedExtIEsExtFieldValueCodec {
	if !*s00.BridgeCOUNTValueExtendedExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTValueExtendedExtIEsExtFieldValueCodec{}
	}
	return func() s08.COUNTValueExtendedExtIEsExtFieldValueCodec {
		sealed := s08.COUNTValueExtendedExtIEsExtFieldValueCodec{}
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldPath(&sealed) = "COUNTValueExtendedExtIEsExtField"
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTValueExtendedExtIEsExtField, error) {
			var field s08.COUNTValueExtendedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTValueExtendedExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTValueExtendedExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTValueExtendedExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.COUNTValueExtendedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.COUNTValueExtendedExtIEsExtField, options aper.DecodeState) (s08.COUNTValueExtendedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.COUNTValueExtendedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// COUNTvalueExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{COUNTvalue-ExtIEs}} codec of TS 36.413.
func COUNTvalueExtIEsValueExtensionFieldTableCodec(table s00.COUNTvalueExtIEsValueExtensionTable) s08.COUNTvalueExtIEsExtFieldValueCodec {
	if !*s00.BridgeCOUNTvalueExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTvalueExtIEsExtFieldValueCodec{}
	}
	return func() s08.COUNTvalueExtIEsExtFieldValueCodec {
		sealed := s08.COUNTvalueExtIEsExtFieldValueCodec{}
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldPath(&sealed) = "COUNTvalueExtIEsExtField"
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTvalueExtIEsExtField, error) {
			var field s08.COUNTvalueExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTvalueExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTvalueExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTvalueExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.COUNTvalueExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.COUNTvalueExtIEsExtField, options aper.DecodeState) (s08.COUNTvalueExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.COUNTvalueExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTvalueExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// COUNTvaluePDCPSNlength18ExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{COUNTvaluePDCP-SNlength18-ExtIEs}} codec of TS 36.413.
func COUNTvaluePDCPSNlength18ExtIEsValueExtensionFieldTableCodec(table s00.COUNTvaluePDCPSNlength18ExtIEsValueExtensionTable) s08.COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec {
	if !*s00.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec{}
	}
	return func() s08.COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec {
		sealed := s08.COUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodec{}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldPath(&sealed) = "COUNTvaluePDCPSNlength18ExtIEsExtField"
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTvaluePDCPSNlength18ExtIEsExtField, error) {
			var field s08.COUNTvaluePDCPSNlength18ExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18ExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTvaluePDCPSNlength18ExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18ExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.COUNTvaluePDCPSNlength18ExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.COUNTvaluePDCPSNlength18ExtIEsExtField, options aper.DecodeState) (s08.COUNTvaluePDCPSNlength18ExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.COUNTvaluePDCPSNlength18ExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CSGIdListItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CSG-IdList-Item-ExtIEs}} codec of TS 36.413.
func CSGIdListItemExtIEsValueExtensionFieldTableCodec(table s00.CSGIdListItemExtIEsValueExtensionTable) s08.CSGIdListItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCSGIdListItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CSGIdListItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.CSGIdListItemExtIEsExtFieldValueCodec {
		sealed := s08.CSGIdListItemExtIEsExtFieldValueCodec{}
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CSGIdListItemExtIEsExtField"
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CSGIdListItemExtIEsExtField, error) {
			var field s08.CSGIdListItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CSGIdListItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CSGIdListItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CSGIdListItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CSGIdListItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CSGIdListItemExtIEsExtField, options aper.DecodeState) (s08.CSGIdListItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CSGIdListItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCSGIdListItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CSGMembershipInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CSGMembershipInfo-ExtIEs}} codec of TS 36.413.
func CSGMembershipInfoExtIEsValueExtensionFieldTableCodec(table s00.CSGMembershipInfoExtIEsValueExtensionTable) s08.CSGMembershipInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeCSGMembershipInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CSGMembershipInfoExtIEsExtFieldValueCodec{}
	}
	return func() s08.CSGMembershipInfoExtIEsExtFieldValueCodec {
		sealed := s08.CSGMembershipInfoExtIEsExtFieldValueCodec{}
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "CSGMembershipInfoExtIEsExtField"
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CSGMembershipInfoExtIEsExtField, error) {
			var field s08.CSGMembershipInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CSGMembershipInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CSGMembershipInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CSGMembershipInfoExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CSGMembershipInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CSGMembershipInfoExtIEsExtField, options aper.DecodeState) (s08.CSGMembershipInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CSGMembershipInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinEAIItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CancelledCellinEAI-Item-ExtIEs}} codec of TS 36.413.
func CancelledCellinEAIItemExtIEsValueExtensionFieldTableCodec(table s00.CancelledCellinEAIItemExtIEsValueExtensionTable) s08.CancelledCellinEAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCancelledCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CancelledCellinEAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.CancelledCellinEAIItemExtIEsExtFieldValueCodec {
		sealed := s08.CancelledCellinEAIItemExtIEsExtFieldValueCodec{}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CancelledCellinEAIItemExtIEsExtField"
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CancelledCellinEAIItemExtIEsExtField, error) {
			var field s08.CancelledCellinEAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CancelledCellinEAIItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CancelledCellinEAIItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CancelledCellinEAIItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CancelledCellinEAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CancelledCellinEAIItemExtIEsExtField, options aper.DecodeState) (s08.CancelledCellinEAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CancelledCellinEAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinTAIItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CancelledCellinTAI-Item-ExtIEs}} codec of TS 36.413.
func CancelledCellinTAIItemExtIEsValueExtensionFieldTableCodec(table s00.CancelledCellinTAIItemExtIEsValueExtensionTable) s08.CancelledCellinTAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCancelledCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CancelledCellinTAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s08.CancelledCellinTAIItemExtIEsExtFieldValueCodec {
		sealed := s08.CancelledCellinTAIItemExtIEsExtFieldValueCodec{}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CancelledCellinTAIItemExtIEsExtField"
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CancelledCellinTAIItemExtIEsExtField, error) {
			var field s08.CancelledCellinTAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CancelledCellinTAIItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CancelledCellinTAIItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CancelledCellinTAIItemExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CancelledCellinTAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CancelledCellinTAIItemExtIEsExtField, options aper.DecodeState) (s08.CancelledCellinTAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CancelledCellinTAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Cdma2000OneXSRVCCInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Cdma2000OneXSRVCCInfo-ExtIEs}} codec of TS 36.413.
func Cdma2000OneXSRVCCInfoExtIEsValueExtensionFieldTableCodec(table s00.Cdma2000OneXSRVCCInfoExtIEsValueExtensionTable) s08.Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeCdma2000OneXSRVCCInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec{}
	}
	return func() s08.Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec {
		sealed := s08.Cdma2000OneXSRVCCInfoExtIEsExtFieldValueCodec{}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "Cdma2000OneXSRVCCInfoExtIEsExtField"
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.Cdma2000OneXSRVCCInfoExtIEsExtField, error) {
			var field s08.Cdma2000OneXSRVCCInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "Cdma2000OneXSRVCCInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfoExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.Cdma2000OneXSRVCCInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.Cdma2000OneXSRVCCInfoExtIEsExtField, options aper.DecodeState) (s08.Cdma2000OneXSRVCCInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.Cdma2000OneXSRVCCInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellBasedMDTExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellBasedMDT-ExtIEs}} codec of TS 36.413.
func CellBasedMDTExtIEsValueExtensionFieldTableCodec(table s00.CellBasedMDTExtIEsValueExtensionTable) s08.CellBasedMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellBasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CellBasedMDTExtIEsExtFieldValueCodec{}
	}
	return func() s08.CellBasedMDTExtIEsExtFieldValueCodec {
		sealed := s08.CellBasedMDTExtIEsExtFieldValueCodec{}
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellBasedMDTExtIEsExtField"
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CellBasedMDTExtIEsExtField, error) {
			var field s08.CellBasedMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellBasedMDTExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellBasedMDTExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellBasedMDTExtIEsExtField")
			}
			return field, nil
		}
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CellBasedMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CellBasedMDTExtIEsExtField, options aper.DecodeState) (s08.CellBasedMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CellBasedMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCellBasedMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellBasedQMCExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellBasedQMC-ExtIEs}} codec of TS 36.413.
func CellBasedQMCExtIEsValueExtensionFieldTableCodec(table s00.CellBasedQMCExtIEsValueExtensionTable) s09.CellBasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellBasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s09.CellBasedQMCExtIEsExtFieldValueCodec {
		sealed := s09.CellBasedQMCExtIEsExtFieldValueCodec{}
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellBasedQMCExtIEsExtField"
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, error) {
			var field s08.CellBasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellBasedQMCExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellBasedQMCExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellBasedQMCExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s08.CellBasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s08.CellBasedQMCExtIEsExtField, options aper.DecodeState) (s08.CellBasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s08.CellBasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellBasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDBroadcastItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellID-Broadcast-Item-ExtIEs}} codec of TS 36.413.
func CellIDBroadcastItemExtIEsValueExtensionFieldTableCodec(table s00.CellIDBroadcastItemExtIEsValueExtensionTable) s09.CellIDBroadcastItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIDBroadcastItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.CellIDBroadcastItemExtIEsExtFieldValueCodec {
		sealed := s09.CellIDBroadcastItemExtIEsExtFieldValueCodec{}
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellIDBroadcastItemExtIEsExtField"
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIDBroadcastItemExtIEsExtField, error) {
			var field s09.CellIDBroadcastItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIDBroadcastItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIDBroadcastItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIDBroadcastItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CellIDBroadcastItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CellIDBroadcastItemExtIEsExtField, options aper.DecodeState) (s09.CellIDBroadcastItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CellIDBroadcastItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDCancelledItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellID-Cancelled-Item-ExtIEs}} codec of TS 36.413.
func CellIDCancelledItemExtIEsValueExtensionFieldTableCodec(table s00.CellIDCancelledItemExtIEsValueExtensionTable) s09.CellIDCancelledItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIDCancelledItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.CellIDCancelledItemExtIEsExtFieldValueCodec {
		sealed := s09.CellIDCancelledItemExtIEsExtFieldValueCodec{}
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellIDCancelledItemExtIEsExtField"
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIDCancelledItemExtIEsExtField, error) {
			var field s09.CellIDCancelledItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIDCancelledItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIDCancelledItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIDCancelledItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CellIDCancelledItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CellIDCancelledItemExtIEsExtField, options aper.DecodeState) (s09.CellIDCancelledItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CellIDCancelledItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellIdentifierAndCELevelForCECapableUEs-ExtIEs}} codec of TS 36.413.
func CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionFieldTableCodec(table s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable) s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec{}
	}
	return func() s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec {
		sealed := s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodec{}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellIdentifierAndCELevelForCECapableUEsExtIEsExtField"
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, error) {
			var field s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, options aper.DecodeState) (s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellTypeExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CellType-ExtIEs}} codec of TS 36.413.
func CellTypeExtIEsValueExtensionFieldTableCodec(table s00.CellTypeExtIEsValueExtensionTable) s09.CellTypeExtIEsExtFieldValueCodec {
	if !*s00.BridgeCellTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellTypeExtIEsExtFieldValueCodec{}
	}
	return func() s09.CellTypeExtIEsExtFieldValueCodec {
		sealed := s09.CellTypeExtIEsExtFieldValueCodec{}
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldPath(&sealed) = "CellTypeExtIEsExtField"
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellTypeExtIEsExtField, error) {
			var field s09.CellTypeExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellTypeExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTypeExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellTypeExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CellTypeExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CellTypeExtIEsExtField, options aper.DecodeState) (s09.CellTypeExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CellTypeExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellTypeExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinEAIItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CompletedCellinEAI-Item-ExtIEs}} codec of TS 36.413.
func CompletedCellinEAIItemExtIEsValueExtensionFieldTableCodec(table s00.CompletedCellinEAIItemExtIEsValueExtensionTable) s09.CompletedCellinEAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCompletedCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CompletedCellinEAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.CompletedCellinEAIItemExtIEsExtFieldValueCodec {
		sealed := s09.CompletedCellinEAIItemExtIEsExtFieldValueCodec{}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CompletedCellinEAIItemExtIEsExtField"
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CompletedCellinEAIItemExtIEsExtField, error) {
			var field s09.CompletedCellinEAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CompletedCellinEAIItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CompletedCellinEAIItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CompletedCellinEAIItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CompletedCellinEAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CompletedCellinEAIItemExtIEsExtField, options aper.DecodeState) (s09.CompletedCellinEAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CompletedCellinEAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinTAIItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CompletedCellinTAI-Item-ExtIEs}} codec of TS 36.413.
func CompletedCellinTAIItemExtIEsValueExtensionFieldTableCodec(table s00.CompletedCellinTAIItemExtIEsValueExtensionTable) s09.CompletedCellinTAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCompletedCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CompletedCellinTAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.CompletedCellinTAIItemExtIEsExtFieldValueCodec {
		sealed := s09.CompletedCellinTAIItemExtIEsExtFieldValueCodec{}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CompletedCellinTAIItemExtIEsExtField"
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CompletedCellinTAIItemExtIEsExtField, error) {
			var field s09.CompletedCellinTAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CompletedCellinTAIItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CompletedCellinTAIItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CompletedCellinTAIItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CompletedCellinTAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CompletedCellinTAIItemExtIEsExtField, options aper.DecodeState) (s09.CompletedCellinTAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CompletedCellinTAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ConnectedengNBItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ConnectedengNBItem-ExtIEs}} codec of TS 36.413.
func ConnectedengNBItemExtIEsValueExtensionFieldTableCodec(table s00.ConnectedengNBItemExtIEsValueExtensionTable) s09.ConnectedengNBItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeConnectedengNBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ConnectedengNBItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.ConnectedengNBItemExtIEsExtFieldValueCodec {
		sealed := s09.ConnectedengNBItemExtIEsExtFieldValueCodec{}
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ConnectedengNBItemExtIEsExtField"
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ConnectedengNBItemExtIEsExtField, error) {
			var field s09.ConnectedengNBItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ConnectedengNBItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ConnectedengNBItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ConnectedengNBItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ConnectedengNBItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ConnectedengNBItemExtIEsExtField, options aper.DecodeState) (s09.ConnectedengNBItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ConnectedengNBItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeConnectedengNBItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ContextatSourceExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ContextatSource-ExtIEs}} codec of TS 36.413.
func ContextatSourceExtIEsValueExtensionFieldTableCodec(table s00.ContextatSourceExtIEsValueExtensionTable) s09.ContextatSourceExtIEsExtFieldValueCodec {
	if !*s00.BridgeContextatSourceExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ContextatSourceExtIEsExtFieldValueCodec{}
	}
	return func() s09.ContextatSourceExtIEsExtFieldValueCodec {
		sealed := s09.ContextatSourceExtIEsExtFieldValueCodec{}
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldPath(&sealed) = "ContextatSourceExtIEsExtField"
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ContextatSourceExtIEsExtField, error) {
			var field s09.ContextatSourceExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ContextatSourceExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ContextatSourceExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ContextatSourceExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ContextatSourceExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ContextatSourceExtIEsExtField, options aper.DecodeState) (s09.ContextatSourceExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ContextatSourceExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeContextatSourceExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CriticalityDiagnosticsExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CriticalityDiagnostics-ExtIEs}} codec of TS 36.413.
func CriticalityDiagnosticsExtIEsValueExtensionFieldTableCodec(table s00.CriticalityDiagnosticsExtIEsValueExtensionTable) s09.CriticalityDiagnosticsExtIEsExtFieldValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CriticalityDiagnosticsExtIEsExtFieldValueCodec{}
	}
	return func() s09.CriticalityDiagnosticsExtIEsExtFieldValueCodec {
		sealed := s09.CriticalityDiagnosticsExtIEsExtFieldValueCodec{}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsExtIEsExtField"
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnosticsExtIEsExtField, error) {
			var field s09.CriticalityDiagnosticsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CriticalityDiagnosticsExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CriticalityDiagnosticsExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CriticalityDiagnosticsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnosticsExtIEsExtField, options aper.DecodeState) (s09.CriticalityDiagnosticsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnosticsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CriticalityDiagnosticsIEItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{CriticalityDiagnostics-IE-Item-ExtIEs}} codec of TS 36.413.
func CriticalityDiagnosticsIEItemExtIEsValueExtensionFieldTableCodec(table s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable) s09.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsIEItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec {
		sealed := s09.CriticalityDiagnosticsIEItemExtIEsExtFieldValueCodec{}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsIEItemExtIEsExtField"
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnosticsIEItemExtIEsExtField, error) {
			var field s09.CriticalityDiagnosticsIEItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.CriticalityDiagnosticsIEItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnosticsIEItemExtIEsExtField, options aper.DecodeState) (s09.CriticalityDiagnosticsIEItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnosticsIEItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSRequestInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{DAPSRequestInfo-ExtIEs}} codec of TS 36.413.
func DAPSRequestInfoExtIEsValueExtensionFieldTableCodec(table s00.DAPSRequestInfoExtIEsValueExtensionTable) s09.DAPSRequestInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSRequestInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSRequestInfoExtIEsExtFieldValueCodec{}
	}
	return func() s09.DAPSRequestInfoExtIEsExtFieldValueCodec {
		sealed := s09.DAPSRequestInfoExtIEsExtFieldValueCodec{}
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "DAPSRequestInfoExtIEsExtField"
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSRequestInfoExtIEsExtField, error) {
			var field s09.DAPSRequestInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSRequestInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSRequestInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSRequestInfoExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.DAPSRequestInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.DAPSRequestInfoExtIEsExtField, options aper.DecodeState) (s09.DAPSRequestInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.DAPSRequestInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{DAPSResponseInfo-ExtIEs}} codec of TS 36.413.
func DAPSResponseInfoExtIEsValueExtensionFieldTableCodec(table s00.DAPSResponseInfoExtIEsValueExtensionTable) s09.DAPSResponseInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSResponseInfoExtIEsExtFieldValueCodec{}
	}
	return func() s09.DAPSResponseInfoExtIEsExtFieldValueCodec {
		sealed := s09.DAPSResponseInfoExtIEsExtFieldValueCodec{}
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "DAPSResponseInfoExtIEsExtField"
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSResponseInfoExtIEsExtField, error) {
			var field s09.DAPSResponseInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.DAPSResponseInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.DAPSResponseInfoExtIEsExtField, options aper.DecodeState) (s09.DAPSResponseInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.DAPSResponseInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{DAPSResponseInfoItem-ExtIEs}} codec of TS 36.413.
func DAPSResponseInfoItemExtIEsValueExtensionFieldTableCodec(table s00.DAPSResponseInfoItemExtIEsValueExtensionTable) s09.DAPSResponseInfoItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSResponseInfoItemExtIEsExtFieldValueCodec{}
	}
	return func() s09.DAPSResponseInfoItemExtIEsExtFieldValueCodec {
		sealed := s09.DAPSResponseInfoItemExtIEsExtFieldValueCodec{}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "DAPSResponseInfoItemExtIEsExtField"
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSResponseInfoItemExtIEsExtField, error) {
			var field s09.DAPSResponseInfoItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoItemExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.DAPSResponseInfoItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.DAPSResponseInfoItemExtIEsExtField, options aper.DecodeState) (s09.DAPSResponseInfoItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.DAPSResponseInfoItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DLCPSecurityInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{DL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func DLCPSecurityInformationExtIEsValueExtensionFieldTableCodec(table s00.DLCPSecurityInformationExtIEsValueExtensionTable) s09.DLCPSecurityInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeDLCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DLCPSecurityInformationExtIEsExtFieldValueCodec{}
	}
	return func() s09.DLCPSecurityInformationExtIEsExtFieldValueCodec {
		sealed := s09.DLCPSecurityInformationExtIEsExtFieldValueCodec{}
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "DLCPSecurityInformationExtIEsExtField"
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DLCPSecurityInformationExtIEsExtField, error) {
			var field s09.DLCPSecurityInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DLCPSecurityInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DLCPSecurityInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DLCPSecurityInformationExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.DLCPSecurityInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.DLCPSecurityInformationExtIEsExtField, options aper.DecodeState) (s09.DLCPSecurityInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.DLCPSecurityInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ENB-StatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable) s09.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
		sealed := s09.ENBStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENBStatusTransferTransparentContainerExtIEsExtField"
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENBStatusTransferTransparentContainerExtIEsExtField, error) {
			var field s09.ENBStatusTransferTransparentContainerExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainerExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferTransparentContainerExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainerExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENBStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENBStatusTransferTransparentContainerExtIEsExtField, options aper.DecodeState) (s09.ENBStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENBStatusTransferTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBX2ExtTLAExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ENBX2ExtTLA-ExtIEs}} codec of TS 36.413.
func ENBX2ExtTLAExtIEsValueExtensionFieldTableCodec(table s00.ENBX2ExtTLAExtIEsValueExtensionTable) s09.ENBX2ExtTLAExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBX2ExtTLAExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENBX2ExtTLAExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENBX2ExtTLAExtIEsExtFieldValueCodec {
		sealed := s09.ENBX2ExtTLAExtIEsExtFieldValueCodec{}
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENBX2ExtTLAExtIEsExtField"
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENBX2ExtTLAExtIEsExtField, error) {
			var field s09.ENBX2ExtTLAExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBX2ExtTLAExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBX2ExtTLAExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBX2ExtTLAExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENBX2ExtTLAExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENBX2ExtTLAExtIEsExtField, options aper.DecodeState) (s09.ENBX2ExtTLAExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENBX2ExtTLAExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONConfigurationTransferExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EN-DCSONConfigurationTransfer-ExtIEs}} codec of TS 36.413.
func ENDCSONConfigurationTransferExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable) s09.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec {
		sealed := s09.ENDCSONConfigurationTransferExtIEsExtFieldValueCodec{}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENDCSONConfigurationTransferExtIEsExtField"
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONConfigurationTransferExtIEsExtField, error) {
			var field s09.ENDCSONConfigurationTransferExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransferExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONConfigurationTransferExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransferExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENDCSONConfigurationTransferExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONConfigurationTransferExtIEsExtField, options aper.DecodeState) (s09.ENDCSONConfigurationTransferExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONConfigurationTransferExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONeNBIdentificationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EN-DCSONeNBIdentification-ExtIEs}} codec of TS 36.413.
func ENDCSONeNBIdentificationExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable) s09.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONeNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec {
		sealed := s09.ENDCSONeNBIdentificationExtIEsExtFieldValueCodec{}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENDCSONeNBIdentificationExtIEsExtField"
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONeNBIdentificationExtIEsExtField, error) {
			var field s09.ENDCSONeNBIdentificationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONeNBIdentificationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONeNBIdentificationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONeNBIdentificationExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENDCSONeNBIdentificationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONeNBIdentificationExtIEsExtField, options aper.DecodeState) (s09.ENDCSONeNBIdentificationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONeNBIdentificationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONengNBIdentificationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EN-DCSONengNBIdentification-ExtIEs}} codec of TS 36.413.
func ENDCSONengNBIdentificationExtIEsValueExtensionFieldTableCodec(table s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable) s09.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCSONengNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec {
		sealed := s09.ENDCSONengNBIdentificationExtIEsExtFieldValueCodec{}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENDCSONengNBIdentificationExtIEsExtField"
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONengNBIdentificationExtIEsExtField, error) {
			var field s09.ENDCSONengNBIdentificationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONengNBIdentificationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONengNBIdentificationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCSONengNBIdentificationExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENDCSONengNBIdentificationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONengNBIdentificationExtIEsExtField, options aper.DecodeState) (s09.ENDCSONengNBIdentificationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONengNBIdentificationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENDCTransferTypeReplyExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EN-DCTransferTypeReply-ExtIEs}} codec of TS 36.413.
func ENDCTransferTypeReplyExtIEsValueExtensionFieldTableCodec(table s00.ENDCTransferTypeReplyExtIEsValueExtensionTable) s09.ENDCTransferTypeReplyExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCTransferTypeReplyExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCTransferTypeReplyExtIEsExtFieldValueCodec{}
	}
	return func() s09.ENDCTransferTypeReplyExtIEsExtFieldValueCodec {
		sealed := s09.ENDCTransferTypeReplyExtIEsExtFieldValueCodec{}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENDCTransferTypeReplyExtIEsExtField"
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCTransferTypeReplyExtIEsExtField, error) {
			var field s09.ENDCTransferTypeReplyExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCTransferTypeReplyExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeReplyExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCTransferTypeReplyExtIEsExtField")
			}
			return field, nil
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s09.ENDCTransferTypeReplyExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s09.ENDCTransferTypeReplyExtIEsExtField, options aper.DecodeState) (s09.ENDCTransferTypeReplyExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s09.ENDCTransferTypeReplyExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENDCTransferTypeRequestExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EN-DCTransferTypeRequest-ExtIEs}} codec of TS 36.413.
func ENDCTransferTypeRequestExtIEsValueExtensionFieldTableCodec(table s00.ENDCTransferTypeRequestExtIEsValueExtensionTable) s10.ENDCTransferTypeRequestExtIEsExtFieldValueCodec {
	if !*s00.BridgeENDCTransferTypeRequestExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ENDCTransferTypeRequestExtIEsExtFieldValueCodec{}
	}
	return func() s10.ENDCTransferTypeRequestExtIEsExtFieldValueCodec {
		sealed := s10.ENDCTransferTypeRequestExtIEsExtFieldValueCodec{}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldPath(&sealed) = "ENDCTransferTypeRequestExtIEsExtField"
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ENDCTransferTypeRequestExtIEsExtField, error) {
			var field s10.ENDCTransferTypeRequestExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCTransferTypeRequestExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeRequestExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENDCTransferTypeRequestExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ENDCTransferTypeRequestExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ENDCTransferTypeRequestExtIEsExtField, options aper.DecodeState) (s10.ENDCTransferTypeRequestExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ENDCTransferTypeRequestExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABAdmittedItem-ExtIEs}} codec of TS 36.413.
func ERABAdmittedItemExtIEsValueExtensionFieldTableCodec(table s00.ERABAdmittedItemExtIEsValueExtensionTable) s10.ERABAdmittedItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABAdmittedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABAdmittedItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABAdmittedItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABAdmittedItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABAdmittedItemExtIEsExtField"
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABAdmittedItemExtIEsExtField, error) {
			var field s10.ERABAdmittedItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABAdmittedItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABAdmittedItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABAdmittedItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABAdmittedItemExtIEsExtField, options aper.DecodeState) (s10.ERABAdmittedItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABAdmittedItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABAdmittedItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABDataForwardingItem-ExtIEs}} codec of TS 36.413.
func ERABDataForwardingItemExtIEsValueExtensionFieldTableCodec(table s00.ERABDataForwardingItemExtIEsValueExtensionTable) s10.ERABDataForwardingItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABDataForwardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABDataForwardingItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABDataForwardingItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABDataForwardingItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABDataForwardingItemExtIEsExtField"
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABDataForwardingItemExtIEsExtField, error) {
			var field s10.ERABDataForwardingItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABDataForwardingItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABDataForwardingItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABDataForwardingItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABDataForwardingItemExtIEsExtField, options aper.DecodeState) (s10.ERABDataForwardingItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABDataForwardingItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABFailedToResumeItemResumeReq-ExtIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable) s10.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec {
		sealed := s10.ERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodec{}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqExtIEsExtField"
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeReqExtIEsExtField, error) {
			var field s10.ERABFailedToResumeItemResumeReqExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABFailedToResumeItemResumeReqExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToResumeItemResumeReqExtIEsExtField, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeReqExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToResumeItemResumeReqExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABFailedToResumeItemResumeRes-ExtIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable) s10.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec {
		sealed := s10.ERABFailedToResumeItemResumeResExtIEsExtFieldValueCodec{}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResExtIEsExtField"
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeResExtIEsExtField, error) {
			var field s10.ERABFailedToResumeItemResumeResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABFailedToResumeItemResumeResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToResumeItemResumeResExtIEsExtField, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToResumeItemResumeResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToSetupItemHOReqAckExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABFailedToSetupItemHOReqAckExtIEs}} codec of TS 36.413.
func ERABFailedToSetupItemHOReqAckExtIEsValueExtensionFieldTableCodec(table s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable) s10.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec {
		sealed := s10.ERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodec{}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABFailedToSetupItemHOReqAckExtIEsExtField"
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, error) {
			var field s10.ERABFailedToSetupItemHOReqAckExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAckExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToSetupItemHOReqAckExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAckExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, options aper.DecodeState) (s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABItem-ExtIEs}} codec of TS 36.413.
func ERABItemExtIEsValueExtensionFieldTableCodec(table s00.ERABItemExtIEsValueExtensionTable) s10.ERABItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABItemExtIEsExtField"
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABItemExtIEsExtField, error) {
			var field s10.ERABItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABItemExtIEsExtField, options aper.DecodeState) (s10.ERABItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABModifyItemBearerModConfExtIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfExtIEsValueExtensionFieldTableCodec(table s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable) s10.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec {
		sealed := s10.ERABModifyItemBearerModConfExtIEsExtFieldValueCodec{}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfExtIEsExtField"
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABModifyItemBearerModConfExtIEsExtField, error) {
			var field s10.ERABModifyItemBearerModConfExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABModifyItemBearerModConfExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABModifyItemBearerModConfExtIEsExtField, options aper.DecodeState) (s10.ERABModifyItemBearerModConfExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABModifyItemBearerModConfExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABModifyItemBearerModResExtIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResExtIEsValueExtensionFieldTableCodec(table s00.ERABModifyItemBearerModResExtIEsValueExtensionTable) s10.ERABModifyItemBearerModResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABModifyItemBearerModResExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABModifyItemBearerModResExtIEsExtFieldValueCodec {
		sealed := s10.ERABModifyItemBearerModResExtIEsExtFieldValueCodec{}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResExtIEsExtField"
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABModifyItemBearerModResExtIEsExtField, error) {
			var field s10.ERABModifyItemBearerModResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABModifyItemBearerModResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABModifyItemBearerModResExtIEsExtField, options aper.DecodeState) (s10.ERABModifyItemBearerModResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABModifyItemBearerModResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABNotToBeModifiedItemBearerModInd-ExtIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable) s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
		sealed := s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndExtIEsExtField"
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, error) {
			var field s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, options aper.DecodeState) (s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABQoSParametersExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABQoSParameters-ExtIEs}} codec of TS 36.413.
func ERABQoSParametersExtIEsValueExtensionFieldTableCodec(table s00.ERABQoSParametersExtIEsValueExtensionTable) s10.ERABQoSParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABQoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABQoSParametersExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABQoSParametersExtIEsExtFieldValueCodec {
		sealed := s10.ERABQoSParametersExtIEsExtFieldValueCodec{}
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABQoSParametersExtIEsExtField"
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABQoSParametersExtIEsExtField, error) {
			var field s10.ERABQoSParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABQoSParametersExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABQoSParametersExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABQoSParametersExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABQoSParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABQoSParametersExtIEsExtField, options aper.DecodeState) (s10.ERABQoSParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABQoSParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABQoSParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABReleaseItemBearerRelCompExtIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompExtIEsValueExtensionFieldTableCodec(table s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable) s10.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec {
		sealed := s10.ERABReleaseItemBearerRelCompExtIEsExtFieldValueCodec{}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompExtIEsExtField"
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABReleaseItemBearerRelCompExtIEsExtField, error) {
			var field s10.ERABReleaseItemBearerRelCompExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABReleaseItemBearerRelCompExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABReleaseItemBearerRelCompExtIEsExtField, options aper.DecodeState) (s10.ERABReleaseItemBearerRelCompExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABReleaseItemBearerRelCompExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABSecurityResultItem-ExtIEs}} codec of TS 36.413.
func ERABSecurityResultItemExtIEsValueExtensionFieldTableCodec(table s00.ERABSecurityResultItemExtIEsValueExtensionTable) s10.ERABSecurityResultItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSecurityResultItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSecurityResultItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABSecurityResultItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABSecurityResultItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABSecurityResultItemExtIEsExtField"
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSecurityResultItemExtIEsExtField, error) {
			var field s10.ERABSecurityResultItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSecurityResultItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSecurityResultItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABSecurityResultItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABSecurityResultItemExtIEsExtField, options aper.DecodeState) (s10.ERABSecurityResultItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABSecurityResultItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABSetupItemBearerSUResExtIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResExtIEsValueExtensionFieldTableCodec(table s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable) s10.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec {
		sealed := s10.ERABSetupItemBearerSUResExtIEsExtFieldValueCodec{}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResExtIEsExtField"
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSetupItemBearerSUResExtIEsExtField, error) {
			var field s10.ERABSetupItemBearerSUResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABSetupItemBearerSUResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABSetupItemBearerSUResExtIEsExtField, options aper.DecodeState) (s10.ERABSetupItemBearerSUResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABSetupItemBearerSUResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABSetupItemCtxtSUResExtIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResExtIEsValueExtensionFieldTableCodec(table s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable) s10.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec {
		sealed := s10.ERABSetupItemCtxtSUResExtIEsExtFieldValueCodec{}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResExtIEsExtField"
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSetupItemCtxtSUResExtIEsExtField, error) {
			var field s10.ERABSetupItemCtxtSUResExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABSetupItemCtxtSUResExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABSetupItemCtxtSUResExtIEsExtField, options aper.DecodeState) (s10.ERABSetupItemCtxtSUResExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABSetupItemCtxtSUResExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeModifiedItemBearerModInd-ExtIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable) s10.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec {
		sealed := s10.ERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodec{}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndExtIEsExtField"
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, error) {
			var field s10.ERABToBeModifiedItemBearerModIndExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, options aper.DecodeState) (s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeSwitchedULItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeSwitchedULItem-ExtIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable) s10.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABToBeSwitchedULItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemExtIEsExtField"
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeSwitchedULItemExtIEsExtField, error) {
			var field s10.ERABToBeSwitchedULItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABToBeSwitchedULItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeSwitchedULItemExtIEsExtField, options aper.DecodeState) (s10.ERABToBeSwitchedULItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeSwitchedULItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeUpdatedItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABToBeUpdatedItem-ExtIEs}} codec of TS 36.413.
func ERABToBeUpdatedItemExtIEsValueExtensionFieldTableCodec(table s00.ERABToBeUpdatedItemExtIEsValueExtensionTable) s10.ERABToBeUpdatedItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeUpdatedItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABToBeUpdatedItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABToBeUpdatedItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABToBeUpdatedItemExtIEsExtField"
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeUpdatedItemExtIEsExtField, error) {
			var field s10.ERABToBeUpdatedItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeUpdatedItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeUpdatedItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABToBeUpdatedItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABToBeUpdatedItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeUpdatedItemExtIEsExtField, options aper.DecodeState) (s10.ERABToBeUpdatedItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeUpdatedItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{E-RABUsageReportItem-ExtIEs}} codec of TS 36.413.
func ERABUsageReportItemExtIEsValueExtensionFieldTableCodec(table s00.ERABUsageReportItemExtIEsValueExtensionTable) s10.ERABUsageReportItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeERABUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABUsageReportItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ERABUsageReportItemExtIEsExtFieldValueCodec {
		sealed := s10.ERABUsageReportItemExtIEsExtFieldValueCodec{}
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ERABUsageReportItemExtIEsExtField"
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABUsageReportItemExtIEsExtField, error) {
			var field s10.ERABUsageReportItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABUsageReportItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABUsageReportItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ERABUsageReportItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ERABUsageReportItemExtIEsExtField, options aper.DecodeState) (s10.ERABUsageReportItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ERABUsageReportItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABUsageReportItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EUTRANCGIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EUTRAN-CGI-ExtIEs}} codec of TS 36.413.
func EUTRANCGIExtIEsValueExtensionFieldTableCodec(table s00.EUTRANCGIExtIEsValueExtensionTable) s10.EUTRANCGIExtIEsExtFieldValueCodec {
	if !*s00.BridgeEUTRANCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EUTRANCGIExtIEsExtFieldValueCodec{}
	}
	return func() s10.EUTRANCGIExtIEsExtFieldValueCodec {
		sealed := s10.EUTRANCGIExtIEsExtFieldValueCodec{}
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldPath(&sealed) = "EUTRANCGIExtIEsExtField"
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EUTRANCGIExtIEsExtField, error) {
			var field s10.EUTRANCGIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "EUTRANCGIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "EUTRANCGIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "EUTRANCGIExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.EUTRANCGIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.EUTRANCGIExtIEsExtField, options aper.DecodeState) (s10.EUTRANCGIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.EUTRANCGIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEUTRANCGIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDBroadcastItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EmergencyAreaID-Broadcast-Item-ExtIEs}} codec of TS 36.413.
func EmergencyAreaIDBroadcastItemExtIEsValueExtensionFieldTableCodec(table s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable) s10.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeEmergencyAreaIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec {
		sealed := s10.EmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodec{}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "EmergencyAreaIDBroadcastItemExtIEsExtField"
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EmergencyAreaIDBroadcastItemExtIEsExtField, error) {
			var field s10.EmergencyAreaIDBroadcastItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDBroadcastItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.EmergencyAreaIDBroadcastItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.EmergencyAreaIDBroadcastItemExtIEsExtField, options aper.DecodeState) (s10.EmergencyAreaIDBroadcastItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.EmergencyAreaIDBroadcastItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDCancelledItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EmergencyAreaID-Cancelled-Item-ExtIEs}} codec of TS 36.413.
func EmergencyAreaIDCancelledItemExtIEsValueExtensionFieldTableCodec(table s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable) s10.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeEmergencyAreaIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec {
		sealed := s10.EmergencyAreaIDCancelledItemExtIEsExtFieldValueCodec{}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "EmergencyAreaIDCancelledItemExtIEsExtField"
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EmergencyAreaIDCancelledItemExtIEsExtField, error) {
			var field s10.EmergencyAreaIDCancelledItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDCancelledItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.EmergencyAreaIDCancelledItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.EmergencyAreaIDCancelledItemExtIEsExtField, options aper.DecodeState) (s10.EmergencyAreaIDCancelledItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.EmergencyAreaIDCancelledItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EventL1LoggedMDTConfigExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{EventL1LoggedMDTConfig-ExtIEs}} codec of TS 36.413.
func EventL1LoggedMDTConfigExtIEsValueExtensionFieldTableCodec(table s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable) s10.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec {
	if !*s00.BridgeEventL1LoggedMDTConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec{}
	}
	return func() s10.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec {
		sealed := s10.EventL1LoggedMDTConfigExtIEsExtFieldValueCodec{}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldPath(&sealed) = "EventL1LoggedMDTConfigExtIEsExtField"
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventL1LoggedMDTConfigExtIEsExtField, error) {
			var field s10.EventL1LoggedMDTConfigExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "EventL1LoggedMDTConfigExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventL1LoggedMDTConfigExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "EventL1LoggedMDTConfigExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.EventL1LoggedMDTConfigExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.EventL1LoggedMDTConfigExtIEsExtField, options aper.DecodeState) (s10.EventL1LoggedMDTConfigExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.EventL1LoggedMDTConfigExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ExpectedUEActivityBehaviourExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ExpectedUEActivityBehaviour-ExtIEs}} codec of TS 36.413.
func ExpectedUEActivityBehaviourExtIEsValueExtensionFieldTableCodec(table s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable) s10.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec {
	if !*s00.BridgeExpectedUEActivityBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec{}
	}
	return func() s10.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec {
		sealed := s10.ExpectedUEActivityBehaviourExtIEsExtFieldValueCodec{}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldPath(&sealed) = "ExpectedUEActivityBehaviourExtIEsExtField"
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ExpectedUEActivityBehaviourExtIEsExtField, error) {
			var field s10.ExpectedUEActivityBehaviourExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviourExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedUEActivityBehaviourExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviourExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ExpectedUEActivityBehaviourExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ExpectedUEActivityBehaviourExtIEsExtField, options aper.DecodeState) (s10.ExpectedUEActivityBehaviourExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ExpectedUEActivityBehaviourExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ExpectedUEBehaviourExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ExpectedUEBehaviour-ExtIEs}} codec of TS 36.413.
func ExpectedUEBehaviourExtIEsValueExtensionFieldTableCodec(table s00.ExpectedUEBehaviourExtIEsValueExtensionTable) s10.ExpectedUEBehaviourExtIEsExtFieldValueCodec {
	if !*s00.BridgeExpectedUEBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ExpectedUEBehaviourExtIEsExtFieldValueCodec{}
	}
	return func() s10.ExpectedUEBehaviourExtIEsExtFieldValueCodec {
		sealed := s10.ExpectedUEBehaviourExtIEsExtFieldValueCodec{}
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldPath(&sealed) = "ExpectedUEBehaviourExtIEsExtField"
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ExpectedUEBehaviourExtIEsExtField, error) {
			var field s10.ExpectedUEBehaviourExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ExpectedUEBehaviourExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedUEBehaviourExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ExpectedUEBehaviourExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ExpectedUEBehaviourExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ExpectedUEBehaviourExtIEsExtField, options aper.DecodeState) (s10.ExpectedUEBehaviourExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ExpectedUEBehaviourExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FiveGSTAIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{FiveGSTAI-ExtIEs}} codec of TS 36.413.
func FiveGSTAIExtIEsValueExtensionFieldTableCodec(table s00.FiveGSTAIExtIEsValueExtensionTable) s10.FiveGSTAIExtIEsExtFieldValueCodec {
	if !*s00.BridgeFiveGSTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.FiveGSTAIExtIEsExtFieldValueCodec{}
	}
	return func() s10.FiveGSTAIExtIEsExtFieldValueCodec {
		sealed := s10.FiveGSTAIExtIEsExtFieldValueCodec{}
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldPath(&sealed) = "FiveGSTAIExtIEsExtField"
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.FiveGSTAIExtIEsExtField, error) {
			var field s10.FiveGSTAIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "FiveGSTAIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "FiveGSTAIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "FiveGSTAIExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.FiveGSTAIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.FiveGSTAIExtIEsExtField, options aper.DecodeState) (s10.FiveGSTAIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.FiveGSTAIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeFiveGSTAIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenLAsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ForbiddenLAs-Item-ExtIEs}} codec of TS 36.413.
func ForbiddenLAsItemExtIEsValueExtensionFieldTableCodec(table s00.ForbiddenLAsItemExtIEsValueExtensionTable) s10.ForbiddenLAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeForbiddenLAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ForbiddenLAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ForbiddenLAsItemExtIEsExtFieldValueCodec {
		sealed := s10.ForbiddenLAsItemExtIEsExtFieldValueCodec{}
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ForbiddenLAsItemExtIEsExtField"
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ForbiddenLAsItemExtIEsExtField, error) {
			var field s10.ForbiddenLAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ForbiddenLAsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ForbiddenLAsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ForbiddenLAsItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ForbiddenLAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ForbiddenLAsItemExtIEsExtField, options aper.DecodeState) (s10.ForbiddenLAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ForbiddenLAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenTAsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ForbiddenTAs-Item-ExtIEs}} codec of TS 36.413.
func ForbiddenTAsItemExtIEsValueExtensionFieldTableCodec(table s00.ForbiddenTAsItemExtIEsValueExtensionTable) s10.ForbiddenTAsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeForbiddenTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ForbiddenTAsItemExtIEsExtFieldValueCodec{}
	}
	return func() s10.ForbiddenTAsItemExtIEsExtFieldValueCodec {
		sealed := s10.ForbiddenTAsItemExtIEsExtFieldValueCodec{}
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "ForbiddenTAsItemExtIEsExtField"
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ForbiddenTAsItemExtIEsExtField, error) {
			var field s10.ForbiddenTAsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ForbiddenTAsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ForbiddenTAsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ForbiddenTAsItemExtIEsExtField")
			}
			return field, nil
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s10.ForbiddenTAsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s10.ForbiddenTAsItemExtIEsExtField, options aper.DecodeState) (s10.ForbiddenTAsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s10.ForbiddenTAsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GBRQosInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{GBR-QosInformation-ExtIEs}} codec of TS 36.413.
func GBRQosInformationExtIEsValueExtensionFieldTableCodec(table s00.GBRQosInformationExtIEsValueExtensionTable) s11.GBRQosInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeGBRQosInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GBRQosInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.GBRQosInformationExtIEsExtFieldValueCodec {
		sealed := s11.GBRQosInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "GBRQosInformationExtIEsExtField"
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GBRQosInformationExtIEsExtField, error) {
			var field s11.GBRQosInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GBRQosInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GBRQosInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GBRQosInformationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GBRQosInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GBRQosInformationExtIEsExtField, options aper.DecodeState) (s11.GBRQosInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GBRQosInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGBRQosInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GERANCellIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{GERAN-Cell-ID-ExtIEs}} codec of TS 36.413.
func GERANCellIDExtIEsValueExtensionFieldTableCodec(table s00.GERANCellIDExtIEsValueExtensionTable) s11.GERANCellIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGERANCellIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GERANCellIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.GERANCellIDExtIEsExtFieldValueCodec {
		sealed := s11.GERANCellIDExtIEsExtFieldValueCodec{}
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "GERANCellIDExtIEsExtField"
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GERANCellIDExtIEsExtField, error) {
			var field s11.GERANCellIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GERANCellIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GERANCellIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GERANCellIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GERANCellIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GERANCellIDExtIEsExtField, options aper.DecodeState) (s11.GERANCellIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GERANCellIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGERANCellIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GNBExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{GNB-ExtIEs}} codec of TS 36.413.
func GNBExtIEsValueExtensionFieldTableCodec(table s00.GNBExtIEsValueExtensionTable) s11.GNBExtIEsExtFieldValueCodec {
	if !*s00.BridgeGNBExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GNBExtIEsExtFieldValueCodec{}
	}
	return func() s11.GNBExtIEsExtFieldValueCodec {
		sealed := s11.GNBExtIEsExtFieldValueCodec{}
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldPath(&sealed) = "GNBExtIEsExtField"
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GNBExtIEsExtField, error) {
			var field s11.GNBExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GNBExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GNBExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GNBExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GNBExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GNBExtIEsExtField, options aper.DecodeState) (s11.GNBExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGNBExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GNBExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGNBExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGNBExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GUMMEIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{GUMMEI-ExtIEs}} codec of TS 36.413.
func GUMMEIExtIEsValueExtensionFieldTableCodec(table s00.GUMMEIExtIEsValueExtensionTable) s11.GUMMEIExtIEsExtFieldValueCodec {
	if !*s00.BridgeGUMMEIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GUMMEIExtIEsExtFieldValueCodec{}
	}
	return func() s11.GUMMEIExtIEsExtFieldValueCodec {
		sealed := s11.GUMMEIExtIEsExtFieldValueCodec{}
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldPath(&sealed) = "GUMMEIExtIEsExtField"
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GUMMEIExtIEsExtField, error) {
			var field s11.GUMMEIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GUMMEIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GUMMEIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GUMMEIExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GUMMEIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GUMMEIExtIEsExtField, options aper.DecodeState) (s11.GUMMEIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GUMMEIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGUMMEIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GlobalENBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{GlobalENB-ID-ExtIEs}} codec of TS 36.413.
func GlobalENBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalENBIDExtIEsValueExtensionTable) s11.GlobalENBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalENBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalENBIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.GlobalENBIDExtIEsExtFieldValueCodec {
		sealed := s11.GlobalENBIDExtIEsExtFieldValueCodec{}
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "GlobalENBIDExtIEsExtField"
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalENBIDExtIEsExtField, error) {
			var field s11.GlobalENBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalENBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalENBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalENBIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GlobalENBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GlobalENBIDExtIEsExtField, options aper.DecodeState) (s11.GlobalENBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GlobalENBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalENBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GlobalEnGNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Global-en-gNB-ID-ExtIEs}} codec of TS 36.413.
func GlobalEnGNBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalEnGNBIDExtIEsValueExtensionTable) s11.GlobalEnGNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalEnGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalEnGNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.GlobalEnGNBIDExtIEsExtFieldValueCodec {
		sealed := s11.GlobalEnGNBIDExtIEsExtFieldValueCodec{}
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "GlobalEnGNBIDExtIEsExtField"
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalEnGNBIDExtIEsExtField, error) {
			var field s11.GlobalEnGNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalEnGNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalEnGNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalEnGNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GlobalEnGNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GlobalEnGNBIDExtIEsExtField, options aper.DecodeState) (s11.GlobalEnGNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GlobalEnGNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GlobalGNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Global-GNB-ID-ExtIEs}} codec of TS 36.413.
func GlobalGNBIDExtIEsValueExtensionFieldTableCodec(table s00.GlobalGNBIDExtIEsValueExtensionTable) s11.GlobalGNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeGlobalGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalGNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.GlobalGNBIDExtIEsExtFieldValueCodec {
		sealed := s11.GlobalGNBIDExtIEsExtFieldValueCodec{}
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "GlobalGNBIDExtIEsExtField"
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalGNBIDExtIEsExtField, error) {
			var field s11.GlobalGNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalGNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalGNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "GlobalGNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.GlobalGNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.GlobalGNBIDExtIEsExtField, options aper.DecodeState) (s11.GlobalGNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.GlobalGNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalGNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// AdditionalGUTIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Additional-GUTI-ExtIEs}} codec of TS 36.413.
func AdditionalGUTIExtIEsValueExtensionTableCodec(table s00.AdditionalGUTIExtIEsValueExtensionTable, bounds aper.ListBounds) s08.AdditionalGUTIExtIEsExtContainerValueCodec {
	if !*s00.BridgeAdditionalGUTIExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AdditionalGUTIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.AdditionalGUTIExtIEsExtContainerValueCodec {
		sealed := s08.AdditionalGUTIExtIEsExtContainerValueCodec{}
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldPath(&sealed) = "AdditionalGUTIExtIEsExtContainer"
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AdditionalGUTIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.AdditionalGUTIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.AdditionalGUTIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeAdditionalGUTIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "AdditionalGUTIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "AdditionalGUTIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "AdditionalGUTIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.AdditionalGUTIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeAdditionalGUTIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.AdditionalGUTIExtIEsExtContainer, options aper.DecodeState) (s08.AdditionalGUTIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.AdditionalGUTIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAdditionalGUTIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// AllocationAndRetentionPriorityExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{AllocationAndRetentionPriority-ExtIEs}} codec of TS 36.413.
func AllocationAndRetentionPriorityExtIEsValueExtensionTableCodec(table s00.AllocationAndRetentionPriorityExtIEsValueExtensionTable, bounds aper.ListBounds) s08.AllocationAndRetentionPriorityExtIEsExtContainerValueCodec {
	if !*s00.BridgeAllocationAndRetentionPriorityExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AllocationAndRetentionPriorityExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.AllocationAndRetentionPriorityExtIEsExtContainerValueCodec {
		sealed := s08.AllocationAndRetentionPriorityExtIEsExtContainerValueCodec{}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldPath(&sealed) = "AllocationAndRetentionPriorityExtIEsExtContainer"
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AllocationAndRetentionPriorityExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.AllocationAndRetentionPriorityExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.AllocationAndRetentionPriorityExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "AllocationAndRetentionPriorityExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "AllocationAndRetentionPriorityExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "AllocationAndRetentionPriorityExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.AllocationAndRetentionPriorityExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.AllocationAndRetentionPriorityExtIEsExtContainer, options aper.DecodeState) (s08.AllocationAndRetentionPriorityExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.AllocationAndRetentionPriorityExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAllocationAndRetentionPriorityExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// AssistanceDataForPagingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{AssistanceDataForPaging-ExtIEs}} codec of TS 36.413.
func AssistanceDataForPagingExtIEsValueExtensionTableCodec(table s00.AssistanceDataForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s08.AssistanceDataForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeAssistanceDataForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AssistanceDataForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.AssistanceDataForPagingExtIEsExtContainerValueCodec {
		sealed := s08.AssistanceDataForPagingExtIEsExtContainerValueCodec{}
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldPath(&sealed) = "AssistanceDataForPagingExtIEsExtContainer"
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AssistanceDataForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.AssistanceDataForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.AssistanceDataForPagingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeAssistanceDataForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "AssistanceDataForPagingExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "AssistanceDataForPagingExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "AssistanceDataForPagingExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.AssistanceDataForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeAssistanceDataForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.AssistanceDataForPagingExtIEsExtContainer, options aper.DecodeState) (s08.AssistanceDataForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.AssistanceDataForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAssistanceDataForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// AssistanceDataForRecommendedCellsExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{AssistanceDataForRecommendedCells-ExtIEs}} codec of TS 36.413.
func AssistanceDataForRecommendedCellsExtIEsValueExtensionTableCodec(table s00.AssistanceDataForRecommendedCellsExtIEsValueExtensionTable, bounds aper.ListBounds) s08.AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec {
	if !*s00.BridgeAssistanceDataForRecommendedCellsExtIEsValueExtensionTableFieldBound(&table) {
		return s08.AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec {
		sealed := s08.AssistanceDataForRecommendedCellsExtIEsExtContainerValueCodec{}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldPath(&sealed) = "AssistanceDataForRecommendedCellsExtIEsExtContainer"
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.AssistanceDataForRecommendedCellsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.AssistanceDataForRecommendedCellsExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCellsExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "AssistanceDataForRecommendedCellsExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "AssistanceDataForRecommendedCellsExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, options aper.DecodeState) (s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.AssistanceDataForRecommendedCellsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Bearers-SubjectToDLDiscarding-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemExtIEsValueExtensionTableCodec(table s00.BearersSubjectToDLDiscardingItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec {
		sealed := s08.BearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodec{}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemExtIEsExtContainer"
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.BearersSubjectToDLDiscardingItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, options aper.DecodeState) (s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableCodec(table s00.BearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec {
		sealed := s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodec{}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer"
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, options aper.DecodeState) (s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BluetoothMeasurementConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{BluetoothMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func BluetoothMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.BluetoothMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s08.BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeBluetoothMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s08.BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s08.BluetoothMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "BluetoothMeasurementConfigurationExtIEsExtContainer"
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.BluetoothMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.BluetoothMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.BluetoothMeasurementConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BluetoothMeasurementConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BluetoothMeasurementConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BluetoothMeasurementConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.BluetoothMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.BluetoothMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s08.BluetoothMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.BluetoothMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeBluetoothMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CGIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CGI-ExtIEs}} codec of TS 36.413.
func CGIExtIEsValueExtensionTableCodec(table s00.CGIExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CGIExtIEsExtContainerValueCodec {
	if !*s00.BridgeCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CGIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CGIExtIEsExtContainerValueCodec {
		sealed := s08.CGIExtIEsExtContainerValueCodec{}
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldPath(&sealed) = "CGIExtIEsExtContainer"
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CGIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CGIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CGIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CGIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CGIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CGIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CGIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CGIExtIEsExtContainer, options aper.DecodeState) (s08.CGIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CGIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCGIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CNTypeRestrictionsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CNTypeRestrictions-Item-ExtIEs}} codec of TS 36.413.
func CNTypeRestrictionsItemExtIEsValueExtensionTableCodec(table s00.CNTypeRestrictionsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CNTypeRestrictionsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCNTypeRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CNTypeRestrictionsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CNTypeRestrictionsItemExtIEsExtContainerValueCodec {
		sealed := s08.CNTypeRestrictionsItemExtIEsExtContainerValueCodec{}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CNTypeRestrictionsItemExtIEsExtContainer"
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CNTypeRestrictionsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CNTypeRestrictionsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CNTypeRestrictionsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CNTypeRestrictionsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CNTypeRestrictionsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CNTypeRestrictionsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CNTypeRestrictionsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CNTypeRestrictionsItemExtIEsExtContainer, options aper.DecodeState) (s08.CNTypeRestrictionsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CNTypeRestrictionsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCNTypeRestrictionsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// COUNTValueExtendedExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{COUNTValueExtended-ExtIEs}} codec of TS 36.413.
func COUNTValueExtendedExtIEsValueExtensionTableCodec(table s00.COUNTValueExtendedExtIEsValueExtensionTable, bounds aper.ListBounds) s08.COUNTValueExtendedExtIEsExtContainerValueCodec {
	if !*s00.BridgeCOUNTValueExtendedExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTValueExtendedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.COUNTValueExtendedExtIEsExtContainerValueCodec {
		sealed := s08.COUNTValueExtendedExtIEsExtContainerValueCodec{}
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldPath(&sealed) = "COUNTValueExtendedExtIEsExtContainer"
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTValueExtendedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.COUNTValueExtendedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.COUNTValueExtendedExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "COUNTValueExtendedExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTValueExtendedExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "COUNTValueExtendedExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.COUNTValueExtendedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.COUNTValueExtendedExtIEsExtContainer, options aper.DecodeState) (s08.COUNTValueExtendedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.COUNTValueExtendedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTValueExtendedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// COUNTvalueExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{COUNTvalue-ExtIEs}} codec of TS 36.413.
func COUNTvalueExtIEsValueExtensionTableCodec(table s00.COUNTvalueExtIEsValueExtensionTable, bounds aper.ListBounds) s08.COUNTvalueExtIEsExtContainerValueCodec {
	if !*s00.BridgeCOUNTvalueExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTvalueExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.COUNTvalueExtIEsExtContainerValueCodec {
		sealed := s08.COUNTvalueExtIEsExtContainerValueCodec{}
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldPath(&sealed) = "COUNTvalueExtIEsExtContainer"
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTvalueExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.COUNTvalueExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.COUNTvalueExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "COUNTvalueExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTvalueExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "COUNTvalueExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.COUNTvalueExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.COUNTvalueExtIEsExtContainer, options aper.DecodeState) (s08.COUNTvalueExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.COUNTvalueExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTvalueExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// COUNTvaluePDCPSNlength18ExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{COUNTvaluePDCP-SNlength18-ExtIEs}} codec of TS 36.413.
func COUNTvaluePDCPSNlength18ExtIEsValueExtensionTableCodec(table s00.COUNTvaluePDCPSNlength18ExtIEsValueExtensionTable, bounds aper.ListBounds) s08.COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec {
	if !*s00.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueExtensionTableFieldBound(&table) {
		return s08.COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec {
		sealed := s08.COUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodec{}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldPath(&sealed) = "COUNTvaluePDCPSNlength18ExtIEsExtContainer"
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.COUNTvaluePDCPSNlength18ExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18ExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "COUNTvaluePDCPSNlength18ExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18ExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, options aper.DecodeState) (s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CSGIdListItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CSG-IdList-Item-ExtIEs}} codec of TS 36.413.
func CSGIdListItemExtIEsValueExtensionTableCodec(table s00.CSGIdListItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CSGIdListItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCSGIdListItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CSGIdListItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CSGIdListItemExtIEsExtContainerValueCodec {
		sealed := s08.CSGIdListItemExtIEsExtContainerValueCodec{}
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CSGIdListItemExtIEsExtContainer"
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CSGIdListItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CSGIdListItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CSGIdListItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CSGIdListItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CSGIdListItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CSGIdListItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CSGIdListItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CSGIdListItemExtIEsExtContainer, options aper.DecodeState) (s08.CSGIdListItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CSGIdListItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCSGIdListItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CSGMembershipInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CSGMembershipInfo-ExtIEs}} codec of TS 36.413.
func CSGMembershipInfoExtIEsValueExtensionTableCodec(table s00.CSGMembershipInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CSGMembershipInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeCSGMembershipInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CSGMembershipInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CSGMembershipInfoExtIEsExtContainerValueCodec {
		sealed := s08.CSGMembershipInfoExtIEsExtContainerValueCodec{}
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "CSGMembershipInfoExtIEsExtContainer"
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CSGMembershipInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CSGMembershipInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CSGMembershipInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CSGMembershipInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CSGMembershipInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CSGMembershipInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CSGMembershipInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CSGMembershipInfoExtIEsExtContainer, options aper.DecodeState) (s08.CSGMembershipInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CSGMembershipInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCSGMembershipInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinEAIItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CancelledCellinEAI-Item-ExtIEs}} codec of TS 36.413.
func CancelledCellinEAIItemExtIEsValueExtensionTableCodec(table s00.CancelledCellinEAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CancelledCellinEAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCancelledCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CancelledCellinEAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CancelledCellinEAIItemExtIEsExtContainerValueCodec {
		sealed := s08.CancelledCellinEAIItemExtIEsExtContainerValueCodec{}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CancelledCellinEAIItemExtIEsExtContainer"
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CancelledCellinEAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CancelledCellinEAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CancelledCellinEAIItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CancelledCellinEAIItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CancelledCellinEAIItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CancelledCellinEAIItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CancelledCellinEAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CancelledCellinEAIItemExtIEsExtContainer, options aper.DecodeState) (s08.CancelledCellinEAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CancelledCellinEAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCancelledCellinEAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinTAIItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CancelledCellinTAI-Item-ExtIEs}} codec of TS 36.413.
func CancelledCellinTAIItemExtIEsValueExtensionTableCodec(table s00.CancelledCellinTAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CancelledCellinTAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCancelledCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CancelledCellinTAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CancelledCellinTAIItemExtIEsExtContainerValueCodec {
		sealed := s08.CancelledCellinTAIItemExtIEsExtContainerValueCodec{}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CancelledCellinTAIItemExtIEsExtContainer"
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CancelledCellinTAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CancelledCellinTAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CancelledCellinTAIItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CancelledCellinTAIItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CancelledCellinTAIItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CancelledCellinTAIItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CancelledCellinTAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CancelledCellinTAIItemExtIEsExtContainer, options aper.DecodeState) (s08.CancelledCellinTAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CancelledCellinTAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCancelledCellinTAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// Cdma2000OneXSRVCCInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Cdma2000OneXSRVCCInfo-ExtIEs}} codec of TS 36.413.
func Cdma2000OneXSRVCCInfoExtIEsValueExtensionTableCodec(table s00.Cdma2000OneXSRVCCInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s08.Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeCdma2000OneXSRVCCInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s08.Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec {
		sealed := s08.Cdma2000OneXSRVCCInfoExtIEsExtContainerValueCodec{}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "Cdma2000OneXSRVCCInfoExtIEsExtContainer"
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.Cdma2000OneXSRVCCInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "Cdma2000OneXSRVCCInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, options aper.DecodeState) (s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellBasedMDTExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellBasedMDT-ExtIEs}} codec of TS 36.413.
func CellBasedMDTExtIEsValueExtensionTableCodec(table s00.CellBasedMDTExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CellBasedMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellBasedMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CellBasedMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CellBasedMDTExtIEsExtContainerValueCodec {
		sealed := s08.CellBasedMDTExtIEsExtContainerValueCodec{}
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellBasedMDTExtIEsExtContainer"
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CellBasedMDTExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CellBasedMDTExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CellBasedMDTExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellBasedMDTExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellBasedMDTExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellBasedMDTExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CellBasedMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CellBasedMDTExtIEsExtContainer, options aper.DecodeState) (s08.CellBasedMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CellBasedMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCellBasedMDTExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellBasedQMCExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellBasedQMC-ExtIEs}} codec of TS 36.413.
func CellBasedQMCExtIEsValueExtensionTableCodec(table s00.CellBasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s08.CellBasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s08.CellBasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s08.CellBasedQMCExtIEsExtContainerValueCodec {
		sealed := s08.CellBasedQMCExtIEsExtContainerValueCodec{}
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellBasedQMCExtIEsExtContainer"
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.CellBasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s08.CellBasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s08.CellBasedQMCExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellBasedQMCExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellBasedQMCExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellBasedQMCExtIEsExtContainer")
			}
			return fields, nil
		}
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s08.CellBasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s08.CellBasedQMCExtIEsExtContainer, options aper.DecodeState) (s08.CellBasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s08.CellBasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s08.BridgeCellBasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellIDBroadcastItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellID-Broadcast-Item-ExtIEs}} codec of TS 36.413.
func CellIDBroadcastItemExtIEsValueExtensionTableCodec(table s00.CellIDBroadcastItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CellIDBroadcastItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIDBroadcastItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CellIDBroadcastItemExtIEsExtContainerValueCodec {
		sealed := s09.CellIDBroadcastItemExtIEsExtContainerValueCodec{}
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellIDBroadcastItemExtIEsExtContainer"
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIDBroadcastItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CellIDBroadcastItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CellIDBroadcastItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellIDBroadcastItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIDBroadcastItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellIDBroadcastItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CellIDBroadcastItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CellIDBroadcastItemExtIEsExtContainer, options aper.DecodeState) (s09.CellIDBroadcastItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CellIDBroadcastItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellIDCancelledItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellID-Cancelled-Item-ExtIEs}} codec of TS 36.413.
func CellIDCancelledItemExtIEsValueExtensionTableCodec(table s00.CellIDCancelledItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CellIDCancelledItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIDCancelledItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CellIDCancelledItemExtIEsExtContainerValueCodec {
		sealed := s09.CellIDCancelledItemExtIEsExtContainerValueCodec{}
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellIDCancelledItemExtIEsExtContainer"
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIDCancelledItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CellIDCancelledItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CellIDCancelledItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellIDCancelledItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIDCancelledItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellIDCancelledItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CellIDCancelledItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CellIDCancelledItemExtIEsExtContainer, options aper.DecodeState) (s09.CellIDCancelledItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CellIDCancelledItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIDCancelledItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellIdentifierAndCELevelForCECapableUEs-ExtIEs}} codec of TS 36.413.
func CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableCodec(table s00.CellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec {
		sealed := s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodec{}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer"
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, options aper.DecodeState) (s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CellTypeExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CellType-ExtIEs}} codec of TS 36.413.
func CellTypeExtIEsValueExtensionTableCodec(table s00.CellTypeExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CellTypeExtIEsExtContainerValueCodec {
	if !*s00.BridgeCellTypeExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CellTypeExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CellTypeExtIEsExtContainerValueCodec {
		sealed := s09.CellTypeExtIEsExtContainerValueCodec{}
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldPath(&sealed) = "CellTypeExtIEsExtContainer"
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CellTypeExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CellTypeExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CellTypeExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellTypeExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTypeExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellTypeExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CellTypeExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CellTypeExtIEsExtContainer, options aper.DecodeState) (s09.CellTypeExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CellTypeExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCellTypeExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinEAIItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CompletedCellinEAI-Item-ExtIEs}} codec of TS 36.413.
func CompletedCellinEAIItemExtIEsValueExtensionTableCodec(table s00.CompletedCellinEAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CompletedCellinEAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCompletedCellinEAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CompletedCellinEAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CompletedCellinEAIItemExtIEsExtContainerValueCodec {
		sealed := s09.CompletedCellinEAIItemExtIEsExtContainerValueCodec{}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CompletedCellinEAIItemExtIEsExtContainer"
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CompletedCellinEAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CompletedCellinEAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CompletedCellinEAIItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CompletedCellinEAIItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CompletedCellinEAIItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CompletedCellinEAIItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CompletedCellinEAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CompletedCellinEAIItemExtIEsExtContainer, options aper.DecodeState) (s09.CompletedCellinEAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CompletedCellinEAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCompletedCellinEAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinTAIItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CompletedCellinTAI-Item-ExtIEs}} codec of TS 36.413.
func CompletedCellinTAIItemExtIEsValueExtensionTableCodec(table s00.CompletedCellinTAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CompletedCellinTAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCompletedCellinTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CompletedCellinTAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CompletedCellinTAIItemExtIEsExtContainerValueCodec {
		sealed := s09.CompletedCellinTAIItemExtIEsExtContainerValueCodec{}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CompletedCellinTAIItemExtIEsExtContainer"
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CompletedCellinTAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CompletedCellinTAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CompletedCellinTAIItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CompletedCellinTAIItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CompletedCellinTAIItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CompletedCellinTAIItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CompletedCellinTAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CompletedCellinTAIItemExtIEsExtContainer, options aper.DecodeState) (s09.CompletedCellinTAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CompletedCellinTAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCompletedCellinTAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ConnectedengNBItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ConnectedengNBItem-ExtIEs}} codec of TS 36.413.
func ConnectedengNBItemExtIEsValueExtensionTableCodec(table s00.ConnectedengNBItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ConnectedengNBItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeConnectedengNBItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ConnectedengNBItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ConnectedengNBItemExtIEsExtContainerValueCodec {
		sealed := s09.ConnectedengNBItemExtIEsExtContainerValueCodec{}
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ConnectedengNBItemExtIEsExtContainer"
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ConnectedengNBItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ConnectedengNBItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ConnectedengNBItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeConnectedengNBItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ConnectedengNBItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ConnectedengNBItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ConnectedengNBItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ConnectedengNBItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeConnectedengNBItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ConnectedengNBItemExtIEsExtContainer, options aper.DecodeState) (s09.ConnectedengNBItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ConnectedengNBItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeConnectedengNBItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ContextatSourceExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ContextatSource-ExtIEs}} codec of TS 36.413.
func ContextatSourceExtIEsValueExtensionTableCodec(table s00.ContextatSourceExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ContextatSourceExtIEsExtContainerValueCodec {
	if !*s00.BridgeContextatSourceExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ContextatSourceExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ContextatSourceExtIEsExtContainerValueCodec {
		sealed := s09.ContextatSourceExtIEsExtContainerValueCodec{}
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldPath(&sealed) = "ContextatSourceExtIEsExtContainer"
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ContextatSourceExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ContextatSourceExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ContextatSourceExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ContextatSourceExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ContextatSourceExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ContextatSourceExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ContextatSourceExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ContextatSourceExtIEsExtContainer, options aper.DecodeState) (s09.ContextatSourceExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ContextatSourceExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeContextatSourceExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CriticalityDiagnosticsExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CriticalityDiagnostics-ExtIEs}} codec of TS 36.413.
func CriticalityDiagnosticsExtIEsValueExtensionTableCodec(table s00.CriticalityDiagnosticsExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CriticalityDiagnosticsExtIEsExtContainerValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CriticalityDiagnosticsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CriticalityDiagnosticsExtIEsExtContainerValueCodec {
		sealed := s09.CriticalityDiagnosticsExtIEsExtContainerValueCodec{}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsExtIEsExtContainer"
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnosticsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CriticalityDiagnosticsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CriticalityDiagnosticsExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CriticalityDiagnosticsExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CriticalityDiagnosticsExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CriticalityDiagnosticsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnosticsExtIEsExtContainer, options aper.DecodeState) (s09.CriticalityDiagnosticsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnosticsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCriticalityDiagnosticsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// CriticalityDiagnosticsIEItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{CriticalityDiagnostics-IE-Item-ExtIEs}} codec of TS 36.413.
func CriticalityDiagnosticsIEItemExtIEsValueExtensionTableCodec(table s00.CriticalityDiagnosticsIEItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeCriticalityDiagnosticsIEItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec {
		sealed := s09.CriticalityDiagnosticsIEItemExtIEsExtContainerValueCodec{}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsIEItemExtIEsExtContainer"
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.CriticalityDiagnosticsIEItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.CriticalityDiagnosticsIEItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, options aper.DecodeState) (s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DAPSRequestInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{DAPSRequestInfo-ExtIEs}} codec of TS 36.413.
func DAPSRequestInfoExtIEsValueExtensionTableCodec(table s00.DAPSRequestInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s09.DAPSRequestInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSRequestInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSRequestInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DAPSRequestInfoExtIEsExtContainerValueCodec {
		sealed := s09.DAPSRequestInfoExtIEsExtContainerValueCodec{}
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "DAPSRequestInfoExtIEsExtContainer"
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSRequestInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DAPSRequestInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DAPSRequestInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DAPSRequestInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSRequestInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSRequestInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.DAPSRequestInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.DAPSRequestInfoExtIEsExtContainer, options aper.DecodeState) (s09.DAPSRequestInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.DAPSRequestInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSRequestInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{DAPSResponseInfo-ExtIEs}} codec of TS 36.413.
func DAPSResponseInfoExtIEsValueExtensionTableCodec(table s00.DAPSResponseInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s09.DAPSResponseInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSResponseInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DAPSResponseInfoExtIEsExtContainerValueCodec {
		sealed := s09.DAPSResponseInfoExtIEsExtContainerValueCodec{}
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "DAPSResponseInfoExtIEsExtContainer"
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSResponseInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DAPSResponseInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DAPSResponseInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.DAPSResponseInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.DAPSResponseInfoExtIEsExtContainer, options aper.DecodeState) (s09.DAPSResponseInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.DAPSResponseInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSResponseInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{DAPSResponseInfoItem-ExtIEs}} codec of TS 36.413.
func DAPSResponseInfoItemExtIEsValueExtensionTableCodec(table s00.DAPSResponseInfoItemExtIEsValueExtensionTable, bounds aper.ListBounds) s09.DAPSResponseInfoItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoItemExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DAPSResponseInfoItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DAPSResponseInfoItemExtIEsExtContainerValueCodec {
		sealed := s09.DAPSResponseInfoItemExtIEsExtContainerValueCodec{}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "DAPSResponseInfoItemExtIEsExtContainer"
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DAPSResponseInfoItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DAPSResponseInfoItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DAPSResponseInfoItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.DAPSResponseInfoItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.DAPSResponseInfoItemExtIEsExtContainer, options aper.DecodeState) (s09.DAPSResponseInfoItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.DAPSResponseInfoItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDAPSResponseInfoItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DLCPSecurityInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{DL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func DLCPSecurityInformationExtIEsValueExtensionTableCodec(table s00.DLCPSecurityInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.DLCPSecurityInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeDLCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.DLCPSecurityInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DLCPSecurityInformationExtIEsExtContainerValueCodec {
		sealed := s09.DLCPSecurityInformationExtIEsExtContainerValueCodec{}
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "DLCPSecurityInformationExtIEsExtContainer"
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DLCPSecurityInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DLCPSecurityInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DLCPSecurityInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DLCPSecurityInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DLCPSecurityInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DLCPSecurityInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.DLCPSecurityInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.DLCPSecurityInformationExtIEsExtContainer, options aper.DecodeState) (s09.DLCPSecurityInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.DLCPSecurityInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDLCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferTransparentContainerExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ENB-StatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBStatusTransferTransparentContainerExtIEsValueExtensionTableCodec(table s00.ENBStatusTransferTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
		sealed := s09.ENBStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENBStatusTransferTransparentContainerExtIEsExtContainer"
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENBStatusTransferTransparentContainerExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENBStatusTransferTransparentContainerExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainerExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferTransparentContainerExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainerExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, options aper.DecodeState) (s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENBStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBX2ExtTLAExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ENBX2ExtTLA-ExtIEs}} codec of TS 36.413.
func ENBX2ExtTLAExtIEsValueExtensionTableCodec(table s00.ENBX2ExtTLAExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENBX2ExtTLAExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBX2ExtTLAExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENBX2ExtTLAExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENBX2ExtTLAExtIEsExtContainerValueCodec {
		sealed := s09.ENBX2ExtTLAExtIEsExtContainerValueCodec{}
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENBX2ExtTLAExtIEsExtContainer"
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENBX2ExtTLAExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENBX2ExtTLAExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENBX2ExtTLAExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENBX2ExtTLAExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBX2ExtTLAExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBX2ExtTLAExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENBX2ExtTLAExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENBX2ExtTLAExtIEsExtContainer, options aper.DecodeState) (s09.ENBX2ExtTLAExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENBX2ExtTLAExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENBX2ExtTLAExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONConfigurationTransferExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EN-DCSONConfigurationTransfer-ExtIEs}} codec of TS 36.413.
func ENDCSONConfigurationTransferExtIEsValueExtensionTableCodec(table s00.ENDCSONConfigurationTransferExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec {
		sealed := s09.ENDCSONConfigurationTransferExtIEsExtContainerValueCodec{}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENDCSONConfigurationTransferExtIEsExtContainer"
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONConfigurationTransferExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENDCSONConfigurationTransferExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENDCSONConfigurationTransferExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransferExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONConfigurationTransferExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENDCSONConfigurationTransferExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENDCSONConfigurationTransferExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONConfigurationTransferExtIEsExtContainer, options aper.DecodeState) (s09.ENDCSONConfigurationTransferExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONConfigurationTransferExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONConfigurationTransferExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONeNBIdentificationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EN-DCSONeNBIdentification-ExtIEs}} codec of TS 36.413.
func ENDCSONeNBIdentificationExtIEsValueExtensionTableCodec(table s00.ENDCSONeNBIdentificationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONeNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec {
		sealed := s09.ENDCSONeNBIdentificationExtIEsExtContainerValueCodec{}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENDCSONeNBIdentificationExtIEsExtContainer"
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONeNBIdentificationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENDCSONeNBIdentificationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENDCSONeNBIdentificationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENDCSONeNBIdentificationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONeNBIdentificationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENDCSONeNBIdentificationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENDCSONeNBIdentificationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONeNBIdentificationExtIEsExtContainer, options aper.DecodeState) (s09.ENDCSONeNBIdentificationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONeNBIdentificationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONeNBIdentificationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENDCSONengNBIdentificationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EN-DCSONengNBIdentification-ExtIEs}} codec of TS 36.413.
func ENDCSONengNBIdentificationExtIEsValueExtensionTableCodec(table s00.ENDCSONengNBIdentificationExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCSONengNBIdentificationExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec {
		sealed := s09.ENDCSONengNBIdentificationExtIEsExtContainerValueCodec{}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENDCSONengNBIdentificationExtIEsExtContainer"
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCSONengNBIdentificationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENDCSONengNBIdentificationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENDCSONengNBIdentificationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENDCSONengNBIdentificationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCSONengNBIdentificationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENDCSONengNBIdentificationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENDCSONengNBIdentificationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENDCSONengNBIdentificationExtIEsExtContainer, options aper.DecodeState) (s09.ENDCSONengNBIdentificationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENDCSONengNBIdentificationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCSONengNBIdentificationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENDCTransferTypeReplyExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EN-DCTransferTypeReply-ExtIEs}} codec of TS 36.413.
func ENDCTransferTypeReplyExtIEsValueExtensionTableCodec(table s00.ENDCTransferTypeReplyExtIEsValueExtensionTable, bounds aper.ListBounds) s09.ENDCTransferTypeReplyExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCTransferTypeReplyExtIEsValueExtensionTableFieldBound(&table) {
		return s09.ENDCTransferTypeReplyExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.ENDCTransferTypeReplyExtIEsExtContainerValueCodec {
		sealed := s09.ENDCTransferTypeReplyExtIEsExtContainerValueCodec{}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENDCTransferTypeReplyExtIEsExtContainer"
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.ENDCTransferTypeReplyExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.ENDCTransferTypeReplyExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.ENDCTransferTypeReplyExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENDCTransferTypeReplyExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeReplyExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENDCTransferTypeReplyExtIEsExtContainer")
			}
			return fields, nil
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s09.ENDCTransferTypeReplyExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeENDCTransferTypeReplyExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s09.ENDCTransferTypeReplyExtIEsExtContainer, options aper.DecodeState) (s09.ENDCTransferTypeReplyExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s09.ENDCTransferTypeReplyExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeENDCTransferTypeReplyExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENDCTransferTypeRequestExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EN-DCTransferTypeRequest-ExtIEs}} codec of TS 36.413.
func ENDCTransferTypeRequestExtIEsValueExtensionTableCodec(table s00.ENDCTransferTypeRequestExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ENDCTransferTypeRequestExtIEsExtContainerValueCodec {
	if !*s00.BridgeENDCTransferTypeRequestExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ENDCTransferTypeRequestExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ENDCTransferTypeRequestExtIEsExtContainerValueCodec {
		sealed := s10.ENDCTransferTypeRequestExtIEsExtContainerValueCodec{}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldPath(&sealed) = "ENDCTransferTypeRequestExtIEsExtContainer"
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ENDCTransferTypeRequestExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ENDCTransferTypeRequestExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ENDCTransferTypeRequestExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ENDCTransferTypeRequestExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENDCTransferTypeRequestExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENDCTransferTypeRequestExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ENDCTransferTypeRequestExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeENDCTransferTypeRequestExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ENDCTransferTypeRequestExtIEsExtContainer, options aper.DecodeState) (s10.ENDCTransferTypeRequestExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ENDCTransferTypeRequestExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeENDCTransferTypeRequestExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABAdmittedItem-ExtIEs}} codec of TS 36.413.
func ERABAdmittedItemExtIEsValueExtensionTableCodec(table s00.ERABAdmittedItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABAdmittedItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABAdmittedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABAdmittedItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABAdmittedItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABAdmittedItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABAdmittedItemExtIEsExtContainer"
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABAdmittedItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABAdmittedItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABAdmittedItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABAdmittedItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABAdmittedItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABAdmittedItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABAdmittedItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABAdmittedItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABDataForwardingItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABDataForwardingItem-ExtIEs}} codec of TS 36.413.
func ERABDataForwardingItemExtIEsValueExtensionTableCodec(table s00.ERABDataForwardingItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABDataForwardingItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABDataForwardingItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABDataForwardingItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABDataForwardingItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABDataForwardingItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABDataForwardingItemExtIEsExtContainer"
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABDataForwardingItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABDataForwardingItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABDataForwardingItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABDataForwardingItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABDataForwardingItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABDataForwardingItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABDataForwardingItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABDataForwardingItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABDataForwardingItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeReqExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABFailedToResumeItemResumeReq-ExtIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeReqExtIEsValueExtensionTableCodec(table s00.ERABFailedToResumeItemResumeReqExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeReqExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec {
		sealed := s10.ERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodec{}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeReqExtIEsExtContainer"
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABFailedToResumeItemResumeReqExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReqExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReqExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToResumeItemResumeReqExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeItemResumeResExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABFailedToResumeItemResumeRes-ExtIEs}} codec of TS 36.413.
func ERABFailedToResumeItemResumeResExtIEsValueExtensionTableCodec(table s00.ERABFailedToResumeItemResumeResExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToResumeItemResumeResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec {
		sealed := s10.ERABFailedToResumeItemResumeResExtIEsExtContainerValueCodec{}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABFailedToResumeItemResumeResExtIEsExtContainer"
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABFailedToResumeItemResumeResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABFailedToResumeItemResumeResExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeResExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeResExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, options aper.DecodeState) (s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToResumeItemResumeResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToResumeItemResumeResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABFailedToSetupItemHOReqAckExtIEs}} codec of TS 36.413.
func ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableCodec(table s00.ERABFailedToSetupItemHOReqAckExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABFailedToSetupItemHOReqAckExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec {
		sealed := s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodec{}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABFailedToSetupItemHOReqAckExtIEsExtContainer"
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABFailedToSetupItemHOReqAckExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAckExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABFailedToSetupItemHOReqAckExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAckExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, options aper.DecodeState) (s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABItem-ExtIEs}} codec of TS 36.413.
func ERABItemExtIEsValueExtensionTableCodec(table s00.ERABItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABItemExtIEsExtContainer"
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModConfExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABModifyItemBearerModConfExtIEs}} codec of TS 36.413.
func ERABModifyItemBearerModConfExtIEsValueExtensionTableCodec(table s00.ERABModifyItemBearerModConfExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModConfExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec {
		sealed := s10.ERABModifyItemBearerModConfExtIEsExtContainerValueCodec{}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModConfExtIEsExtContainer"
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABModifyItemBearerModConfExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABModifyItemBearerModConfExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABModifyItemBearerModConfExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConfExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModConfExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABModifyItemBearerModConfExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABModifyItemBearerModConfExtIEsExtContainer, options aper.DecodeState) (s10.ERABModifyItemBearerModConfExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABModifyItemBearerModConfExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABModifyItemBearerModConfExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABModifyItemBearerModResExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABModifyItemBearerModResExtIEs}} codec of TS 36.413.
func ERABModifyItemBearerModResExtIEsValueExtensionTableCodec(table s00.ERABModifyItemBearerModResExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABModifyItemBearerModResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABModifyItemBearerModResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABModifyItemBearerModResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABModifyItemBearerModResExtIEsExtContainerValueCodec {
		sealed := s10.ERABModifyItemBearerModResExtIEsExtContainerValueCodec{}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABModifyItemBearerModResExtIEsExtContainer"
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABModifyItemBearerModResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABModifyItemBearerModResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABModifyItemBearerModResExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModResExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABModifyItemBearerModResExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABModifyItemBearerModResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABModifyItemBearerModResExtIEsExtContainer, options aper.DecodeState) (s10.ERABModifyItemBearerModResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABModifyItemBearerModResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABModifyItemBearerModResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABNotToBeModifiedItemBearerModInd-ExtIEs}} codec of TS 36.413.
func ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec(table s00.ERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
		sealed := s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer"
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, options aper.DecodeState) (s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABQoSParametersExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABQoSParameters-ExtIEs}} codec of TS 36.413.
func ERABQoSParametersExtIEsValueExtensionTableCodec(table s00.ERABQoSParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABQoSParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABQoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABQoSParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABQoSParametersExtIEsExtContainerValueCodec {
		sealed := s10.ERABQoSParametersExtIEsExtContainerValueCodec{}
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABQoSParametersExtIEsExtContainer"
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABQoSParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABQoSParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABQoSParametersExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABQoSParametersExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABQoSParametersExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABQoSParametersExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABQoSParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABQoSParametersExtIEsExtContainer, options aper.DecodeState) (s10.ERABQoSParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABQoSParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABQoSParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABReleaseItemBearerRelCompExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABReleaseItemBearerRelCompExtIEs}} codec of TS 36.413.
func ERABReleaseItemBearerRelCompExtIEsValueExtensionTableCodec(table s00.ERABReleaseItemBearerRelCompExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABReleaseItemBearerRelCompExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec {
		sealed := s10.ERABReleaseItemBearerRelCompExtIEsExtContainerValueCodec{}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABReleaseItemBearerRelCompExtIEsExtContainer"
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABReleaseItemBearerRelCompExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABReleaseItemBearerRelCompExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelCompExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelCompExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, options aper.DecodeState) (s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABReleaseItemBearerRelCompExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABReleaseItemBearerRelCompExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSecurityResultItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABSecurityResultItem-ExtIEs}} codec of TS 36.413.
func ERABSecurityResultItemExtIEsValueExtensionTableCodec(table s00.ERABSecurityResultItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABSecurityResultItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSecurityResultItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSecurityResultItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABSecurityResultItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABSecurityResultItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABSecurityResultItemExtIEsExtContainer"
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSecurityResultItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABSecurityResultItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABSecurityResultItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABSecurityResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSecurityResultItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSecurityResultItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABSecurityResultItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABSecurityResultItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABSecurityResultItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABSecurityResultItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABSecurityResultItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSecurityResultItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemBearerSUResExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABSetupItemBearerSUResExtIEs}} codec of TS 36.413.
func ERABSetupItemBearerSUResExtIEsValueExtensionTableCodec(table s00.ERABSetupItemBearerSUResExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSetupItemBearerSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec {
		sealed := s10.ERABSetupItemBearerSUResExtIEsExtContainerValueCodec{}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABSetupItemBearerSUResExtIEsExtContainer"
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSetupItemBearerSUResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABSetupItemBearerSUResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABSetupItemBearerSUResExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSUResExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemBearerSUResExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABSetupItemBearerSUResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABSetupItemBearerSUResExtIEsExtContainer, options aper.DecodeState) (s10.ERABSetupItemBearerSUResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABSetupItemBearerSUResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSetupItemBearerSUResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABSetupItemCtxtSUResExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABSetupItemCtxtSUResExtIEs}} codec of TS 36.413.
func ERABSetupItemCtxtSUResExtIEsValueExtensionTableCodec(table s00.ERABSetupItemCtxtSUResExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABSetupItemCtxtSUResExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec {
		sealed := s10.ERABSetupItemCtxtSUResExtIEsExtContainerValueCodec{}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSUResExtIEsExtContainer"
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABSetupItemCtxtSUResExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABSetupItemCtxtSUResExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABSetupItemCtxtSUResExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSUResExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSUResExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABSetupItemCtxtSUResExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABSetupItemCtxtSUResExtIEsExtContainer, options aper.DecodeState) (s10.ERABSetupItemCtxtSUResExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABSetupItemCtxtSUResExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABSetupItemCtxtSUResExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeModifiedItemBearerModInd-ExtIEs}} codec of TS 36.413.
func ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableCodec(table s00.ERABToBeModifiedItemBearerModIndExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeModifiedItemBearerModIndExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec {
		sealed := s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodec{}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABToBeModifiedItemBearerModIndExtIEsExtContainer"
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABToBeModifiedItemBearerModIndExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModIndExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModIndExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, options aper.DecodeState) (s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeSwitchedULItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeSwitchedULItem-ExtIEs}} codec of TS 36.413.
func ERABToBeSwitchedULItemExtIEsValueExtensionTableCodec(table s00.ERABToBeSwitchedULItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeSwitchedULItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABToBeSwitchedULItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULItemExtIEsExtContainer"
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeSwitchedULItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABToBeSwitchedULItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABToBeSwitchedULItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABToBeSwitchedULItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeSwitchedULItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABToBeSwitchedULItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeSwitchedULItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeSwitchedULItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABToBeUpdatedItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABToBeUpdatedItem-ExtIEs}} codec of TS 36.413.
func ERABToBeUpdatedItemExtIEsValueExtensionTableCodec(table s00.ERABToBeUpdatedItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABToBeUpdatedItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABToBeUpdatedItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABToBeUpdatedItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABToBeUpdatedItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABToBeUpdatedItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABToBeUpdatedItemExtIEsExtContainer"
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABToBeUpdatedItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABToBeUpdatedItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABToBeUpdatedItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABToBeUpdatedItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABToBeUpdatedItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABToBeUpdatedItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABToBeUpdatedItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABToBeUpdatedItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABToBeUpdatedItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABToBeUpdatedItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABToBeUpdatedItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABToBeUpdatedItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABUsageReportItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{E-RABUsageReportItem-ExtIEs}} codec of TS 36.413.
func ERABUsageReportItemExtIEsValueExtensionTableCodec(table s00.ERABUsageReportItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ERABUsageReportItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeERABUsageReportItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ERABUsageReportItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ERABUsageReportItemExtIEsExtContainerValueCodec {
		sealed := s10.ERABUsageReportItemExtIEsExtContainerValueCodec{}
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ERABUsageReportItemExtIEsExtContainer"
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ERABUsageReportItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ERABUsageReportItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ERABUsageReportItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABUsageReportItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABUsageReportItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ERABUsageReportItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ERABUsageReportItemExtIEsExtContainer, options aper.DecodeState) (s10.ERABUsageReportItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ERABUsageReportItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeERABUsageReportItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EUTRANCGIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EUTRAN-CGI-ExtIEs}} codec of TS 36.413.
func EUTRANCGIExtIEsValueExtensionTableCodec(table s00.EUTRANCGIExtIEsValueExtensionTable, bounds aper.ListBounds) s10.EUTRANCGIExtIEsExtContainerValueCodec {
	if !*s00.BridgeEUTRANCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EUTRANCGIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.EUTRANCGIExtIEsExtContainerValueCodec {
		sealed := s10.EUTRANCGIExtIEsExtContainerValueCodec{}
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldPath(&sealed) = "EUTRANCGIExtIEsExtContainer"
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EUTRANCGIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EUTRANCGIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EUTRANCGIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EUTRANCGIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "EUTRANCGIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EUTRANCGIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.EUTRANCGIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.EUTRANCGIExtIEsExtContainer, options aper.DecodeState) (s10.EUTRANCGIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.EUTRANCGIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEUTRANCGIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDBroadcastItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EmergencyAreaID-Broadcast-Item-ExtIEs}} codec of TS 36.413.
func EmergencyAreaIDBroadcastItemExtIEsValueExtensionTableCodec(table s00.EmergencyAreaIDBroadcastItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeEmergencyAreaIDBroadcastItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec {
		sealed := s10.EmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodec{}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "EmergencyAreaIDBroadcastItemExtIEsExtContainer"
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EmergencyAreaIDBroadcastItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDBroadcastItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EmergencyAreaIDBroadcastItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, options aper.DecodeState) (s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.EmergencyAreaIDBroadcastItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDCancelledItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EmergencyAreaID-Cancelled-Item-ExtIEs}} codec of TS 36.413.
func EmergencyAreaIDCancelledItemExtIEsValueExtensionTableCodec(table s00.EmergencyAreaIDCancelledItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeEmergencyAreaIDCancelledItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec {
		sealed := s10.EmergencyAreaIDCancelledItemExtIEsExtContainerValueCodec{}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "EmergencyAreaIDCancelledItemExtIEsExtContainer"
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EmergencyAreaIDCancelledItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EmergencyAreaIDCancelledItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDCancelledItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, options aper.DecodeState) (s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EventL1LoggedMDTConfigExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{EventL1LoggedMDTConfig-ExtIEs}} codec of TS 36.413.
func EventL1LoggedMDTConfigExtIEsValueExtensionTableCodec(table s00.EventL1LoggedMDTConfigExtIEsValueExtensionTable, bounds aper.ListBounds) s10.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec {
	if !*s00.BridgeEventL1LoggedMDTConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s10.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec {
		sealed := s10.EventL1LoggedMDTConfigExtIEsExtContainerValueCodec{}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldPath(&sealed) = "EventL1LoggedMDTConfigExtIEsExtContainer"
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventL1LoggedMDTConfigExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EventL1LoggedMDTConfigExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EventL1LoggedMDTConfigExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EventL1LoggedMDTConfigExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventL1LoggedMDTConfigExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EventL1LoggedMDTConfigExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.EventL1LoggedMDTConfigExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.EventL1LoggedMDTConfigExtIEsExtContainer, options aper.DecodeState) (s10.EventL1LoggedMDTConfigExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.EventL1LoggedMDTConfigExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventL1LoggedMDTConfigExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ExpectedUEActivityBehaviourExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ExpectedUEActivityBehaviour-ExtIEs}} codec of TS 36.413.
func ExpectedUEActivityBehaviourExtIEsValueExtensionTableCodec(table s00.ExpectedUEActivityBehaviourExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec {
	if !*s00.BridgeExpectedUEActivityBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec {
		sealed := s10.ExpectedUEActivityBehaviourExtIEsExtContainerValueCodec{}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldPath(&sealed) = "ExpectedUEActivityBehaviourExtIEsExtContainer"
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ExpectedUEActivityBehaviourExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ExpectedUEActivityBehaviourExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ExpectedUEActivityBehaviourExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviourExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedUEActivityBehaviourExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviourExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ExpectedUEActivityBehaviourExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ExpectedUEActivityBehaviourExtIEsExtContainer, options aper.DecodeState) (s10.ExpectedUEActivityBehaviourExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ExpectedUEActivityBehaviourExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeExpectedUEActivityBehaviourExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ExpectedUEBehaviourExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ExpectedUEBehaviour-ExtIEs}} codec of TS 36.413.
func ExpectedUEBehaviourExtIEsValueExtensionTableCodec(table s00.ExpectedUEBehaviourExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ExpectedUEBehaviourExtIEsExtContainerValueCodec {
	if !*s00.BridgeExpectedUEBehaviourExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ExpectedUEBehaviourExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ExpectedUEBehaviourExtIEsExtContainerValueCodec {
		sealed := s10.ExpectedUEBehaviourExtIEsExtContainerValueCodec{}
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldPath(&sealed) = "ExpectedUEBehaviourExtIEsExtContainer"
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ExpectedUEBehaviourExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ExpectedUEBehaviourExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ExpectedUEBehaviourExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ExpectedUEBehaviourExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedUEBehaviourExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ExpectedUEBehaviourExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ExpectedUEBehaviourExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ExpectedUEBehaviourExtIEsExtContainer, options aper.DecodeState) (s10.ExpectedUEBehaviourExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ExpectedUEBehaviourExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeExpectedUEBehaviourExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// FiveGSTAIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{FiveGSTAI-ExtIEs}} codec of TS 36.413.
func FiveGSTAIExtIEsValueExtensionTableCodec(table s00.FiveGSTAIExtIEsValueExtensionTable, bounds aper.ListBounds) s10.FiveGSTAIExtIEsExtContainerValueCodec {
	if !*s00.BridgeFiveGSTAIExtIEsValueExtensionTableFieldBound(&table) {
		return s10.FiveGSTAIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.FiveGSTAIExtIEsExtContainerValueCodec {
		sealed := s10.FiveGSTAIExtIEsExtContainerValueCodec{}
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldPath(&sealed) = "FiveGSTAIExtIEsExtContainer"
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.FiveGSTAIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.FiveGSTAIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.FiveGSTAIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "FiveGSTAIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "FiveGSTAIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "FiveGSTAIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.FiveGSTAIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.FiveGSTAIExtIEsExtContainer, options aper.DecodeState) (s10.FiveGSTAIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.FiveGSTAIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeFiveGSTAIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenLAsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ForbiddenLAs-Item-ExtIEs}} codec of TS 36.413.
func ForbiddenLAsItemExtIEsValueExtensionTableCodec(table s00.ForbiddenLAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ForbiddenLAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeForbiddenLAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ForbiddenLAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ForbiddenLAsItemExtIEsExtContainerValueCodec {
		sealed := s10.ForbiddenLAsItemExtIEsExtContainerValueCodec{}
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ForbiddenLAsItemExtIEsExtContainer"
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ForbiddenLAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ForbiddenLAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ForbiddenLAsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ForbiddenLAsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ForbiddenLAsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ForbiddenLAsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ForbiddenLAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ForbiddenLAsItemExtIEsExtContainer, options aper.DecodeState) (s10.ForbiddenLAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ForbiddenLAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeForbiddenLAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenTAsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ForbiddenTAs-Item-ExtIEs}} codec of TS 36.413.
func ForbiddenTAsItemExtIEsValueExtensionTableCodec(table s00.ForbiddenTAsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s10.ForbiddenTAsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeForbiddenTAsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s10.ForbiddenTAsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.ForbiddenTAsItemExtIEsExtContainerValueCodec {
		sealed := s10.ForbiddenTAsItemExtIEsExtContainerValueCodec{}
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "ForbiddenTAsItemExtIEsExtContainer"
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ForbiddenTAsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.ForbiddenTAsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.ForbiddenTAsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ForbiddenTAsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ForbiddenTAsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ForbiddenTAsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s10.ForbiddenTAsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s10.ForbiddenTAsItemExtIEsExtContainer, options aper.DecodeState) (s10.ForbiddenTAsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s10.ForbiddenTAsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeForbiddenTAsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GBRQosInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{GBR-QosInformation-ExtIEs}} codec of TS 36.413.
func GBRQosInformationExtIEsValueExtensionTableCodec(table s00.GBRQosInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GBRQosInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeGBRQosInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GBRQosInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GBRQosInformationExtIEsExtContainerValueCodec {
		sealed := s11.GBRQosInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "GBRQosInformationExtIEsExtContainer"
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GBRQosInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GBRQosInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GBRQosInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GBRQosInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GBRQosInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GBRQosInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GBRQosInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GBRQosInformationExtIEsExtContainer, options aper.DecodeState) (s11.GBRQosInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GBRQosInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGBRQosInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GERANCellIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{GERAN-Cell-ID-ExtIEs}} codec of TS 36.413.
func GERANCellIDExtIEsValueExtensionTableCodec(table s00.GERANCellIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GERANCellIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGERANCellIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GERANCellIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GERANCellIDExtIEsExtContainerValueCodec {
		sealed := s11.GERANCellIDExtIEsExtContainerValueCodec{}
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "GERANCellIDExtIEsExtContainer"
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GERANCellIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GERANCellIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GERANCellIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GERANCellIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GERANCellIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GERANCellIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GERANCellIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GERANCellIDExtIEsExtContainer, options aper.DecodeState) (s11.GERANCellIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GERANCellIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGERANCellIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GNBExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{GNB-ExtIEs}} codec of TS 36.413.
func GNBExtIEsValueExtensionTableCodec(table s00.GNBExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GNBExtIEsExtContainerValueCodec {
	if !*s00.BridgeGNBExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GNBExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GNBExtIEsExtContainerValueCodec {
		sealed := s11.GNBExtIEsExtContainerValueCodec{}
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldPath(&sealed) = "GNBExtIEsExtContainer"
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GNBExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GNBExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GNBExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GNBExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GNBExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GNBExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GNBExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GNBExtIEsExtContainer, options aper.DecodeState) (s11.GNBExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGNBExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GNBExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGNBExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGNBExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GUMMEIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{GUMMEI-ExtIEs}} codec of TS 36.413.
func GUMMEIExtIEsValueExtensionTableCodec(table s00.GUMMEIExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GUMMEIExtIEsExtContainerValueCodec {
	if !*s00.BridgeGUMMEIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GUMMEIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GUMMEIExtIEsExtContainerValueCodec {
		sealed := s11.GUMMEIExtIEsExtContainerValueCodec{}
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldPath(&sealed) = "GUMMEIExtIEsExtContainer"
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GUMMEIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GUMMEIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GUMMEIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GUMMEIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GUMMEIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GUMMEIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GUMMEIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GUMMEIExtIEsExtContainer, options aper.DecodeState) (s11.GUMMEIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GUMMEIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGUMMEIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GlobalENBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{GlobalENB-ID-ExtIEs}} codec of TS 36.413.
func GlobalENBIDExtIEsValueExtensionTableCodec(table s00.GlobalENBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GlobalENBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalENBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalENBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GlobalENBIDExtIEsExtContainerValueCodec {
		sealed := s11.GlobalENBIDExtIEsExtContainerValueCodec{}
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "GlobalENBIDExtIEsExtContainer"
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalENBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GlobalENBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GlobalENBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GlobalENBIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalENBIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GlobalENBIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GlobalENBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GlobalENBIDExtIEsExtContainer, options aper.DecodeState) (s11.GlobalENBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GlobalENBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalENBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GlobalEnGNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Global-en-gNB-ID-ExtIEs}} codec of TS 36.413.
func GlobalEnGNBIDExtIEsValueExtensionTableCodec(table s00.GlobalEnGNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GlobalEnGNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalEnGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalEnGNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GlobalEnGNBIDExtIEsExtContainerValueCodec {
		sealed := s11.GlobalEnGNBIDExtIEsExtContainerValueCodec{}
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "GlobalEnGNBIDExtIEsExtContainer"
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalEnGNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GlobalEnGNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GlobalEnGNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GlobalEnGNBIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalEnGNBIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GlobalEnGNBIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GlobalEnGNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GlobalEnGNBIDExtIEsExtContainer, options aper.DecodeState) (s11.GlobalEnGNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GlobalEnGNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalEnGNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// GlobalGNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Global-GNB-ID-ExtIEs}} codec of TS 36.413.
func GlobalGNBIDExtIEsValueExtensionTableCodec(table s00.GlobalGNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.GlobalGNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeGlobalGNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.GlobalGNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.GlobalGNBIDExtIEsExtContainerValueCodec {
		sealed := s11.GlobalGNBIDExtIEsExtContainerValueCodec{}
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "GlobalGNBIDExtIEsExtContainer"
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.GlobalGNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.GlobalGNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.GlobalGNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "GlobalGNBIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "GlobalGNBIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "GlobalGNBIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.GlobalGNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.GlobalGNBIDExtIEsExtContainer, options aper.DecodeState) (s11.GlobalGNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.GlobalGNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeGlobalGNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DeactivateTraceIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{DeactivateTraceIEs}} codec of TS 36.413.
func DeactivateTraceIEValueIEFieldTableCodec(table s00.DeactivateTraceIEValueIETable) s09.DeactivateTraceIEFieldValueCodec {
	if !*s00.BridgeDeactivateTraceIEValueIETableFieldBound(&table) {
		return s09.DeactivateTraceIEFieldValueCodec{}
	}
	return func() s09.DeactivateTraceIEFieldValueCodec {
		sealed := s09.DeactivateTraceIEFieldValueCodec{}
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldPath(&sealed) = "DeactivateTraceIEField"
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DeactivateTraceIEField, error) {
			var field s09.DeactivateTraceIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DeactivateTraceIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DeactivateTraceIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DeactivateTraceIEField")
			}
			return field, nil
		}
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldEncode(&sealed) = func(field s09.DeactivateTraceIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldCapture(&sealed) = func(v s09.DeactivateTraceIEField, options aper.DecodeState) (s09.DeactivateTraceIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldCompare(&sealed) = func(v s09.DeactivateTraceIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDeactivateTraceIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{DownlinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s09.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s09.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(&sealed) = "DownlinkNonUEAssociatedLPPaTransportIEField"
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEField, error) {
			var field s09.DownlinkNonUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEField")
			}
			return field, nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s09.DownlinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{DownlinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeDownlinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s09.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s09.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s09.DownlinkUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldPath(&sealed) = "DownlinkUEAssociatedLPPaTransportIEField"
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEField, error) {
			var field s09.DownlinkUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransportIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEField")
			}
			return field, nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s09.DownlinkUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EventTriggerExtIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{EventTrigger-ExtIEs}} codec of TS 36.413.
func EventTriggerExtIEValueIEFieldTableCodec(table s00.EventTriggerExtIEValueIETable) s10.EventTriggerExtIEFieldValueCodec {
	if !*s00.BridgeEventTriggerExtIEValueIETableFieldBound(&table) {
		return s10.EventTriggerExtIEFieldValueCodec{}
	}
	return func() s10.EventTriggerExtIEFieldValueCodec {
		sealed := s10.EventTriggerExtIEFieldValueCodec{}
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldPath(&sealed) = "EventTriggerExtIEField"
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventTriggerExtIEField, error) {
			var field s10.EventTriggerExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "EventTriggerExtIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventTriggerExtIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "EventTriggerExtIEField")
			}
			return field, nil
		}
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldEncode(&sealed) = func(field s10.EventTriggerExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s10.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldCapture(&sealed) = func(v s10.EventTriggerExtIEField, options aper.DecodeState) (s10.EventTriggerExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldCompare(&sealed) = func(v s10.EventTriggerExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventTriggerExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DeactivateTraceIEValueIETableCodec constructs the ProtocolIE-Container {{DeactivateTraceIEs}} codec of TS 36.413.
func DeactivateTraceIEValueIETableCodec(table s00.DeactivateTraceIEValueIETable, bounds aper.ListBounds) s09.DeactivateTraceIEContainerValueCodec {
	if !*s00.BridgeDeactivateTraceIEValueIETableFieldBound(&table) {
		return s09.DeactivateTraceIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DeactivateTraceIEContainerValueCodec {
		sealed := s09.DeactivateTraceIEContainerValueCodec{}
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldPath(&sealed) = "DeactivateTraceIEContainer"
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DeactivateTraceIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DeactivateTraceIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DeactivateTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DeactivateTraceIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEContainer")
			}
			return fields, nil
		}
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&sealed) = func(fields s09.DeactivateTraceIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldCapture(&sealed) = func(v s09.DeactivateTraceIEContainer, options aper.DecodeState) (s09.DeactivateTraceIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldCompare(&sealed) = func(v s09.DeactivateTraceIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDeactivateTraceIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{DownlinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s09.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s09.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(&sealed) = "DownlinkNonUEAssociatedLPPaTransportIEContainer"
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkNonUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEContainer")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DownlinkUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{DownlinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s09.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeDownlinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s09.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s09.DownlinkUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldPath(&sealed) = "DownlinkUEAssociatedLPPaTransportIEContainer"
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransportIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEContainer")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s09.DownlinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EventTriggerExtIEValueIETableCodec constructs the ProtocolIE-Container {{EventTrigger-ExtIEs}} codec of TS 36.413.
func EventTriggerExtIEValueIETableCodec(table s00.EventTriggerExtIEValueIETable, bounds aper.ListBounds) s10.EventTriggerExtIEContainerValueCodec {
	if !*s00.BridgeEventTriggerExtIEValueIETableFieldBound(&table) {
		return s10.EventTriggerExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s10.EventTriggerExtIEContainerValueCodec {
		sealed := s10.EventTriggerExtIEContainerValueCodec{}
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldPath(&sealed) = "EventTriggerExtIEContainer"
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventTriggerExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EventTriggerExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EventTriggerExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventTriggerExtIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEContainer")
			}
			return fields, nil
		}
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s10.EventTriggerExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s10.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldCapture(&sealed) = func(v s10.EventTriggerExtIEContainer, options aper.DecodeState) (s10.EventTriggerExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldCompare(&sealed) = func(v s10.EventTriggerExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventTriggerExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DeactivateTraceIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{DeactivateTraceIEs}} codec of TS 36.413.
func DeactivateTraceIEValueProtocolErrorIEContainerListCodec(table s00.DeactivateTraceIEValueIETable) s09.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s09.DeactivateTraceIEValueProtocolErrorIEContainerListValueCodec{}
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "DeactivateTraceIEValueProtocolErrorIEContainerList"
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DeactivateTraceIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DeactivateTraceIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DeactivateTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DeactivateTraceIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DeactivateTraceIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s09.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DeactivateTraceIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s09.DeactivateTraceIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DeactivateTraceIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDeactivateTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{DownlinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{DownlinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable) s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EventTriggerExtIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{EventTrigger-ExtIEs}} codec of TS 36.413.
func EventTriggerExtIEValueProtocolErrorIEContainerListCodec(table s00.EventTriggerExtIEValueIETable) s10.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s10.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s10.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s10.EventTriggerExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "EventTriggerExtIEValueProtocolErrorIEContainerList"
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventTriggerExtIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EventTriggerExtIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EventTriggerExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventTriggerExtIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.EventTriggerExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s10.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.EventTriggerExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s10.EventTriggerExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.EventTriggerExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventTriggerExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DeactivateTraceIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {DeactivateTraceIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func DeactivateTraceIEValueProtocolIEContainerListCodec(table s00.DeactivateTraceIEValueIETable, bounds aper.ListBounds) s09.DeactivateTraceIEValueProtocolIEContainerListValueCodec {
	codec := DeactivateTraceIEValueIETableCodec(table, bounds)
	if *s09.BridgeDeactivateTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DeactivateTraceIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s09.DeactivateTraceIEValueProtocolIEContainerListValueCodec {
		sealed := s09.DeactivateTraceIEValueProtocolIEContainerListValueCodec{}
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "DeactivateTraceIEValueProtocolIEContainerList"
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DeactivateTraceIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DeactivateTraceIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DeactivateTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DeactivateTraceIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DeactivateTraceIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DeactivateTraceIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDeactivateTraceIEContainerValueCodecFieldEncode(&codec))(s09.DeactivateTraceIEContainer(value), fresh, budget)
		}
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DeactivateTraceIEValueProtocolIEContainerList, options aper.DecodeState) (s09.DeactivateTraceIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DeactivateTraceIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDeactivateTraceIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {DownlinkNonUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.DownlinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList"
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkNonUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {DownlinkUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.DownlinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList"
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s09.DownlinkUEAssociatedLPPaTransportIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s09.BridgeDownlinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s09.DownlinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// EventTriggerExtIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {EventTrigger-ExtIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func EventTriggerExtIEValueProtocolIEContainerListCodec(table s00.EventTriggerExtIEValueIETable, bounds aper.ListBounds) s10.EventTriggerExtIEValueProtocolIEContainerListValueCodec {
	codec := EventTriggerExtIEValueIETableCodec(table, bounds)
	if *s10.BridgeEventTriggerExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s10.EventTriggerExtIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s10.EventTriggerExtIEValueProtocolIEContainerListValueCodec {
		sealed := s10.EventTriggerExtIEValueProtocolIEContainerListValueCodec{}
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "EventTriggerExtIEValueProtocolIEContainerList"
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.EventTriggerExtIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s10.EventTriggerExtIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s10.EventTriggerExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "EventTriggerExtIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "EventTriggerExtIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s10.EventTriggerExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s10.BridgeEventTriggerExtIEContainerValueCodecFieldEncode(&codec))(s10.EventTriggerExtIEContainer(value), fresh, budget)
		}
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s10.EventTriggerExtIEValueProtocolIEContainerList, options aper.DecodeState) (s10.EventTriggerExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s10.EventTriggerExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s10.BridgeEventTriggerExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionField(v *s08.AdditionalGUTIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeAdditionalGUTIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeAdditionalGUTIExtIEsExtFieldFieldReplay(v), *s08.BridgeAdditionalGUTIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionField(v *s08.AdditionalGUTIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeAdditionalGUTIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeAdditionalGUTIExtIEsExtFieldFieldReplay(v), *s08.BridgeAdditionalGUTIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionField(v *s08.AllocationAndRetentionPriorityExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldReplay(v), *s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionField(v *s08.AllocationAndRetentionPriorityExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeAllocationAndRetentionPriorityExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldReplay(v), *s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceDataForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s08.AssistanceDataForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeAssistanceDataForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeAssistanceDataForPagingExtIEsExtFieldFieldReplay(v), *s08.BridgeAssistanceDataForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceDataForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s08.AssistanceDataForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeAssistanceDataForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeAssistanceDataForPagingExtIEsExtFieldFieldReplay(v), *s08.BridgeAssistanceDataForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueCaptureS1APProtocolExtensionField(v *s08.AssistanceDataForRecommendedCellsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldReplay(v), *s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueCompareS1APProtocolExtensionField(v *s08.AssistanceDataForRecommendedCellsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldReplay(v), *s08.BridgeAssistanceDataForRecommendedCellsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.BearersSubjectToDLDiscardingItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldReplay(v), *s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.BearersSubjectToDLDiscardingItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldReplay(v), *s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldReplay(v), *s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldReplay(v), *s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s08.BluetoothMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s08.BluetoothMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeBluetoothMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCGIExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCGIExtIEsExtFieldFieldReplay(v), *s08.BridgeCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCGIExtIEsValueCompareS1APProtocolExtensionField(v *s08.CGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCGIExtIEsExtFieldFieldReplay(v), *s08.BridgeCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CNTypeRestrictionsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.CNTypeRestrictionsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCNTypeRestrictionsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionField(v *s08.COUNTValueExtendedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCOUNTValueExtendedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCOUNTValueExtendedExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTValueExtendedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionField(v *s08.COUNTValueExtendedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCOUNTValueExtendedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCOUNTValueExtendedExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTValueExtendedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionField(v *s08.COUNTvalueExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCOUNTvalueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCOUNTvalueExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTvalueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionField(v *s08.COUNTvalueExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCOUNTvalueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCOUNTvalueExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTvalueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionField(v *s08.COUNTvaluePDCPSNlength18ExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionField(v *s08.COUNTvaluePDCPSNlength18ExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldReplay(v), *s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CSGIdListItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCSGIdListItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCSGIdListItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCSGIdListItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.CSGIdListItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCSGIdListItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCSGIdListItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCSGIdListItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CSGMembershipInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCSGMembershipInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCSGMembershipInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeCSGMembershipInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionField(v *s08.CSGMembershipInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCSGMembershipInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCSGMembershipInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeCSGMembershipInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CancelledCellinEAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCancelledCellinEAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCancelledCellinEAIItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCancelledCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.CancelledCellinEAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCancelledCellinEAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCancelledCellinEAIItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCancelledCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CancelledCellinTAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCancelledCellinTAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCancelledCellinTAIItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCancelledCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s08.CancelledCellinTAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCancelledCellinTAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCancelledCellinTAIItemExtIEsExtFieldFieldReplay(v), *s08.BridgeCancelledCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s08.Cdma2000OneXSRVCCInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionField(v *s08.Cdma2000OneXSRVCCInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldReplay(v), *s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CellBasedMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellBasedMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCellBasedMDTExtIEsExtFieldFieldReplay(v), *s08.BridgeCellBasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionField(v *s08.CellBasedMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellBasedMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCellBasedMDTExtIEsExtFieldFieldReplay(v), *s08.BridgeCellBasedMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s08.CellBasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellBasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s08.BridgeCellBasedQMCExtIEsExtFieldFieldReplay(v), *s08.BridgeCellBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s08.CellBasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellBasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s08.BridgeCellBasedQMCExtIEsExtFieldFieldReplay(v), *s08.BridgeCellBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CellIDBroadcastItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellIDBroadcastItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCellIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.CellIDBroadcastItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellIDBroadcastItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCellIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CellIDCancelledItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellIDCancelledItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCellIDCancelledItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.CellIDCancelledItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellIDCancelledItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCellIDCancelledItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(v *s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldReplay(v), *s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CellTypeExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCellTypeExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCellTypeExtIEsExtFieldFieldReplay(v), *s09.BridgeCellTypeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionField(v *s09.CellTypeExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCellTypeExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCellTypeExtIEsExtFieldFieldReplay(v), *s09.BridgeCellTypeExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CompletedCellinEAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCompletedCellinEAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.CompletedCellinEAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCompletedCellinEAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCompletedCellinEAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CompletedCellinTAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCompletedCellinTAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.CompletedCellinTAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCompletedCellinTAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCompletedCellinTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeConnectedengNBItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ConnectedengNBItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeConnectedengNBItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeConnectedengNBItemExtIEsExtFieldFieldReplay(v), *s09.BridgeConnectedengNBItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeConnectedengNBItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.ConnectedengNBItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeConnectedengNBItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeConnectedengNBItemExtIEsExtFieldFieldReplay(v), *s09.BridgeConnectedengNBItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ContextatSourceExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeContextatSourceExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeContextatSourceExtIEsExtFieldFieldReplay(v), *s09.BridgeContextatSourceExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionField(v *s09.ContextatSourceExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeContextatSourceExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeContextatSourceExtIEsExtFieldFieldReplay(v), *s09.BridgeContextatSourceExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s09.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsExtIEsValueCompareS1APProtocolExtensionField(v *s09.CriticalityDiagnosticsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldReplay(v), *s09.BridgeCriticalityDiagnosticsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.CriticalityDiagnosticsIEItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.CriticalityDiagnosticsIEItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldReplay(v), *s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s09.DAPSRequestInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDAPSRequestInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeDAPSRequestInfoExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSRequestInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionField(v *s09.DAPSRequestInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDAPSRequestInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeDAPSRequestInfoExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSRequestInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s09.DAPSResponseInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s03.BridgeDAPSResponseInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeDAPSResponseInfoExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSResponseInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionField(v *s09.DAPSResponseInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s03.BridgeDAPSResponseInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeDAPSResponseInfoExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSResponseInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionField(v *s09.DAPSResponseInfoItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeDAPSResponseInfoItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionField(v *s09.DAPSResponseInfoItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeDAPSResponseInfoItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldReplay(v), *s09.BridgeDAPSResponseInfoItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.DLCPSecurityInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeDLCPSecurityInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeDLCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeDLCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(v *s09.DLCPSecurityInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeDLCPSecurityInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeDLCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s09.BridgeDLCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// deactivateTraceIEValueProtocolOpenValue is the concrete protocolOpenValue[DeactivateTraceIEValue].
type DeactivateTraceIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.DeactivateTraceIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.DeactivateTraceIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(v *s09.DeactivateTraceIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s09.BridgeDeactivateTraceIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s09.BridgeDeactivateTraceIEFieldFieldReplay(v), *s09.BridgeDeactivateTraceIEFieldFieldWithoutReplay(v))
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(v *s09.DeactivateTraceIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s09.BridgeDeactivateTraceIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeDeactivateTraceIEFieldFieldReplay(v), *s09.BridgeDeactivateTraceIEFieldFieldWithoutReplay(v))
}

// downlinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkNonUEAssociatedLPPaTransportIEValue].
type DownlinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.DownlinkNonUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.DownlinkNonUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s09.DownlinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s09.DownlinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}

// downlinkUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkUEAssociatedLPPaTransportIEValue].
type DownlinkUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.DownlinkUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.DownlinkUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s09.DownlinkUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s09.DownlinkUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENBStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v), *s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENBStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENBStatusTransferTransparentContainerExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v), *s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENBX2ExtTLAExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENBX2ExtTLAExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENBX2ExtTLAExtIEsExtFieldFieldReplay(v), *s09.BridgeENBX2ExtTLAExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENBX2ExtTLAExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENBX2ExtTLAExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENBX2ExtTLAExtIEsExtFieldFieldReplay(v), *s09.BridgeENBX2ExtTLAExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENDCSONConfigurationTransferExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENDCSONConfigurationTransferExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENDCSONConfigurationTransferExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONeNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENDCSONeNBIdentificationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONeNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENDCSONeNBIdentificationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENDCSONeNBIdentificationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONeNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONengNBIdentificationExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENDCSONengNBIdentificationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCSONengNBIdentificationExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENDCSONengNBIdentificationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENDCSONengNBIdentificationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCSONengNBIdentificationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeReplyExtIEsValueCaptureS1APProtocolExtensionField(v *s09.ENDCTransferTypeReplyExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENDCTransferTypeReplyExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s09.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeReplyExtIEsValueCompareS1APProtocolExtensionField(v *s09.ENDCTransferTypeReplyExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENDCTransferTypeReplyExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s09.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldReplay(v), *s09.BridgeENDCTransferTypeReplyExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeRequestExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ENDCTransferTypeRequestExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeENDCTransferTypeRequestExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldReplay(v), *s10.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeENDCTransferTypeRequestExtIEsValueCompareS1APProtocolExtensionField(v *s10.ENDCTransferTypeRequestExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeENDCTransferTypeRequestExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldReplay(v), *s10.BridgeENDCTransferTypeRequestExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABAdmittedItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABAdmittedItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABAdmittedItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABAdmittedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABAdmittedItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABAdmittedItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABAdmittedItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABAdmittedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABDataForwardingItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABDataForwardingItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABDataForwardingItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABDataForwardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABDataForwardingItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABDataForwardingItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABDataForwardingItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABDataForwardingItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABFailedToResumeItemResumeReqExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABFailedToResumeItemResumeReqExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABFailedToResumeItemResumeResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABFailedToResumeItemResumeResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABFailedToResumeItemResumeResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABFailedToSetupItemHOReqAckExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldReplay(v), *s10.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABItemExtIEsExtFieldFieldWithoutReplay(v))
}

// eRABQoSParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ERABQoSParametersExtIEsValue].
type ERABQoSParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.ERABQoSParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.ERABQoSParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABQoSParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s10.BridgeERABQoSParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABQoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgeERABQoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABQoSParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s10.BridgeERABQoSParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABQoSParametersExtIEsExtFieldFieldReplay(v), *s10.BridgeERABQoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABModifyItemBearerModConfExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldReplay(v), *s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABModifyItemBearerModConfExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABModifyItemBearerModConfExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldReplay(v), *s10.BridgeERABModifyItemBearerModConfExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABModifyItemBearerModResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABModifyItemBearerModResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABModifyItemBearerModResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABModifyItemBearerModResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABModifyItemBearerModResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABNotToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s10.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABReleaseItemBearerRelCompExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldReplay(v), *s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABReleaseItemBearerRelCompExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABReleaseItemBearerRelCompExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldReplay(v), *s10.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSecurityResultItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABSecurityResultItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABSecurityResultItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABSecurityResultItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSecurityResultItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSecurityResultItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABSecurityResultItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABSecurityResultItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABSecurityResultItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSecurityResultItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABSetupItemBearerSUResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABSetupItemBearerSUResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABSetupItemBearerSUResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSetupItemBearerSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABSetupItemCtxtSUResExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABSetupItemCtxtSUResExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABSetupItemCtxtSUResExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldReplay(v), *s10.BridgeERABSetupItemCtxtSUResExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABToBeModifiedItemBearerModIndExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABToBeSwitchedULItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABToBeSwitchedULItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeSwitchedULItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeUpdatedItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABToBeUpdatedItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABToBeUpdatedItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABToBeUpdatedItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABToBeUpdatedItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABToBeUpdatedItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABToBeUpdatedItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ERABUsageReportItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeERABUsageReportItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeERABUsageReportItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ERABUsageReportItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeERABUsageReportItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeERABUsageReportItemExtIEsExtFieldFieldReplay(v), *s10.BridgeERABUsageReportItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionField(v *s10.EUTRANCGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEUTRANCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeEUTRANCGIExtIEsExtFieldFieldReplay(v), *s10.BridgeEUTRANCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionField(v *s10.EUTRANCGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEUTRANCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeEUTRANCGIExtIEsExtFieldFieldReplay(v), *s10.BridgeEUTRANCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.EmergencyAreaIDBroadcastItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.EmergencyAreaIDBroadcastItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldReplay(v), *s10.BridgeEmergencyAreaIDBroadcastItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.EmergencyAreaIDCancelledItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldReplay(v), *s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.EmergencyAreaIDCancelledItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldReplay(v), *s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionField(v *s10.EventL1LoggedMDTConfigExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldReplay(v), *s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionField(v *s10.EventL1LoggedMDTConfigExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEventL1LoggedMDTConfigExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldReplay(v), *s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEField(v *s10.EventTriggerExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s04.BridgeEventTriggerExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s10.BridgeEventTriggerExtIEFieldFieldReplay(v), *s10.BridgeEventTriggerExtIEFieldFieldWithoutReplay(v))
}
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEField(v *s10.EventTriggerExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s04.BridgeEventTriggerExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeEventTriggerExtIEFieldFieldReplay(v), *s10.BridgeEventTriggerExtIEFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ExpectedUEActivityBehaviourExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldReplay(v), *s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionField(v *s10.ExpectedUEActivityBehaviourExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeExpectedUEActivityBehaviourExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldReplay(v), *s10.BridgeExpectedUEActivityBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ExpectedUEBehaviourExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeExpectedUEBehaviourExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeExpectedUEBehaviourExtIEsExtFieldFieldReplay(v), *s10.BridgeExpectedUEBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionField(v *s10.ExpectedUEBehaviourExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeExpectedUEBehaviourExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeExpectedUEBehaviourExtIEsExtFieldFieldReplay(v), *s10.BridgeExpectedUEBehaviourExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionField(v *s10.FiveGSTAIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeFiveGSTAIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeFiveGSTAIExtIEsExtFieldFieldReplay(v), *s10.BridgeFiveGSTAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionField(v *s10.FiveGSTAIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeFiveGSTAIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeFiveGSTAIExtIEsExtFieldFieldReplay(v), *s10.BridgeFiveGSTAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ForbiddenLAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeForbiddenLAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeForbiddenLAsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeForbiddenLAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ForbiddenLAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeForbiddenLAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeForbiddenLAsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeForbiddenLAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s10.ForbiddenTAsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeForbiddenTAsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s10.BridgeForbiddenTAsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeForbiddenTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionField(v *s10.ForbiddenTAsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeForbiddenTAsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s10.BridgeForbiddenTAsItemExtIEsExtFieldFieldReplay(v), *s10.BridgeForbiddenTAsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GBRQosInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGBRQosInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGBRQosInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeGBRQosInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.GBRQosInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGBRQosInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGBRQosInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeGBRQosInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GERANCellIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGERANCellIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGERANCellIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGERANCellIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.GERANCellIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGERANCellIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGERANCellIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGERANCellIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGNBExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GNBExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGNBExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGNBExtIEsExtFieldFieldReplay(v), *s11.BridgeGNBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGNBExtIEsValueCompareS1APProtocolExtensionField(v *s11.GNBExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGNBExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGNBExtIEsExtFieldFieldReplay(v), *s11.BridgeGNBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GUMMEIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGUMMEIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGUMMEIExtIEsExtFieldFieldReplay(v), *s11.BridgeGUMMEIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionField(v *s11.GUMMEIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGUMMEIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGUMMEIExtIEsExtFieldFieldReplay(v), *s11.BridgeGUMMEIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GlobalENBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGlobalENBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGlobalENBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalENBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.GlobalENBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGlobalENBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGlobalENBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalENBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GlobalEnGNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGlobalEnGNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGlobalEnGNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalEnGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.GlobalEnGNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGlobalEnGNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGlobalEnGNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalEnGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.GlobalGNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeGlobalGNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeGlobalGNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.GlobalGNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeGlobalGNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeGlobalGNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeGlobalGNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(v *s11.HandoverSuccessIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s11.BridgeHandoverSuccessIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s11.BridgeHandoverSuccessIEFieldFieldReplay(v), *s11.BridgeHandoverSuccessIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(v *s11.HandoverSuccessIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s11.BridgeHandoverSuccessIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s11.BridgeHandoverSuccessIEFieldFieldReplay(v), *s11.BridgeHandoverSuccessIEFieldFieldWithoutReplay(v))
}

// WUSAssistanceInformationExtIEsIEField uses the ProtocolIE-Field shape for object set WUS-Assistance-Information-ExtIEs of TS 36.413.
type WUSAssistanceInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         s08.WUSAssistanceInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WUSAssistanceInformationExtIEsIEField) WithoutReplay() WUSAssistanceInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *WUSAssistanceInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *WUSAssistanceInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if !s08.BridgeWUSAssistanceInformationExtIEsValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := s08.BridgeWUSAssistanceInformationExtIEsValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *WUSAssistanceInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WUSAssistanceInformationExtIEsIEField{}
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
	var zero s08.WUSAssistanceInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, s08.BridgeWUSAssistanceInformationExtIEsValueMethodReason(zero, v.Id), s08.BridgeWUSAssistanceInformationExtIEsValueMethodRule(zero))
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := s08.BridgeWUSAssistanceInformationExtIEsValueMethodDecode(zero, v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// WUSAssistanceInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set WUS-Assistance-Information-ExtIEs of TS 36.413: a list of WUSAssistanceInformationExtIEsIEField values.
type WUSAssistanceInformationExtIEsIEContainer []WUSAssistanceInformationExtIEsIEField

func BridgeDeactivateTraceIEValueCaptureS1APERABIEContainerList(v *s09.DeactivateTraceIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCompareS1APERABIEContainerList(v *s09.DeactivateTraceIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCaptureS1APERABIEContainerList(v *s10.EventTriggerExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCompareS1APERABIEContainerList(v *s10.EventTriggerExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCaptureS1APERABIEContainerList(v *s11.HandoverSuccessIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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

// WUSAssistanceInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[WUSAssistanceInformationExtIEsExtField].
type WUSAssistanceInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, error)
	encode  func(s14.WUSAssistanceInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s14.WUSAssistanceInformationExtIEsExtField, aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, aper.Snapshot)
	compare func(s14.WUSAssistanceInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WUSAssistanceInformationExtIEsExtFieldValueCodec) New(value s14.WUSAssistanceInformationExtIEsExtField) (WUSAssistanceInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WUSAssistanceInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WUSAssistanceInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WUSAssistanceInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WUSAssistanceInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WUSAssistanceInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WUSAssistanceInformationExtIEsExtFieldValueCodec) EncodeAPER(value WUSAssistanceInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WUSAssistanceInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value s14.WUSAssistanceInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WUSAssistanceInformationExtIEsExtFieldValueCodec) encodeChanged(value s14.WUSAssistanceInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WUSAssistanceInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[WUSAssistanceInformationExtIEsExtContainer].
type WUSAssistanceInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WUSAssistanceInformationExtIEsExtContainer, error)
	encode  func(WUSAssistanceInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WUSAssistanceInformationExtIEsExtContainer, aper.DecodeState) (WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot)
	compare func(WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WUSAssistanceInformationExtIEsExtContainerValueCodec) New(value WUSAssistanceInformationExtIEsExtContainer) (WUSAssistanceInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WUSAssistanceInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WUSAssistanceInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WUSAssistanceInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WUSAssistanceInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WUSAssistanceInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WUSAssistanceInformationExtIEsExtContainerValueCodec) EncodeAPER(value WUSAssistanceInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WUSAssistanceInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value WUSAssistanceInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WUSAssistanceInformationExtIEsExtContainerValueCodec) encodeChanged(value WUSAssistanceInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainer(v *s10.EventTriggerExtIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainer(v *s10.EventTriggerExtIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCaptureS1APProtocolErrorIEContainerList(v *s09.DeactivateTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCompareS1APProtocolErrorIEContainerList(v *s09.DeactivateTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s10.EventTriggerExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCompareS1APProtocolErrorIEContainerList(v *s10.EventTriggerExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCaptureS1APProtocolErrorIEContainerList(v *s11.HandoverSuccessIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainerList(v *s09.DeactivateTraceIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainerList(v *s09.DeactivateTraceIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCaptureS1APProtocolIEContainerList(v *s10.EventTriggerExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeEventTriggerExtIEValueCompareS1APProtocolIEContainerList(v *s10.EventTriggerExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainerList(v *s11.HandoverSuccessIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeDeactivateTraceIEValueCaptureS1APProtocolIESingleContainer(v *s09.DeactivateTraceIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDeactivateTraceIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDeactivateTraceIEValueCompareS1APProtocolIESingleContainer(v *s09.DeactivateTraceIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDeactivateTraceIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s09.DownlinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s09.DownlinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverSuccessIEValueCaptureS1APProtocolIESingleContainer(v *s11.HandoverSuccessIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}

// WUSAssistanceInformationExtIEsExtFieldAPERValue is the concrete APERValue[WUSAssistanceInformationExtIEsExtField].
type WUSAssistanceInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         s14.WUSAssistanceInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WUSAssistanceInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WUSAssistanceInformationExtIEsExtFieldAPERValue) WithoutReplay() WUSAssistanceInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WUSAssistanceInformationExtIEsExtContainerAPERValue is the concrete APERValue[WUSAssistanceInformationExtIEsExtContainer].
type WUSAssistanceInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WUSAssistanceInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WUSAssistanceInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WUSAssistanceInformationExtIEsExtContainerAPERValue) WithoutReplay() WUSAssistanceInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type WUSAssistanceInformationExtIETable struct{}

func WUSAssistanceInformationExtIEs() WUSAssistanceInformationExtIETable {
	return WUSAssistanceInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of WUSAssistanceInformationExtIETable.
func (WUSAssistanceInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WUS-Assistance-Information-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by WUSAssistanceInformationExtIETable.
func (WUSAssistanceInformationExtIETable) Table() s00.WUSAssistanceInformationExtIEsValueExtensionTable {
	return func() s00.WUSAssistanceInformationExtIEsValueExtensionTable {
		sealed := s00.WUSAssistanceInformationExtIEsValueExtensionTable{}
		*s00.BridgeWUSAssistanceInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in WUSAssistanceInformationExtIETable.
func (t WUSAssistanceInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (s14.WUSAssistanceInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s14.WUSAssistanceInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s14.WUSAssistanceInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s14.WUSAssistanceInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return s14.WUSAssistanceInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s08.WUSAssistanceInformationExtIEsValue {
			sealed := s08.WUSAssistanceInformationExtIEsValue{}
			*s08.BridgeWUSAssistanceInformationExtIEsValueFieldId(&sealed) = id
			*s08.BridgeWUSAssistanceInformationExtIEsValueFieldOpaque(&sealed) = opaque
			*s08.BridgeWUSAssistanceInformationExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCapture(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *func(WUSAssistanceInformationExtIEsExtContainer, aper.DecodeState) (WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCompare(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *func(WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldContext(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldDecode(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (WUSAssistanceInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldEncode(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *func(WUSAssistanceInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldPath(v *WUSAssistanceInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCapture(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *func(s14.WUSAssistanceInformationExtIEsExtField, aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCompare(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *func(s14.WUSAssistanceInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldContext(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldDecode(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldEncode(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *func(s14.WUSAssistanceInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldPath(v *WUSAssistanceInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
