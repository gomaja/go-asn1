// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s16 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s16

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	bits "math/bits"
)

func BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.InformationForCECapableUEsExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.InformationForCECapableUEsExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainer(v *s11.HandoverSuccessIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s15.BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.InterSystemMeasurementItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.InterSystemMeasurementItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.InterSystemMeasurementParametersExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.InterSystemMeasurementParametersExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.IntersystemMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.IntersystemMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.LAIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.LAIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.LTENTNTAIInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.LTENTNTAIInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.LastVisitedPSCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.LastVisitedPSCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.ListeningSubframePatternExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.ListeningSubframePatternExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.LoggedMBSFNMDTExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.LoggedMBSFNMDTExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M1PeriodicReportingExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M1PeriodicReportingExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M1ThresholdEventA2ExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M1ThresholdEventA2ExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M3ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M3ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M4ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M4ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M5ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M5ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M6ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M6ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.M7ConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.M7ConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.MBSFNResultToLogInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.MBSFNResultToLogInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(v *s11.MMECPRelocationIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(v *s11.MMECPRelocationIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.MutingPatternInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.MutingPatternInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(v *s12.NASDeliveryIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(v *s12.NASDeliveryIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NBIoTPagingEDRXInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NBIoTPagingEDRXInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NGENBExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNGENBExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NGENBExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NRCGIExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NRCGIExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NRUESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NRUESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.NRV2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.NRV2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PC5FlowBitRatesExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PC5FlowBitRatesExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PC5QoSFlowItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PC5QoSFlowItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PC5QoSParametersExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PLMNAreaBasedQMCExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PSCellInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PSCellInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PagingAttemptInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.PagingEDRXInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.PagingEDRXInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.ProSeAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.ProSeAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.RATRestrictionsItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.RATRestrictionsItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.RIMTransferExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.RIMTransferExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.RLFReportInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.RLFReportInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemExtIEsExtContainer is ProtocolExtensionContainer {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} of TS 36.413: a list of BearersSubjectToStatusTransferItemExtIEsExtField values.
type BearersSubjectToStatusTransferItemExtIEsExtContainer []BearersSubjectToStatusTransferItemExtIEsExtField

// BearersSubjectToStatusTransferItemExtIEsExtField is ProtocolExtensionField {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} of TS 36.413: an extension field.
type BearersSubjectToStatusTransferItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue BearersSubjectToStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtField) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemExtIEsExtField{}
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
	var zero BearersSubjectToStatusTransferItemExtIEsValue

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

// BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding binds COUNTValueExtended to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding struct {
	info   s00.ExtensionInfo
	codec  COUNTValueExtendedValueCodec
	inject func(COUNTValueExtended,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*COUNTValueExtended,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Codec() COUNTValueExtendedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) New(value COUNTValueExtended,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*COUNTValueExtended,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// COUNTValueExtendedValueCodec is the concrete ValueCodec[COUNTValueExtended].
type COUNTValueExtendedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (COUNTValueExtended,

		error)
	encode func(COUNTValueExtended,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(COUNTValueExtended, aper.DecodeState,

	) (COUNTValueExtended, aper.Snapshot,

	)
	compare func(COUNTValueExtended, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTValueExtendedValueCodec) New(value COUNTValueExtended,

) (COUNTValueExtendedAPERValue, error) {
	if c.encode == nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTValueExtendedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTValueExtendedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTValueExtendedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTValueExtendedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTValueExtendedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTValueExtendedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTValueExtendedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTValueExtendedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTValueExtendedValueCodec) EncodeAPER(value COUNTValueExtendedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c COUNTValueExtendedValueCodec) encodeBudgetValue(value COUNTValueExtended,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTValueExtendedValueCodec) encodeChanged(value COUNTValueExtended,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding binds ReceiveStatusOfULPDCPSDUsExtended to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec
	inject func(s00.ReceiveStatusOfULPDCPSDUsExtended,

	) BearersSubjectToStatusTransferItemExtIEsValue

	get func(*BearersSubjectToStatusTransferItemExtIEsValue,

	) (*s00.ReceiveStatusOfULPDCPSDUsExtended,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Codec() s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) New(value s00.ReceiveStatusOfULPDCPSDUsExtended,

) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) Get(field *BearersSubjectToStatusTransferItemExtIEsExtField) (*s00.ReceiveStatusOfULPDCPSDUsExtended,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// CNTypeRestrictionsValueCodec is the concrete ValueCodec[CNTypeRestrictions].
type CNTypeRestrictionsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictions,

		error)
	encode func(CNTypeRestrictions,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictions, aper.DecodeState,

	) (CNTypeRestrictions, aper.Snapshot,

	)
	compare func(CNTypeRestrictions, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsValueCodec) New(value CNTypeRestrictions,

) (CNTypeRestrictionsAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsValueCodec) EncodeAPER(value CNTypeRestrictionsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CNTypeRestrictionsValueCodec) encodeBudgetValue(value CNTypeRestrictions,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsValueCodec) encodeChanged(value CNTypeRestrictions,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BluetoothMeasurementConfigurationValueCodec is the concrete ValueCodec[BluetoothMeasurementConfiguration].
type BluetoothMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BluetoothMeasurementConfiguration,

		error)
	encode func(BluetoothMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BluetoothMeasurementConfiguration, aper.DecodeState,

	) (BluetoothMeasurementConfiguration, aper.Snapshot,

	)
	compare func(BluetoothMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BluetoothMeasurementConfigurationValueCodec) New(value BluetoothMeasurementConfiguration,

) (BluetoothMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BluetoothMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BluetoothMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BluetoothMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BluetoothMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BluetoothMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BluetoothMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BluetoothMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BluetoothMeasurementConfigurationValueCodec) EncodeAPER(value BluetoothMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BluetoothMeasurementConfigurationValueCodec) encodeBudgetValue(value BluetoothMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BluetoothMeasurementConfigurationValueCodec) encodeChanged(value BluetoothMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ActivatedCellsListValueCodec is the concrete ValueCodec[ActivatedCellsList].
type ActivatedCellsListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ActivatedCellsList,

		error)
	encode func(ActivatedCellsList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ActivatedCellsList, aper.DecodeState,

	) (ActivatedCellsList, aper.Snapshot,

	)
	compare func(ActivatedCellsList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ActivatedCellsListValueCodec) New(value ActivatedCellsList,

) (ActivatedCellsListAPERValue, error) {
	if c.encode == nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ActivatedCellsListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ActivatedCellsListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ActivatedCellsListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ActivatedCellsListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ActivatedCellsListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ActivatedCellsListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ActivatedCellsListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ActivatedCellsListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ActivatedCellsListValueCodec) EncodeAPER(value ActivatedCellsListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ActivatedCellsListValueCodec) encodeBudgetValue(value ActivatedCellsList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ActivatedCellsListValueCodec) encodeChanged(value ActivatedCellsList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ActivatedCellsListItemValueCodec is the concrete ValueCodec[ActivatedCellsListItem].
type ActivatedCellsListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ActivatedCellsListItem,

		error)
	encode func(ActivatedCellsListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ActivatedCellsListItem, aper.DecodeState,

	) (ActivatedCellsListItem, aper.Snapshot,

	)
	compare func(ActivatedCellsListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ActivatedCellsListItemValueCodec) New(value ActivatedCellsListItem,

) (ActivatedCellsListItemAPERValue, error) {
	if c.encode == nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ActivatedCellsListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ActivatedCellsListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ActivatedCellsListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ActivatedCellsListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ActivatedCellsListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ActivatedCellsListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ActivatedCellsListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ActivatedCellsListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ActivatedCellsListItemValueCodec) EncodeAPER(value ActivatedCellsListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ActivatedCellsListItemValueCodec) encodeBudgetValue(value ActivatedCellsListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ActivatedCellsListItemValueCodec) encodeChanged(value ActivatedCellsListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AllocationAndRetentionPriorityValueCodec is the concrete ValueCodec[AllocationAndRetentionPriority].
type AllocationAndRetentionPriorityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AllocationAndRetentionPriority,

		error)
	encode func(AllocationAndRetentionPriority,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AllocationAndRetentionPriority, aper.DecodeState,

	) (AllocationAndRetentionPriority, aper.Snapshot,

	)
	compare func(AllocationAndRetentionPriority, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AllocationAndRetentionPriorityValueCodec) New(value AllocationAndRetentionPriority,

) (AllocationAndRetentionPriorityAPERValue, error) {
	if c.encode == nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AllocationAndRetentionPriorityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AllocationAndRetentionPriorityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AllocationAndRetentionPriorityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AllocationAndRetentionPriorityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AllocationAndRetentionPriorityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AllocationAndRetentionPriorityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AllocationAndRetentionPriorityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AllocationAndRetentionPriorityValueCodec) EncodeAPER(value AllocationAndRetentionPriorityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AllocationAndRetentionPriorityValueCodec) encodeBudgetValue(value AllocationAndRetentionPriority,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AllocationAndRetentionPriorityValueCodec) encodeChanged(value AllocationAndRetentionPriority,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CGIValueCodec is the concrete ValueCodec[CGI].
type CGIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CGI,

		error)
	encode func(CGI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CGI, aper.DecodeState,

	) (CGI, aper.Snapshot,

	)
	compare func(CGI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CGIValueCodec) New(value CGI,

) (CGIAPERValue, error) {
	if c.encode == nil {
		return CGIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CGIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CGIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CGIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CGIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CGIValueCodec) EncodeAPER(value CGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CGIValueCodec) encodeBudgetValue(value CGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CGIValueCodec) encodeChanged(value CGI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CNTypeRestrictionsItemValueCodec is the concrete ValueCodec[CNTypeRestrictionsItem].
type CNTypeRestrictionsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CNTypeRestrictionsItem,

		error)
	encode func(CNTypeRestrictionsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CNTypeRestrictionsItem, aper.DecodeState,

	) (CNTypeRestrictionsItem, aper.Snapshot,

	)
	compare func(CNTypeRestrictionsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CNTypeRestrictionsItemValueCodec) New(value CNTypeRestrictionsItem,

) (CNTypeRestrictionsItemAPERValue, error) {
	if c.encode == nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CNTypeRestrictionsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CNTypeRestrictionsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CNTypeRestrictionsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CNTypeRestrictionsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CNTypeRestrictionsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CNTypeRestrictionsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CNTypeRestrictionsItemValueCodec) EncodeAPER(value CNTypeRestrictionsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CNTypeRestrictionsItemValueCodec) encodeBudgetValue(value CNTypeRestrictionsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CNTypeRestrictionsItemValueCodec) encodeChanged(value CNTypeRestrictionsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverSuccessIEs}} codec of TS 36.413.
func HandoverSuccessIEValueERABIEContainerListCodec(table s00.HandoverSuccessIEValueIETable) s11.HandoverSuccessIEValueERABIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.HandoverSuccessIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.HandoverSuccessIEValueERABIEContainerListValueCodec {
		sealed := s11.HandoverSuccessIEValueERABIEContainerListValueCodec{}
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "HandoverSuccessIEValueERABIEContainerList"
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.HandoverSuccessIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.HandoverSuccessIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.HandoverSuccessIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverSuccessIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.HandoverSuccessIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s11.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.HandoverSuccessIEValueERABIEContainerList, options aper.DecodeState) (s11.HandoverSuccessIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.HandoverSuccessIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeHandoverSuccessIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMECPRelocationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMECPRelocationIndicationIEs}} codec of TS 36.413.
func MMECPRelocationIndicationIEValueERABIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable) s12.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s12.MMECPRelocationIndicationIEValueERABIEContainerListValueCodec{}
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMECPRelocationIndicationIEValueERABIEContainerList"
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MMECPRelocationIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.MMECPRelocationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MMECPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s11.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MMECPRelocationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MMECPRelocationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMMECPRelocationIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MeasurementThresholdL1LoggedMDT-ExtIEs}} codec of TS 36.413.
func MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec {
		sealed := s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodec{}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList"
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.MeasurementThresholdL1LoggedMDTExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s12.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASDeliveryIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{NASDeliveryIndicationIEs}} codec of TS 36.413.
func NASDeliveryIndicationIEValueERABIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable) s12.NASDeliveryIndicationIEValueERABIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.NASDeliveryIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.NASDeliveryIndicationIEValueERABIEContainerListValueCodec {
		sealed := s12.NASDeliveryIndicationIEValueERABIEContainerListValueCodec{}
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "NASDeliveryIndicationIEValueERABIEContainerList"
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NASDeliveryIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NASDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASDeliveryIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.NASDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s12.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.NASDeliveryIndicationIEValueERABIEContainerList, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.NASDeliveryIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNASDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InformationForCECapableUEsExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{InformationForCECapableUEs-ExtIEs}} codec of TS 36.413.
func InformationForCECapableUEsExtIEsValueExtensionFieldTableCodec(table s00.InformationForCECapableUEsExtIEsValueExtensionTable) s11.InformationForCECapableUEsExtIEsExtFieldValueCodec {
	if !*s00.BridgeInformationForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InformationForCECapableUEsExtIEsExtFieldValueCodec{}
	}
	return func() s11.InformationForCECapableUEsExtIEsExtFieldValueCodec {
		sealed := s11.InformationForCECapableUEsExtIEsExtFieldValueCodec{}
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldPath(&sealed) = "InformationForCECapableUEsExtIEsExtField"
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InformationForCECapableUEsExtIEsExtField, error) {
			var field s11.InformationForCECapableUEsExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InformationForCECapableUEsExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InformationForCECapableUEsExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InformationForCECapableUEsExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.InformationForCECapableUEsExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.InformationForCECapableUEsExtIEsExtField, options aper.DecodeState) (s11.InformationForCECapableUEsExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.InformationForCECapableUEsExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{InformationOnRecommendedCellsAndENBsForPaging-ExtIEs}} codec of TS 36.413.
func InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionFieldTableCodec(table s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable) s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec {
	if !*s00.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec{}
	}
	return func() s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec {
		sealed := s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodec{}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldPath(&sealed) = "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField"
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, error) {
			var field s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, options aper.DecodeState) (s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InterSystemMeasurementItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{InterSystemMeasurementItem-ExtIEs}} codec of TS 36.413.
func InterSystemMeasurementItemExtIEsValueExtensionFieldTableCodec(table s00.InterSystemMeasurementItemExtIEsValueExtensionTable) s11.InterSystemMeasurementItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeInterSystemMeasurementItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InterSystemMeasurementItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.InterSystemMeasurementItemExtIEsExtFieldValueCodec {
		sealed := s11.InterSystemMeasurementItemExtIEsExtFieldValueCodec{}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "InterSystemMeasurementItemExtIEsExtField"
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InterSystemMeasurementItemExtIEsExtField, error) {
			var field s11.InterSystemMeasurementItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InterSystemMeasurementItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InterSystemMeasurementItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.InterSystemMeasurementItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.InterSystemMeasurementItemExtIEsExtField, options aper.DecodeState) (s11.InterSystemMeasurementItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.InterSystemMeasurementItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InterSystemMeasurementParametersExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{InterSystemMeasurementParameters-ExtIEs}} codec of TS 36.413.
func InterSystemMeasurementParametersExtIEsValueExtensionFieldTableCodec(table s00.InterSystemMeasurementParametersExtIEsValueExtensionTable) s11.InterSystemMeasurementParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgeInterSystemMeasurementParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InterSystemMeasurementParametersExtIEsExtFieldValueCodec{}
	}
	return func() s11.InterSystemMeasurementParametersExtIEsExtFieldValueCodec {
		sealed := s11.InterSystemMeasurementParametersExtIEsExtFieldValueCodec{}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldPath(&sealed) = "InterSystemMeasurementParametersExtIEsExtField"
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InterSystemMeasurementParametersExtIEsExtField, error) {
			var field s11.InterSystemMeasurementParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InterSystemMeasurementParametersExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementParametersExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InterSystemMeasurementParametersExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.InterSystemMeasurementParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.InterSystemMeasurementParametersExtIEsExtField, options aper.DecodeState) (s11.InterSystemMeasurementParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.InterSystemMeasurementParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IntersystemMeasurementConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{IntersystemMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func IntersystemMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable) s11.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeIntersystemMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.IntersystemMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "IntersystemMeasurementConfigurationExtIEsExtField"
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.IntersystemMeasurementConfigurationExtIEsExtField, error) {
			var field s11.IntersystemMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "IntersystemMeasurementConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "IntersystemMeasurementConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "IntersystemMeasurementConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.IntersystemMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.IntersystemMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s11.IntersystemMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.IntersystemMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LAIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LAI-ExtIEs}} codec of TS 36.413.
func LAIExtIEsValueExtensionFieldTableCodec(table s00.LAIExtIEsValueExtensionTable) s11.LAIExtIEsExtFieldValueCodec {
	if !*s00.BridgeLAIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LAIExtIEsExtFieldValueCodec{}
	}
	return func() s11.LAIExtIEsExtFieldValueCodec {
		sealed := s11.LAIExtIEsExtFieldValueCodec{}
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldPath(&sealed) = "LAIExtIEsExtField"
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LAIExtIEsExtField, error) {
			var field s11.LAIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LAIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LAIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LAIExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.LAIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.LAIExtIEsExtField, options aper.DecodeState) (s11.LAIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLAIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.LAIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLAIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLAIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LTENTNTAIInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LTE-NTN-TAI-Information-ExtIEs}} codec of TS 36.413.
func LTENTNTAIInformationExtIEsValueExtensionFieldTableCodec(table s00.LTENTNTAIInformationExtIEsValueExtensionTable) s11.LTENTNTAIInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeLTENTNTAIInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LTENTNTAIInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.LTENTNTAIInformationExtIEsExtFieldValueCodec {
		sealed := s11.LTENTNTAIInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "LTENTNTAIInformationExtIEsExtField"
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LTENTNTAIInformationExtIEsExtField, error) {
			var field s11.LTENTNTAIInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LTENTNTAIInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LTENTNTAIInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LTENTNTAIInformationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.LTENTNTAIInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.LTENTNTAIInformationExtIEsExtField, options aper.DecodeState) (s11.LTENTNTAIInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.LTENTNTAIInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LastVisitedPSCellInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LastVisitedPSCellInformation-ExtIEs}} codec of TS 36.413.
func LastVisitedPSCellInformationExtIEsValueExtensionFieldTableCodec(table s00.LastVisitedPSCellInformationExtIEsValueExtensionTable) s11.LastVisitedPSCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeLastVisitedPSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LastVisitedPSCellInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.LastVisitedPSCellInformationExtIEsExtFieldValueCodec {
		sealed := s11.LastVisitedPSCellInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "LastVisitedPSCellInformationExtIEsExtField"
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LastVisitedPSCellInformationExtIEsExtField, error) {
			var field s11.LastVisitedPSCellInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LastVisitedPSCellInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LastVisitedPSCellInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LastVisitedPSCellInformationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.LastVisitedPSCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.LastVisitedPSCellInformationExtIEsExtField, options aper.DecodeState) (s11.LastVisitedPSCellInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.LastVisitedPSCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ListeningSubframePatternExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ListeningSubframePattern-ExtIEs}} codec of TS 36.413.
func ListeningSubframePatternExtIEsValueExtensionFieldTableCodec(table s00.ListeningSubframePatternExtIEsValueExtensionTable) s11.ListeningSubframePatternExtIEsExtFieldValueCodec {
	if !*s00.BridgeListeningSubframePatternExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ListeningSubframePatternExtIEsExtFieldValueCodec{}
	}
	return func() s11.ListeningSubframePatternExtIEsExtFieldValueCodec {
		sealed := s11.ListeningSubframePatternExtIEsExtFieldValueCodec{}
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldPath(&sealed) = "ListeningSubframePatternExtIEsExtField"
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ListeningSubframePatternExtIEsExtField, error) {
			var field s11.ListeningSubframePatternExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ListeningSubframePatternExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ListeningSubframePatternExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ListeningSubframePatternExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.ListeningSubframePatternExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.ListeningSubframePatternExtIEsExtField, options aper.DecodeState) (s11.ListeningSubframePatternExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.ListeningSubframePatternExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeListeningSubframePatternExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LoggedMBSFNMDTExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{LoggedMBSFNMDT-ExtIEs}} codec of TS 36.413.
func LoggedMBSFNMDTExtIEsValueExtensionFieldTableCodec(table s00.LoggedMBSFNMDTExtIEsValueExtensionTable) s11.LoggedMBSFNMDTExtIEsExtFieldValueCodec {
	if !*s00.BridgeLoggedMBSFNMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LoggedMBSFNMDTExtIEsExtFieldValueCodec{}
	}
	return func() s11.LoggedMBSFNMDTExtIEsExtFieldValueCodec {
		sealed := s11.LoggedMBSFNMDTExtIEsExtFieldValueCodec{}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldPath(&sealed) = "LoggedMBSFNMDTExtIEsExtField"
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LoggedMBSFNMDTExtIEsExtField, error) {
			var field s11.LoggedMBSFNMDTExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "LoggedMBSFNMDTExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "LoggedMBSFNMDTExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "LoggedMBSFNMDTExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.LoggedMBSFNMDTExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.LoggedMBSFNMDTExtIEsExtField, options aper.DecodeState) (s11.LoggedMBSFNMDTExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.LoggedMBSFNMDTExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M1PeriodicReportingExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M1PeriodicReporting-ExtIEs}} codec of TS 36.413.
func M1PeriodicReportingExtIEsValueExtensionFieldTableCodec(table s00.M1PeriodicReportingExtIEsValueExtensionTable) s11.M1PeriodicReportingExtIEsExtFieldValueCodec {
	if !*s00.BridgeM1PeriodicReportingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M1PeriodicReportingExtIEsExtFieldValueCodec{}
	}
	return func() s11.M1PeriodicReportingExtIEsExtFieldValueCodec {
		sealed := s11.M1PeriodicReportingExtIEsExtFieldValueCodec{}
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldPath(&sealed) = "M1PeriodicReportingExtIEsExtField"
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M1PeriodicReportingExtIEsExtField, error) {
			var field s11.M1PeriodicReportingExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M1PeriodicReportingExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M1PeriodicReportingExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M1PeriodicReportingExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M1PeriodicReportingExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M1PeriodicReportingExtIEsExtField, options aper.DecodeState) (s11.M1PeriodicReportingExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M1PeriodicReportingExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M1ThresholdEventA2ExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M1ThresholdEventA2-ExtIEs}} codec of TS 36.413.
func M1ThresholdEventA2ExtIEsValueExtensionFieldTableCodec(table s00.M1ThresholdEventA2ExtIEsValueExtensionTable) s11.M1ThresholdEventA2ExtIEsExtFieldValueCodec {
	if !*s00.BridgeM1ThresholdEventA2ExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M1ThresholdEventA2ExtIEsExtFieldValueCodec{}
	}
	return func() s11.M1ThresholdEventA2ExtIEsExtFieldValueCodec {
		sealed := s11.M1ThresholdEventA2ExtIEsExtFieldValueCodec{}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldPath(&sealed) = "M1ThresholdEventA2ExtIEsExtField"
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M1ThresholdEventA2ExtIEsExtField, error) {
			var field s11.M1ThresholdEventA2ExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M1ThresholdEventA2ExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M1ThresholdEventA2ExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M1ThresholdEventA2ExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M1ThresholdEventA2ExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M1ThresholdEventA2ExtIEsExtField, options aper.DecodeState) (s11.M1ThresholdEventA2ExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M1ThresholdEventA2ExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M3ConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M3Configuration-ExtIEs}} codec of TS 36.413.
func M3ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M3ConfigurationExtIEsValueExtensionTable) s11.M3ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM3ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M3ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.M3ConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.M3ConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "M3ConfigurationExtIEsExtField"
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M3ConfigurationExtIEsExtField, error) {
			var field s11.M3ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M3ConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M3ConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M3ConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M3ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M3ConfigurationExtIEsExtField, options aper.DecodeState) (s11.M3ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M3ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM3ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M4ConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M4Configuration-ExtIEs}} codec of TS 36.413.
func M4ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M4ConfigurationExtIEsValueExtensionTable) s11.M4ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM4ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M4ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.M4ConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.M4ConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "M4ConfigurationExtIEsExtField"
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M4ConfigurationExtIEsExtField, error) {
			var field s11.M4ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M4ConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M4ConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M4ConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M4ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M4ConfigurationExtIEsExtField, options aper.DecodeState) (s11.M4ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M4ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM4ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M5ConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M5Configuration-ExtIEs}} codec of TS 36.413.
func M5ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M5ConfigurationExtIEsValueExtensionTable) s11.M5ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM5ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M5ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.M5ConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.M5ConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "M5ConfigurationExtIEsExtField"
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M5ConfigurationExtIEsExtField, error) {
			var field s11.M5ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M5ConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M5ConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M5ConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M5ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M5ConfigurationExtIEsExtField, options aper.DecodeState) (s11.M5ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M5ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM5ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M6ConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M6Configuration-ExtIEs}} codec of TS 36.413.
func M6ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M6ConfigurationExtIEsValueExtensionTable) s11.M6ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM6ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M6ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.M6ConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.M6ConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "M6ConfigurationExtIEsExtField"
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M6ConfigurationExtIEsExtField, error) {
			var field s11.M6ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M6ConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M6ConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M6ConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M6ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M6ConfigurationExtIEsExtField, options aper.DecodeState) (s11.M6ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M6ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM6ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M7ConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{M7Configuration-ExtIEs}} codec of TS 36.413.
func M7ConfigurationExtIEsValueExtensionFieldTableCodec(table s00.M7ConfigurationExtIEsValueExtensionTable) s11.M7ConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeM7ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M7ConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s11.M7ConfigurationExtIEsExtFieldValueCodec {
		sealed := s11.M7ConfigurationExtIEsExtFieldValueCodec{}
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "M7ConfigurationExtIEsExtField"
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M7ConfigurationExtIEsExtField, error) {
			var field s11.M7ConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "M7ConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "M7ConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "M7ConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.M7ConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.M7ConfigurationExtIEsExtField, options aper.DecodeState) (s11.M7ConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.M7ConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM7ConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MBSFNResultToLogInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{MBSFN-ResultToLogInfo-ExtIEs}} codec of TS 36.413.
func MBSFNResultToLogInfoExtIEsValueExtensionFieldTableCodec(table s00.MBSFNResultToLogInfoExtIEsValueExtensionTable) s11.MBSFNResultToLogInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeMBSFNResultToLogInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.MBSFNResultToLogInfoExtIEsExtFieldValueCodec{}
	}
	return func() s11.MBSFNResultToLogInfoExtIEsExtFieldValueCodec {
		sealed := s11.MBSFNResultToLogInfoExtIEsExtFieldValueCodec{}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "MBSFNResultToLogInfoExtIEsExtField"
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.MBSFNResultToLogInfoExtIEsExtField, error) {
			var field s11.MBSFNResultToLogInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MBSFNResultToLogInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MBSFNResultToLogInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MBSFNResultToLogInfoExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.MBSFNResultToLogInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.MBSFNResultToLogInfoExtIEsExtField, options aper.DecodeState) (s11.MBSFNResultToLogInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.MBSFNResultToLogInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MutingPatternInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{MutingPatternInformation-ExtIEs}} codec of TS 36.413.
func MutingPatternInformationExtIEsValueExtensionFieldTableCodec(table s00.MutingPatternInformationExtIEsValueExtensionTable) s12.MutingPatternInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeMutingPatternInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.MutingPatternInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.MutingPatternInformationExtIEsExtFieldValueCodec {
		sealed := s12.MutingPatternInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "MutingPatternInformationExtIEsExtField"
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MutingPatternInformationExtIEsExtField, error) {
			var field s12.MutingPatternInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MutingPatternInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MutingPatternInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MutingPatternInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.MutingPatternInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.MutingPatternInformationExtIEsExtField, options aper.DecodeState) (s12.MutingPatternInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.MutingPatternInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMutingPatternInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NBIoTPagingEDRXInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NB-IoT-Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func NBIoTPagingEDRXInformationExtIEsValueExtensionFieldTableCodec(table s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable) s12.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeNBIoTPagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec {
		sealed := s12.NBIoTPagingEDRXInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "NBIoTPagingEDRXInformationExtIEsExtField"
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NBIoTPagingEDRXInformationExtIEsExtField, error) {
			var field s12.NBIoTPagingEDRXInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NBIoTPagingEDRXInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NBIoTPagingEDRXInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NBIoTPagingEDRXInformationExtIEsExtField, options aper.DecodeState) (s12.NBIoTPagingEDRXInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NBIoTPagingEDRXInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NGENBExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NG-eNB-ExtIEs}} codec of TS 36.413.
func NGENBExtIEsValueExtensionFieldTableCodec(table s00.NGENBExtIEsValueExtensionTable) s12.NGENBExtIEsExtFieldValueCodec {
	if !*s00.BridgeNGENBExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NGENBExtIEsExtFieldValueCodec{}
	}
	return func() s12.NGENBExtIEsExtFieldValueCodec {
		sealed := s12.NGENBExtIEsExtFieldValueCodec{}
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldPath(&sealed) = "NGENBExtIEsExtField"
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NGENBExtIEsExtField, error) {
			var field s12.NGENBExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NGENBExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NGENBExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NGENBExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NGENBExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NGENBExtIEsExtField, options aper.DecodeState) (s12.NGENBExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NGENBExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNGENBExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNGENBExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRCGIExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NR-CGI-ExtIEs}} codec of TS 36.413.
func NRCGIExtIEsValueExtensionFieldTableCodec(table s00.NRCGIExtIEsValueExtensionTable) s12.NRCGIExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRCGIExtIEsExtFieldValueCodec{}
	}
	return func() s12.NRCGIExtIEsExtFieldValueCodec {
		sealed := s12.NRCGIExtIEsExtFieldValueCodec{}
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldPath(&sealed) = "NRCGIExtIEsExtField"
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRCGIExtIEsExtField, error) {
			var field s12.NRCGIExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NRCGIExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRCGIExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NRCGIExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NRCGIExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NRCGIExtIEsExtField, options aper.DecodeState) (s12.NRCGIExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NRCGIExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRCGIExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRUESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NRUESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func NRUESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec(table s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable) s12.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec{}
	}
	return func() s12.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec {
		sealed := s12.NRUESecurityCapabilitiesExtIEsExtFieldValueCodec{}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldPath(&sealed) = "NRUESecurityCapabilitiesExtIEsExtField"
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRUESecurityCapabilitiesExtIEsExtField, error) {
			var field s12.NRUESecurityCapabilitiesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NRUESecurityCapabilitiesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRUESecurityCapabilitiesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NRUESecurityCapabilitiesExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NRUESecurityCapabilitiesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NRUESecurityCapabilitiesExtIEsExtField, options aper.DecodeState) (s12.NRUESecurityCapabilitiesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NRUESecurityCapabilitiesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NRUESidelinkAggregateMaximumBitrate-ExtIEs}} codec of TS 36.413.
func NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionFieldTableCodec(table s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable) s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec{}
	}
	return func() s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec {
		sealed := s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodec{}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrateExtIEsExtField"
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, error) {
			var field s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrateExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRUESidelinkAggregateMaximumBitrateExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrateExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, options aper.DecodeState) (s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRV2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{NRV2XServicesAuthorized-ExtIEs}} codec of TS 36.413.
func NRV2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable) s12.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeNRV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s12.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec {
		sealed := s12.NRV2XServicesAuthorizedExtIEsExtFieldValueCodec{}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorizedExtIEsExtField"
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRV2XServicesAuthorizedExtIEsExtField, error) {
			var field s12.NRV2XServicesAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NRV2XServicesAuthorizedExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRV2XServicesAuthorizedExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NRV2XServicesAuthorizedExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.NRV2XServicesAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.NRV2XServicesAuthorizedExtIEsExtField, options aper.DecodeState) (s12.NRV2XServicesAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.NRV2XServicesAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PC5FlowBitRatesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PC5FlowBitRates-ExtIEs}} codec of TS 36.413.
func PC5FlowBitRatesExtIEsValueExtensionFieldTableCodec(table s00.PC5FlowBitRatesExtIEsValueExtensionTable) s12.PC5FlowBitRatesExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5FlowBitRatesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5FlowBitRatesExtIEsExtFieldValueCodec{}
	}
	return func() s12.PC5FlowBitRatesExtIEsExtFieldValueCodec {
		sealed := s12.PC5FlowBitRatesExtIEsExtFieldValueCodec{}
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldPath(&sealed) = "PC5FlowBitRatesExtIEsExtField"
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5FlowBitRatesExtIEsExtField, error) {
			var field s12.PC5FlowBitRatesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5FlowBitRatesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5FlowBitRatesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5FlowBitRatesExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PC5FlowBitRatesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PC5FlowBitRatesExtIEsExtField, options aper.DecodeState) (s12.PC5FlowBitRatesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PC5FlowBitRatesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSFlowItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PC5QoSFlowItem-ExtIEs}} codec of TS 36.413.
func PC5QoSFlowItemExtIEsValueExtensionFieldTableCodec(table s00.PC5QoSFlowItemExtIEsValueExtensionTable) s12.PC5QoSFlowItemExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5QoSFlowItemExtIEsExtFieldValueCodec{}
	}
	return func() s12.PC5QoSFlowItemExtIEsExtFieldValueCodec {
		sealed := s12.PC5QoSFlowItemExtIEsExtFieldValueCodec{}
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "PC5QoSFlowItemExtIEsExtField"
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5QoSFlowItemExtIEsExtField, error) {
			var field s12.PC5QoSFlowItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5QoSFlowItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5QoSFlowItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5QoSFlowItemExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PC5QoSFlowItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PC5QoSFlowItemExtIEsExtField, options aper.DecodeState) (s12.PC5QoSFlowItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PC5QoSFlowItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSParametersExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PC5QoSParameters-ExtIEs}} codec of TS 36.413.
func PC5QoSParametersExtIEsValueExtensionFieldTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable) s12.PC5QoSParametersExtIEsExtFieldValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5QoSParametersExtIEsExtFieldValueCodec{}
	}
	return func() s12.PC5QoSParametersExtIEsExtFieldValueCodec {
		sealed := s12.PC5QoSParametersExtIEsExtFieldValueCodec{}
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldPath(&sealed) = "PC5QoSParametersExtIEsExtField"
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5QoSParametersExtIEsExtField, error) {
			var field s12.PC5QoSParametersExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5QoSParametersExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5QoSParametersExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PC5QoSParametersExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PC5QoSParametersExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PC5QoSParametersExtIEsExtField, options aper.DecodeState) (s12.PC5QoSParametersExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PC5QoSParametersExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5QoSParametersExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PLMNAreaBasedQMC-ExtIEs}} codec of TS 36.413.
func PLMNAreaBasedQMCExtIEsValueExtensionFieldTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable) s12.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
	}
	return func() s12.PLMNAreaBasedQMCExtIEsExtFieldValueCodec {
		sealed := s12.PLMNAreaBasedQMCExtIEsExtFieldValueCodec{}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldPath(&sealed) = "PLMNAreaBasedQMCExtIEsExtField"
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PLMNAreaBasedQMCExtIEsExtField, error) {
			var field s12.PLMNAreaBasedQMCExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PLMNAreaBasedQMCExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PLMNAreaBasedQMCExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PLMNAreaBasedQMCExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PLMNAreaBasedQMCExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PLMNAreaBasedQMCExtIEsExtField, options aper.DecodeState) (s12.PLMNAreaBasedQMCExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PLMNAreaBasedQMCExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PSCellInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PSCellInformation-ExtIEs}} codec of TS 36.413.
func PSCellInformationExtIEsValueExtensionFieldTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable) s12.PSCellInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PSCellInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.PSCellInformationExtIEsExtFieldValueCodec {
		sealed := s12.PSCellInformationExtIEsExtFieldValueCodec{}
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "PSCellInformationExtIEsExtField"
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PSCellInformationExtIEsExtField, error) {
			var field s12.PSCellInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PSCellInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PSCellInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PSCellInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PSCellInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PSCellInformationExtIEsExtField, options aper.DecodeState) (s12.PSCellInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PSCellInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePSCellInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingAttemptInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{PagingAttemptInformation-ExtIEs}} codec of TS 36.413.
func PagingAttemptInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable) s12.PagingAttemptInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PagingAttemptInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.PagingAttemptInformationExtIEsExtFieldValueCodec {
		sealed := s12.PagingAttemptInformationExtIEsExtFieldValueCodec{}
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "PagingAttemptInformationExtIEsExtField"
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PagingAttemptInformationExtIEsExtField, error) {
			var field s12.PagingAttemptInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PagingAttemptInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingAttemptInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PagingAttemptInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PagingAttemptInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PagingAttemptInformationExtIEsExtField, options aper.DecodeState) (s12.PagingAttemptInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PagingAttemptInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePagingAttemptInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingEDRXInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func PagingEDRXInformationExtIEsValueExtensionFieldTableCodec(table s00.PagingEDRXInformationExtIEsValueExtensionTable) s12.PagingEDRXInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PagingEDRXInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.PagingEDRXInformationExtIEsExtFieldValueCodec {
		sealed := s12.PagingEDRXInformationExtIEsExtFieldValueCodec{}
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "PagingEDRXInformationExtIEsExtField"
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PagingEDRXInformationExtIEsExtField, error) {
			var field s12.PagingEDRXInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "PagingEDRXInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingEDRXInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "PagingEDRXInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.PagingEDRXInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.PagingEDRXInformationExtIEsExtField, options aper.DecodeState) (s12.PagingEDRXInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.PagingEDRXInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePagingEDRXInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProSeAuthorizedExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ProSeAuthorized-ExtIEs}} codec of TS 36.413.
func ProSeAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.ProSeAuthorizedExtIEsValueExtensionTable) s12.ProSeAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeProSeAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ProSeAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s12.ProSeAuthorizedExtIEsExtFieldValueCodec {
		sealed := s12.ProSeAuthorizedExtIEsExtFieldValueCodec{}
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldPath(&sealed) = "ProSeAuthorizedExtIEsExtField"
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ProSeAuthorizedExtIEsExtField, error) {
			var field s12.ProSeAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ProSeAuthorizedExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ProSeAuthorizedExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ProSeAuthorizedExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.ProSeAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.ProSeAuthorizedExtIEsExtField, options aper.DecodeState) (s12.ProSeAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.ProSeAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeProSeAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RATRestrictionsItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RAT-RestrictionsItem-ExtIEs}} codec of TS 36.413.
func RATRestrictionsItemExtIEsValueExtensionFieldTableCodec(table s00.RATRestrictionsItemExtIEsValueExtensionTable) s12.RATRestrictionsItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeRATRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RATRestrictionsItemExtIEsExtFieldValueCodec{}
	}
	return func() s12.RATRestrictionsItemExtIEsExtFieldValueCodec {
		sealed := s12.RATRestrictionsItemExtIEsExtFieldValueCodec{}
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "RATRestrictionsItemExtIEsExtField"
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RATRestrictionsItemExtIEsExtField, error) {
			var field s12.RATRestrictionsItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RATRestrictionsItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RATRestrictionsItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RATRestrictionsItemExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.RATRestrictionsItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.RATRestrictionsItemExtIEsExtField, options aper.DecodeState) (s12.RATRestrictionsItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.RATRestrictionsItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RIMTransferExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RIMTransfer-ExtIEs}} codec of TS 36.413.
func RIMTransferExtIEsValueExtensionFieldTableCodec(table s00.RIMTransferExtIEsValueExtensionTable) s12.RIMTransferExtIEsExtFieldValueCodec {
	if !*s00.BridgeRIMTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RIMTransferExtIEsExtFieldValueCodec{}
	}
	return func() s12.RIMTransferExtIEsExtFieldValueCodec {
		sealed := s12.RIMTransferExtIEsExtFieldValueCodec{}
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldPath(&sealed) = "RIMTransferExtIEsExtField"
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RIMTransferExtIEsExtField, error) {
			var field s12.RIMTransferExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RIMTransferExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RIMTransferExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RIMTransferExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.RIMTransferExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.RIMTransferExtIEsExtField, options aper.DecodeState) (s12.RIMTransferExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.RIMTransferExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRIMTransferExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RLFReportInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{RLFReportInformation-ExtIEs}} codec of TS 36.413.
func RLFReportInformationExtIEsValueExtensionFieldTableCodec(table s00.RLFReportInformationExtIEsValueExtensionTable) s12.RLFReportInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeRLFReportInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RLFReportInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.RLFReportInformationExtIEsExtFieldValueCodec {
		sealed := s12.RLFReportInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "RLFReportInformationExtIEsExtField"
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RLFReportInformationExtIEsExtField, error) {
			var field s12.RLFReportInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "RLFReportInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "RLFReportInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "RLFReportInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.RLFReportInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.RLFReportInformationExtIEsExtField, options aper.DecodeState) (s12.RLFReportInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.RLFReportInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRLFReportInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InformationForCECapableUEsExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{InformationForCECapableUEs-ExtIEs}} codec of TS 36.413.
func InformationForCECapableUEsExtIEsValueExtensionTableCodec(table s00.InformationForCECapableUEsExtIEsValueExtensionTable, bounds aper.ListBounds) s11.InformationForCECapableUEsExtIEsExtContainerValueCodec {
	if !*s00.BridgeInformationForCECapableUEsExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InformationForCECapableUEsExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.InformationForCECapableUEsExtIEsExtContainerValueCodec {
		sealed := s11.InformationForCECapableUEsExtIEsExtContainerValueCodec{}
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldPath(&sealed) = "InformationForCECapableUEsExtIEsExtContainer"
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InformationForCECapableUEsExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.InformationForCECapableUEsExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.InformationForCECapableUEsExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InformationForCECapableUEsExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InformationForCECapableUEsExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InformationForCECapableUEsExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.InformationForCECapableUEsExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.InformationForCECapableUEsExtIEsExtContainer, options aper.DecodeState) (s11.InformationForCECapableUEsExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.InformationForCECapableUEsExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInformationForCECapableUEsExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{InformationOnRecommendedCellsAndENBsForPaging-ExtIEs}} codec of TS 36.413.
func InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableCodec(table s00.InformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTable, bounds aper.ListBounds) s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec {
	if !*s00.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec {
		sealed := s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodec{}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldPath(&sealed) = "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer"
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, options aper.DecodeState) (s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InterSystemMeasurementItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{InterSystemMeasurementItem-ExtIEs}} codec of TS 36.413.
func InterSystemMeasurementItemExtIEsValueExtensionTableCodec(table s00.InterSystemMeasurementItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.InterSystemMeasurementItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeInterSystemMeasurementItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InterSystemMeasurementItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.InterSystemMeasurementItemExtIEsExtContainerValueCodec {
		sealed := s11.InterSystemMeasurementItemExtIEsExtContainerValueCodec{}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "InterSystemMeasurementItemExtIEsExtContainer"
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InterSystemMeasurementItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.InterSystemMeasurementItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.InterSystemMeasurementItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InterSystemMeasurementItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InterSystemMeasurementItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.InterSystemMeasurementItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.InterSystemMeasurementItemExtIEsExtContainer, options aper.DecodeState) (s11.InterSystemMeasurementItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.InterSystemMeasurementItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInterSystemMeasurementItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InterSystemMeasurementParametersExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{InterSystemMeasurementParameters-ExtIEs}} codec of TS 36.413.
func InterSystemMeasurementParametersExtIEsValueExtensionTableCodec(table s00.InterSystemMeasurementParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s11.InterSystemMeasurementParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgeInterSystemMeasurementParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s11.InterSystemMeasurementParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.InterSystemMeasurementParametersExtIEsExtContainerValueCodec {
		sealed := s11.InterSystemMeasurementParametersExtIEsExtContainerValueCodec{}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldPath(&sealed) = "InterSystemMeasurementParametersExtIEsExtContainer"
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.InterSystemMeasurementParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.InterSystemMeasurementParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.InterSystemMeasurementParametersExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InterSystemMeasurementParametersExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementParametersExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InterSystemMeasurementParametersExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.InterSystemMeasurementParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.InterSystemMeasurementParametersExtIEsExtContainer, options aper.DecodeState) (s11.InterSystemMeasurementParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.InterSystemMeasurementParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeInterSystemMeasurementParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// IntersystemMeasurementConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{IntersystemMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func IntersystemMeasurementConfigurationExtIEsValueExtensionTableCodec(table s00.IntersystemMeasurementConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeIntersystemMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.IntersystemMeasurementConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "IntersystemMeasurementConfigurationExtIEsExtContainer"
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.IntersystemMeasurementConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.IntersystemMeasurementConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.IntersystemMeasurementConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "IntersystemMeasurementConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "IntersystemMeasurementConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "IntersystemMeasurementConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.IntersystemMeasurementConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.IntersystemMeasurementConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.IntersystemMeasurementConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.IntersystemMeasurementConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeIntersystemMeasurementConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LAIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LAI-ExtIEs}} codec of TS 36.413.
func LAIExtIEsValueExtensionTableCodec(table s00.LAIExtIEsValueExtensionTable, bounds aper.ListBounds) s11.LAIExtIEsExtContainerValueCodec {
	if !*s00.BridgeLAIExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LAIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.LAIExtIEsExtContainerValueCodec {
		sealed := s11.LAIExtIEsExtContainerValueCodec{}
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldPath(&sealed) = "LAIExtIEsExtContainer"
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LAIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.LAIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.LAIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LAIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LAIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LAIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.LAIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.LAIExtIEsExtContainer, options aper.DecodeState) (s11.LAIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.LAIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLAIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LTENTNTAIInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LTE-NTN-TAI-Information-ExtIEs}} codec of TS 36.413.
func LTENTNTAIInformationExtIEsValueExtensionTableCodec(table s00.LTENTNTAIInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.LTENTNTAIInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeLTENTNTAIInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LTENTNTAIInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.LTENTNTAIInformationExtIEsExtContainerValueCodec {
		sealed := s11.LTENTNTAIInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "LTENTNTAIInformationExtIEsExtContainer"
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LTENTNTAIInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.LTENTNTAIInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.LTENTNTAIInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LTENTNTAIInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LTENTNTAIInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LTENTNTAIInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.LTENTNTAIInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.LTENTNTAIInformationExtIEsExtContainer, options aper.DecodeState) (s11.LTENTNTAIInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.LTENTNTAIInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLTENTNTAIInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LastVisitedPSCellInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LastVisitedPSCellInformation-ExtIEs}} codec of TS 36.413.
func LastVisitedPSCellInformationExtIEsValueExtensionTableCodec(table s00.LastVisitedPSCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.LastVisitedPSCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeLastVisitedPSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LastVisitedPSCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.LastVisitedPSCellInformationExtIEsExtContainerValueCodec {
		sealed := s11.LastVisitedPSCellInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "LastVisitedPSCellInformationExtIEsExtContainer"
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LastVisitedPSCellInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.LastVisitedPSCellInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.LastVisitedPSCellInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LastVisitedPSCellInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LastVisitedPSCellInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LastVisitedPSCellInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.LastVisitedPSCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.LastVisitedPSCellInformationExtIEsExtContainer, options aper.DecodeState) (s11.LastVisitedPSCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.LastVisitedPSCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLastVisitedPSCellInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ListeningSubframePatternExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ListeningSubframePattern-ExtIEs}} codec of TS 36.413.
func ListeningSubframePatternExtIEsValueExtensionTableCodec(table s00.ListeningSubframePatternExtIEsValueExtensionTable, bounds aper.ListBounds) s11.ListeningSubframePatternExtIEsExtContainerValueCodec {
	if !*s00.BridgeListeningSubframePatternExtIEsValueExtensionTableFieldBound(&table) {
		return s11.ListeningSubframePatternExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.ListeningSubframePatternExtIEsExtContainerValueCodec {
		sealed := s11.ListeningSubframePatternExtIEsExtContainerValueCodec{}
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldPath(&sealed) = "ListeningSubframePatternExtIEsExtContainer"
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ListeningSubframePatternExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.ListeningSubframePatternExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.ListeningSubframePatternExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ListeningSubframePatternExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ListeningSubframePatternExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ListeningSubframePatternExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.ListeningSubframePatternExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.ListeningSubframePatternExtIEsExtContainer, options aper.DecodeState) (s11.ListeningSubframePatternExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.ListeningSubframePatternExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeListeningSubframePatternExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// LoggedMBSFNMDTExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{LoggedMBSFNMDT-ExtIEs}} codec of TS 36.413.
func LoggedMBSFNMDTExtIEsValueExtensionTableCodec(table s00.LoggedMBSFNMDTExtIEsValueExtensionTable, bounds aper.ListBounds) s11.LoggedMBSFNMDTExtIEsExtContainerValueCodec {
	if !*s00.BridgeLoggedMBSFNMDTExtIEsValueExtensionTableFieldBound(&table) {
		return s11.LoggedMBSFNMDTExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.LoggedMBSFNMDTExtIEsExtContainerValueCodec {
		sealed := s11.LoggedMBSFNMDTExtIEsExtContainerValueCodec{}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldPath(&sealed) = "LoggedMBSFNMDTExtIEsExtContainer"
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.LoggedMBSFNMDTExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.LoggedMBSFNMDTExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.LoggedMBSFNMDTExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "LoggedMBSFNMDTExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "LoggedMBSFNMDTExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "LoggedMBSFNMDTExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.LoggedMBSFNMDTExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.LoggedMBSFNMDTExtIEsExtContainer, options aper.DecodeState) (s11.LoggedMBSFNMDTExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.LoggedMBSFNMDTExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeLoggedMBSFNMDTExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M1PeriodicReportingExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M1PeriodicReporting-ExtIEs}} codec of TS 36.413.
func M1PeriodicReportingExtIEsValueExtensionTableCodec(table s00.M1PeriodicReportingExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M1PeriodicReportingExtIEsExtContainerValueCodec {
	if !*s00.BridgeM1PeriodicReportingExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M1PeriodicReportingExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M1PeriodicReportingExtIEsExtContainerValueCodec {
		sealed := s11.M1PeriodicReportingExtIEsExtContainerValueCodec{}
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldPath(&sealed) = "M1PeriodicReportingExtIEsExtContainer"
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M1PeriodicReportingExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M1PeriodicReportingExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M1PeriodicReportingExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M1PeriodicReportingExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M1PeriodicReportingExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M1PeriodicReportingExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M1PeriodicReportingExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M1PeriodicReportingExtIEsExtContainer, options aper.DecodeState) (s11.M1PeriodicReportingExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M1PeriodicReportingExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM1PeriodicReportingExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M1ThresholdEventA2ExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M1ThresholdEventA2-ExtIEs}} codec of TS 36.413.
func M1ThresholdEventA2ExtIEsValueExtensionTableCodec(table s00.M1ThresholdEventA2ExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M1ThresholdEventA2ExtIEsExtContainerValueCodec {
	if !*s00.BridgeM1ThresholdEventA2ExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M1ThresholdEventA2ExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M1ThresholdEventA2ExtIEsExtContainerValueCodec {
		sealed := s11.M1ThresholdEventA2ExtIEsExtContainerValueCodec{}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldPath(&sealed) = "M1ThresholdEventA2ExtIEsExtContainer"
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M1ThresholdEventA2ExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M1ThresholdEventA2ExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M1ThresholdEventA2ExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M1ThresholdEventA2ExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M1ThresholdEventA2ExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M1ThresholdEventA2ExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M1ThresholdEventA2ExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M1ThresholdEventA2ExtIEsExtContainer, options aper.DecodeState) (s11.M1ThresholdEventA2ExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M1ThresholdEventA2ExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM1ThresholdEventA2ExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M3ConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M3Configuration-ExtIEs}} codec of TS 36.413.
func M3ConfigurationExtIEsValueExtensionTableCodec(table s00.M3ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M3ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM3ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M3ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M3ConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.M3ConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "M3ConfigurationExtIEsExtContainer"
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M3ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M3ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M3ConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M3ConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M3ConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M3ConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M3ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M3ConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.M3ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M3ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM3ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M4ConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M4Configuration-ExtIEs}} codec of TS 36.413.
func M4ConfigurationExtIEsValueExtensionTableCodec(table s00.M4ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M4ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM4ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M4ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M4ConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.M4ConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "M4ConfigurationExtIEsExtContainer"
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M4ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M4ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M4ConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M4ConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M4ConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M4ConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M4ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M4ConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.M4ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M4ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM4ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M5ConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M5Configuration-ExtIEs}} codec of TS 36.413.
func M5ConfigurationExtIEsValueExtensionTableCodec(table s00.M5ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M5ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM5ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M5ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M5ConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.M5ConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "M5ConfigurationExtIEsExtContainer"
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M5ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M5ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M5ConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M5ConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M5ConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M5ConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M5ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M5ConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.M5ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M5ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM5ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M6ConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M6Configuration-ExtIEs}} codec of TS 36.413.
func M6ConfigurationExtIEsValueExtensionTableCodec(table s00.M6ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M6ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM6ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M6ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M6ConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.M6ConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "M6ConfigurationExtIEsExtContainer"
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M6ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M6ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M6ConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M6ConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M6ConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M6ConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M6ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M6ConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.M6ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M6ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM6ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// M7ConfigurationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{M7Configuration-ExtIEs}} codec of TS 36.413.
func M7ConfigurationExtIEsValueExtensionTableCodec(table s00.M7ConfigurationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.M7ConfigurationExtIEsExtContainerValueCodec {
	if !*s00.BridgeM7ConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.M7ConfigurationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.M7ConfigurationExtIEsExtContainerValueCodec {
		sealed := s11.M7ConfigurationExtIEsExtContainerValueCodec{}
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldPath(&sealed) = "M7ConfigurationExtIEsExtContainer"
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.M7ConfigurationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.M7ConfigurationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.M7ConfigurationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "M7ConfigurationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "M7ConfigurationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "M7ConfigurationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.M7ConfigurationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.M7ConfigurationExtIEsExtContainer, options aper.DecodeState) (s11.M7ConfigurationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.M7ConfigurationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeM7ConfigurationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MBSFNResultToLogInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{MBSFN-ResultToLogInfo-ExtIEs}} codec of TS 36.413.
func MBSFNResultToLogInfoExtIEsValueExtensionTableCodec(table s00.MBSFNResultToLogInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s11.MBSFNResultToLogInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeMBSFNResultToLogInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.MBSFNResultToLogInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.MBSFNResultToLogInfoExtIEsExtContainerValueCodec {
		sealed := s11.MBSFNResultToLogInfoExtIEsExtContainerValueCodec{}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "MBSFNResultToLogInfoExtIEsExtContainer"
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.MBSFNResultToLogInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.MBSFNResultToLogInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.MBSFNResultToLogInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MBSFNResultToLogInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MBSFNResultToLogInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MBSFNResultToLogInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.MBSFNResultToLogInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.MBSFNResultToLogInfoExtIEsExtContainer, options aper.DecodeState) (s11.MBSFNResultToLogInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.MBSFNResultToLogInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeMBSFNResultToLogInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MutingPatternInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{MutingPatternInformation-ExtIEs}} codec of TS 36.413.
func MutingPatternInformationExtIEsValueExtensionTableCodec(table s00.MutingPatternInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.MutingPatternInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeMutingPatternInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.MutingPatternInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.MutingPatternInformationExtIEsExtContainerValueCodec {
		sealed := s12.MutingPatternInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "MutingPatternInformationExtIEsExtContainer"
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MutingPatternInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MutingPatternInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.MutingPatternInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MutingPatternInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MutingPatternInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MutingPatternInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.MutingPatternInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.MutingPatternInformationExtIEsExtContainer, options aper.DecodeState) (s12.MutingPatternInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.MutingPatternInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMutingPatternInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NBIoTPagingEDRXInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NB-IoT-Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func NBIoTPagingEDRXInformationExtIEsValueExtensionTableCodec(table s00.NBIoTPagingEDRXInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeNBIoTPagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec {
		sealed := s12.NBIoTPagingEDRXInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "NBIoTPagingEDRXInformationExtIEsExtContainer"
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NBIoTPagingEDRXInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NBIoTPagingEDRXInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NBIoTPagingEDRXInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NBIoTPagingEDRXInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NBIoTPagingEDRXInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NBIoTPagingEDRXInformationExtIEsExtContainer, options aper.DecodeState) (s12.NBIoTPagingEDRXInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NBIoTPagingEDRXInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNBIoTPagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NGENBExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NG-eNB-ExtIEs}} codec of TS 36.413.
func NGENBExtIEsValueExtensionTableCodec(table s00.NGENBExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NGENBExtIEsExtContainerValueCodec {
	if !*s00.BridgeNGENBExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NGENBExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NGENBExtIEsExtContainerValueCodec {
		sealed := s12.NGENBExtIEsExtContainerValueCodec{}
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldPath(&sealed) = "NGENBExtIEsExtContainer"
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NGENBExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NGENBExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NGENBExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NGENBExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NGENBExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NGENBExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NGENBExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NGENBExtIEsExtContainer, options aper.DecodeState) (s12.NGENBExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NGENBExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNGENBExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNGENBExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NRCGIExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NR-CGI-ExtIEs}} codec of TS 36.413.
func NRCGIExtIEsValueExtensionTableCodec(table s00.NRCGIExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NRCGIExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRCGIExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRCGIExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NRCGIExtIEsExtContainerValueCodec {
		sealed := s12.NRCGIExtIEsExtContainerValueCodec{}
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldPath(&sealed) = "NRCGIExtIEsExtContainer"
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRCGIExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NRCGIExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NRCGIExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NRCGIExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRCGIExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NRCGIExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NRCGIExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NRCGIExtIEsExtContainer, options aper.DecodeState) (s12.NRCGIExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NRCGIExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRCGIExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NRUESecurityCapabilitiesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NRUESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func NRUESecurityCapabilitiesExtIEsValueExtensionTableCodec(table s00.NRUESecurityCapabilitiesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec {
		sealed := s12.NRUESecurityCapabilitiesExtIEsExtContainerValueCodec{}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldPath(&sealed) = "NRUESecurityCapabilitiesExtIEsExtContainer"
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRUESecurityCapabilitiesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NRUESecurityCapabilitiesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NRUESecurityCapabilitiesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NRUESecurityCapabilitiesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRUESecurityCapabilitiesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NRUESecurityCapabilitiesExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NRUESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NRUESecurityCapabilitiesExtIEsExtContainer, options aper.DecodeState) (s12.NRUESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NRUESecurityCapabilitiesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NRUESidelinkAggregateMaximumBitrate-ExtIEs}} codec of TS 36.413.
func NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableCodec(table s00.NRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec {
		sealed := s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodec{}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer"
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, options aper.DecodeState) (s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NRV2XServicesAuthorizedExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{NRV2XServicesAuthorized-ExtIEs}} codec of TS 36.413.
func NRV2XServicesAuthorizedExtIEsValueExtensionTableCodec(table s00.NRV2XServicesAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s12.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeNRV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec {
		sealed := s12.NRV2XServicesAuthorizedExtIEsExtContainerValueCodec{}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorizedExtIEsExtContainer"
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NRV2XServicesAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NRV2XServicesAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NRV2XServicesAuthorizedExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NRV2XServicesAuthorizedExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NRV2XServicesAuthorizedExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NRV2XServicesAuthorizedExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.NRV2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.NRV2XServicesAuthorizedExtIEsExtContainer, options aper.DecodeState) (s12.NRV2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.NRV2XServicesAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNRV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PC5FlowBitRatesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PC5FlowBitRates-ExtIEs}} codec of TS 36.413.
func PC5FlowBitRatesExtIEsValueExtensionTableCodec(table s00.PC5FlowBitRatesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PC5FlowBitRatesExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5FlowBitRatesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5FlowBitRatesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PC5FlowBitRatesExtIEsExtContainerValueCodec {
		sealed := s12.PC5FlowBitRatesExtIEsExtContainerValueCodec{}
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldPath(&sealed) = "PC5FlowBitRatesExtIEsExtContainer"
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5FlowBitRatesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PC5FlowBitRatesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PC5FlowBitRatesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PC5FlowBitRatesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5FlowBitRatesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PC5FlowBitRatesExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PC5FlowBitRatesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PC5FlowBitRatesExtIEsExtContainer, options aper.DecodeState) (s12.PC5FlowBitRatesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PC5FlowBitRatesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5FlowBitRatesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSFlowItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PC5QoSFlowItem-ExtIEs}} codec of TS 36.413.
func PC5QoSFlowItemExtIEsValueExtensionTableCodec(table s00.PC5QoSFlowItemExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PC5QoSFlowItemExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSFlowItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PC5QoSFlowItemExtIEsExtContainerValueCodec {
		sealed := s12.PC5QoSFlowItemExtIEsExtContainerValueCodec{}
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "PC5QoSFlowItemExtIEsExtContainer"
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5QoSFlowItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PC5QoSFlowItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PC5QoSFlowItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PC5QoSFlowItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5QoSFlowItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PC5QoSFlowItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PC5QoSFlowItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PC5QoSFlowItemExtIEsExtContainer, options aper.DecodeState) (s12.PC5QoSFlowItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PC5QoSFlowItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5QoSFlowItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSParametersExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PC5QoSParameters-ExtIEs}} codec of TS 36.413.
func PC5QoSParametersExtIEsValueExtensionTableCodec(table s00.PC5QoSParametersExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PC5QoSParametersExtIEsExtContainerValueCodec {
	if !*s00.BridgePC5QoSParametersExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PC5QoSParametersExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PC5QoSParametersExtIEsExtContainerValueCodec {
		sealed := s12.PC5QoSParametersExtIEsExtContainerValueCodec{}
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldPath(&sealed) = "PC5QoSParametersExtIEsExtContainer"
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PC5QoSParametersExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PC5QoSParametersExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PC5QoSParametersExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PC5QoSParametersExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PC5QoSParametersExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PC5QoSParametersExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PC5QoSParametersExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PC5QoSParametersExtIEsExtContainer, options aper.DecodeState) (s12.PC5QoSParametersExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PC5QoSParametersExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePC5QoSParametersExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PLMNAreaBasedQMCExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PLMNAreaBasedQMC-ExtIEs}} codec of TS 36.413.
func PLMNAreaBasedQMCExtIEsValueExtensionTableCodec(table s00.PLMNAreaBasedQMCExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
	if !*s00.BridgePLMNAreaBasedQMCExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PLMNAreaBasedQMCExtIEsExtContainerValueCodec {
		sealed := s12.PLMNAreaBasedQMCExtIEsExtContainerValueCodec{}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldPath(&sealed) = "PLMNAreaBasedQMCExtIEsExtContainer"
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PLMNAreaBasedQMCExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PLMNAreaBasedQMCExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PLMNAreaBasedQMCExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PLMNAreaBasedQMCExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PLMNAreaBasedQMCExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PLMNAreaBasedQMCExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PLMNAreaBasedQMCExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PLMNAreaBasedQMCExtIEsExtContainer, options aper.DecodeState) (s12.PLMNAreaBasedQMCExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PLMNAreaBasedQMCExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePLMNAreaBasedQMCExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PSCellInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PSCellInformation-ExtIEs}} codec of TS 36.413.
func PSCellInformationExtIEsValueExtensionTableCodec(table s00.PSCellInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PSCellInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePSCellInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PSCellInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PSCellInformationExtIEsExtContainerValueCodec {
		sealed := s12.PSCellInformationExtIEsExtContainerValueCodec{}
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "PSCellInformationExtIEsExtContainer"
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PSCellInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PSCellInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PSCellInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PSCellInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PSCellInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PSCellInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PSCellInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PSCellInformationExtIEsExtContainer, options aper.DecodeState) (s12.PSCellInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PSCellInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePSCellInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingAttemptInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{PagingAttemptInformation-ExtIEs}} codec of TS 36.413.
func PagingAttemptInformationExtIEsValueExtensionTableCodec(table s00.PagingAttemptInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PagingAttemptInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePagingAttemptInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PagingAttemptInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PagingAttemptInformationExtIEsExtContainerValueCodec {
		sealed := s12.PagingAttemptInformationExtIEsExtContainerValueCodec{}
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "PagingAttemptInformationExtIEsExtContainer"
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PagingAttemptInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PagingAttemptInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PagingAttemptInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PagingAttemptInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingAttemptInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PagingAttemptInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PagingAttemptInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PagingAttemptInformationExtIEsExtContainer, options aper.DecodeState) (s12.PagingAttemptInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PagingAttemptInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePagingAttemptInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingEDRXInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Paging-eDRXInformation-ExtIEs}} codec of TS 36.413.
func PagingEDRXInformationExtIEsValueExtensionTableCodec(table s00.PagingEDRXInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.PagingEDRXInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgePagingEDRXInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.PagingEDRXInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.PagingEDRXInformationExtIEsExtContainerValueCodec {
		sealed := s12.PagingEDRXInformationExtIEsExtContainerValueCodec{}
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "PagingEDRXInformationExtIEsExtContainer"
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.PagingEDRXInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.PagingEDRXInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.PagingEDRXInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "PagingEDRXInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingEDRXInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "PagingEDRXInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.PagingEDRXInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.PagingEDRXInformationExtIEsExtContainer, options aper.DecodeState) (s12.PagingEDRXInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.PagingEDRXInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgePagingEDRXInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ProSeAuthorizedExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ProSeAuthorized-ExtIEs}} codec of TS 36.413.
func ProSeAuthorizedExtIEsValueExtensionTableCodec(table s00.ProSeAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s12.ProSeAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeProSeAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ProSeAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.ProSeAuthorizedExtIEsExtContainerValueCodec {
		sealed := s12.ProSeAuthorizedExtIEsExtContainerValueCodec{}
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldPath(&sealed) = "ProSeAuthorizedExtIEsExtContainer"
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ProSeAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.ProSeAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.ProSeAuthorizedExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ProSeAuthorizedExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ProSeAuthorizedExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ProSeAuthorizedExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.ProSeAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.ProSeAuthorizedExtIEsExtContainer, options aper.DecodeState) (s12.ProSeAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.ProSeAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeProSeAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RATRestrictionsItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RAT-RestrictionsItem-ExtIEs}} codec of TS 36.413.
func RATRestrictionsItemExtIEsValueExtensionTableCodec(table s00.RATRestrictionsItemExtIEsValueExtensionTable, bounds aper.ListBounds) s12.RATRestrictionsItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeRATRestrictionsItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RATRestrictionsItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.RATRestrictionsItemExtIEsExtContainerValueCodec {
		sealed := s12.RATRestrictionsItemExtIEsExtContainerValueCodec{}
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "RATRestrictionsItemExtIEsExtContainer"
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RATRestrictionsItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.RATRestrictionsItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.RATRestrictionsItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RATRestrictionsItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RATRestrictionsItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RATRestrictionsItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.RATRestrictionsItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.RATRestrictionsItemExtIEsExtContainer, options aper.DecodeState) (s12.RATRestrictionsItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.RATRestrictionsItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRATRestrictionsItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RIMTransferExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RIMTransfer-ExtIEs}} codec of TS 36.413.
func RIMTransferExtIEsValueExtensionTableCodec(table s00.RIMTransferExtIEsValueExtensionTable, bounds aper.ListBounds) s12.RIMTransferExtIEsExtContainerValueCodec {
	if !*s00.BridgeRIMTransferExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RIMTransferExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.RIMTransferExtIEsExtContainerValueCodec {
		sealed := s12.RIMTransferExtIEsExtContainerValueCodec{}
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldPath(&sealed) = "RIMTransferExtIEsExtContainer"
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RIMTransferExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.RIMTransferExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.RIMTransferExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RIMTransferExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RIMTransferExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RIMTransferExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.RIMTransferExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.RIMTransferExtIEsExtContainer, options aper.DecodeState) (s12.RIMTransferExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.RIMTransferExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRIMTransferExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// RLFReportInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{RLFReportInformation-ExtIEs}} codec of TS 36.413.
func RLFReportInformationExtIEsValueExtensionTableCodec(table s00.RLFReportInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.RLFReportInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeRLFReportInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.RLFReportInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.RLFReportInformationExtIEsExtContainerValueCodec {
		sealed := s12.RLFReportInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "RLFReportInformationExtIEsExtContainer"
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.RLFReportInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.RLFReportInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.RLFReportInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RLFReportInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "RLFReportInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RLFReportInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.RLFReportInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.RLFReportInformationExtIEsExtContainer, options aper.DecodeState) (s12.RLFReportInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.RLFReportInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeRLFReportInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverSuccessIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverSuccessIEs}} codec of TS 36.413.
func HandoverSuccessIEValueIEFieldTableCodec(table s00.HandoverSuccessIEValueIETable) s11.HandoverSuccessIEFieldValueCodec {
	if !*s00.BridgeHandoverSuccessIEValueIETableFieldBound(&table) {
		return s11.HandoverSuccessIEFieldValueCodec{}
	}
	return func() s11.HandoverSuccessIEFieldValueCodec {
		sealed := s11.HandoverSuccessIEFieldValueCodec{}
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldPath(&sealed) = "HandoverSuccessIEField"
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.HandoverSuccessIEField, error) {
			var field s11.HandoverSuccessIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverSuccessIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverSuccessIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverSuccessIEField")
			}
			return field, nil
		}
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldEncode(&sealed) = func(field s11.HandoverSuccessIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldCapture(&sealed) = func(v s11.HandoverSuccessIEField, options aper.DecodeState) (s11.HandoverSuccessIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldCompare(&sealed) = func(v s11.HandoverSuccessIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeHandoverSuccessIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMECPRelocationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMECPRelocationIndicationIEs}} codec of TS 36.413.
func MMECPRelocationIndicationIEValueIEFieldTableCodec(table s00.MMECPRelocationIndicationIEValueIETable) s12.MMECPRelocationIndicationIEFieldValueCodec {
	if !*s00.BridgeMMECPRelocationIndicationIEValueIETableFieldBound(&table) {
		return s12.MMECPRelocationIndicationIEFieldValueCodec{}
	}
	return func() s12.MMECPRelocationIndicationIEFieldValueCodec {
		sealed := s12.MMECPRelocationIndicationIEFieldValueCodec{}
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldPath(&sealed) = "MMECPRelocationIndicationIEField"
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.MMECPRelocationIndicationIEField, error) {
			var field s11.MMECPRelocationIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEField")
			}
			return field, nil
		}
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s11.MMECPRelocationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s11.MMECPRelocationIndicationIEField, options aper.DecodeState) (s11.MMECPRelocationIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s11.MMECPRelocationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMMECPRelocationIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MeasurementThresholdL1LoggedMDTExtIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MeasurementThresholdL1LoggedMDT-ExtIEs}} codec of TS 36.413.
func MeasurementThresholdL1LoggedMDTExtIEValueIEFieldTableCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s12.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec {
	if !*s00.BridgeMeasurementThresholdL1LoggedMDTExtIEValueIETableFieldBound(&table) {
		return s12.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec{}
	}
	return func() s12.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec {
		sealed := s12.MeasurementThresholdL1LoggedMDTExtIEFieldValueCodec{}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldPath(&sealed) = "MeasurementThresholdL1LoggedMDTExtIEField"
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEField, error) {
			var field s12.MeasurementThresholdL1LoggedMDTExtIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDTExtIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEField")
			}
			return field, nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldEncode(&sealed) = func(field s12.MeasurementThresholdL1LoggedMDTExtIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCapture(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEField, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldCompare(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASDeliveryIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{NASDeliveryIndicationIEs}} codec of TS 36.413.
func NASDeliveryIndicationIEValueIEFieldTableCodec(table s00.NASDeliveryIndicationIEValueIETable) s12.NASDeliveryIndicationIEFieldValueCodec {
	if !*s00.BridgeNASDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s12.NASDeliveryIndicationIEFieldValueCodec{}
	}
	return func() s12.NASDeliveryIndicationIEFieldValueCodec {
		sealed := s12.NASDeliveryIndicationIEFieldValueCodec{}
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldPath(&sealed) = "NASDeliveryIndicationIEField"
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NASDeliveryIndicationIEField, error) {
			var field s12.NASDeliveryIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASDeliveryIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEField")
			}
			return field, nil
		}
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s12.NASDeliveryIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s12.NASDeliveryIndicationIEField, options aper.DecodeState) (s12.NASDeliveryIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s12.NASDeliveryIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNASDeliveryIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverSuccessIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverSuccessIEs}} codec of TS 36.413.
func HandoverSuccessIEValueIETableCodec(table s00.HandoverSuccessIEValueIETable, bounds aper.ListBounds) s11.HandoverSuccessIEContainerValueCodec {
	if !*s00.BridgeHandoverSuccessIEValueIETableFieldBound(&table) {
		return s11.HandoverSuccessIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.HandoverSuccessIEContainerValueCodec {
		sealed := s11.HandoverSuccessIEContainerValueCodec{}
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldPath(&sealed) = "HandoverSuccessIEContainer"
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.HandoverSuccessIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.HandoverSuccessIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.HandoverSuccessIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverSuccessIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEContainer")
			}
			return fields, nil
		}
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&sealed) = func(fields s11.HandoverSuccessIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldCapture(&sealed) = func(v s11.HandoverSuccessIEContainer, options aper.DecodeState) (s11.HandoverSuccessIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldCompare(&sealed) = func(v s11.HandoverSuccessIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeHandoverSuccessIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMECPRelocationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{MMECPRelocationIndicationIEs}} codec of TS 36.413.
func MMECPRelocationIndicationIEValueIETableCodec(table s00.MMECPRelocationIndicationIEValueIETable, bounds aper.ListBounds) s12.MMECPRelocationIndicationIEContainerValueCodec {
	if !*s00.BridgeMMECPRelocationIndicationIEValueIETableFieldBound(&table) {
		return s12.MMECPRelocationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.MMECPRelocationIndicationIEContainerValueCodec {
		sealed := s12.MMECPRelocationIndicationIEContainerValueCodec{}
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldPath(&sealed) = "MMECPRelocationIndicationIEContainer"
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.MMECPRelocationIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.MMECPRelocationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEContainer")
			}
			return fields, nil
		}
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s11.MMECPRelocationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s11.MMECPRelocationIndicationIEContainer, options aper.DecodeState) (s11.MMECPRelocationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s11.MMECPRelocationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec constructs the ProtocolIE-Container {{MeasurementThresholdL1LoggedMDT-ExtIEs}} codec of TS 36.413.
func MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable, bounds aper.ListBounds) s12.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec {
	if !*s00.BridgeMeasurementThresholdL1LoggedMDTExtIEValueIETableFieldBound(&table) {
		return s12.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec {
		sealed := s12.MeasurementThresholdL1LoggedMDTExtIEContainerValueCodec{}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldPath(&sealed) = "MeasurementThresholdL1LoggedMDTExtIEContainer"
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MeasurementThresholdL1LoggedMDTExtIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.MeasurementThresholdL1LoggedMDTExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDTExtIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEContainer")
			}
			return fields, nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.MeasurementThresholdL1LoggedMDTExtIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCapture(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEContainer, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldCompare(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASDeliveryIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{NASDeliveryIndicationIEs}} codec of TS 36.413.
func NASDeliveryIndicationIEValueIETableCodec(table s00.NASDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s12.NASDeliveryIndicationIEContainerValueCodec {
	if !*s00.BridgeNASDeliveryIndicationIEValueIETableFieldBound(&table) {
		return s12.NASDeliveryIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.NASDeliveryIndicationIEContainerValueCodec {
		sealed := s12.NASDeliveryIndicationIEContainerValueCodec{}
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldPath(&sealed) = "NASDeliveryIndicationIEContainer"
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NASDeliveryIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NASDeliveryIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NASDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASDeliveryIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEContainer")
			}
			return fields, nil
		}
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.NASDeliveryIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s12.NASDeliveryIndicationIEContainer, options aper.DecodeState) (s12.NASDeliveryIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s12.NASDeliveryIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverSuccessIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverSuccessIEs}} codec of TS 36.413.
func HandoverSuccessIEValueProtocolErrorIEContainerListCodec(table s00.HandoverSuccessIEValueIETable) s11.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s11.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s11.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s11.HandoverSuccessIEValueProtocolErrorIEContainerListValueCodec{}
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "HandoverSuccessIEValueProtocolErrorIEContainerList"
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.HandoverSuccessIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.HandoverSuccessIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.HandoverSuccessIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverSuccessIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.HandoverSuccessIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s11.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.HandoverSuccessIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s11.HandoverSuccessIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.HandoverSuccessIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeHandoverSuccessIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMECPRelocationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMECPRelocationIndicationIEs}} codec of TS 36.413.
func MMECPRelocationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable) s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMECPRelocationIndicationIEValueProtocolErrorIEContainerList"
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.MMECPRelocationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s11.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MeasurementThresholdL1LoggedMDT-ExtIEs}} codec of TS 36.413.
func MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable) s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList"
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.MeasurementThresholdL1LoggedMDTExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s12.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NASDeliveryIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{NASDeliveryIndicationIEs}} codec of TS 36.413.
func NASDeliveryIndicationIEValueProtocolErrorIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable) s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "NASDeliveryIndicationIEValueProtocolErrorIEContainerList"
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NASDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASDeliveryIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s12.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverSuccessIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverSuccessIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverSuccessIEValueProtocolIEContainerListCodec(table s00.HandoverSuccessIEValueIETable, bounds aper.ListBounds) s11.HandoverSuccessIEValueProtocolIEContainerListValueCodec {
	codec := HandoverSuccessIEValueIETableCodec(table, bounds)
	if *s11.BridgeHandoverSuccessIEContainerValueCodecFieldDecode(&codec) == nil {
		return s11.HandoverSuccessIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s11.HandoverSuccessIEValueProtocolIEContainerListValueCodec {
		sealed := s11.HandoverSuccessIEValueProtocolIEContainerListValueCodec{}
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "HandoverSuccessIEValueProtocolIEContainerList"
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.HandoverSuccessIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.HandoverSuccessIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.HandoverSuccessIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverSuccessIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverSuccessIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s11.HandoverSuccessIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s11.BridgeHandoverSuccessIEContainerValueCodecFieldEncode(&codec))(s11.HandoverSuccessIEContainer(value), fresh, budget)
		}
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s11.HandoverSuccessIEValueProtocolIEContainerList, options aper.DecodeState) (s11.HandoverSuccessIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s11.HandoverSuccessIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeHandoverSuccessIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MMECPRelocationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMECPRelocationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMECPRelocationIndicationIEValueProtocolIEContainerListCodec(table s00.MMECPRelocationIndicationIEValueIETable, bounds aper.ListBounds) s12.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := MMECPRelocationIndicationIEValueIETableCodec(table, bounds)
	if *s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s12.MMECPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMECPRelocationIndicationIEValueProtocolIEContainerList"
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MMECPRelocationIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.MMECPRelocationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMECPRelocationIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMMECPRelocationIndicationIEContainerValueCodecFieldEncode(&codec))(s11.MMECPRelocationIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMMECPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MeasurementThresholdL1LoggedMDT-ExtIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListCodec(table s00.MeasurementThresholdL1LoggedMDTExtIEValueIETable, bounds aper.ListBounds) s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec {
	codec := MeasurementThresholdL1LoggedMDTExtIEValueIETableCodec(table, bounds)
	if *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec {
		sealed := s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList"
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.MeasurementThresholdL1LoggedMDTExtIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEContainerValueCodecFieldEncode(&codec))(s12.MeasurementThresholdL1LoggedMDTExtIEContainer(value), fresh, budget)
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, options aper.DecodeState) (s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeMeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// NASDeliveryIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {NASDeliveryIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func NASDeliveryIndicationIEValueProtocolIEContainerListCodec(table s00.NASDeliveryIndicationIEValueIETable, bounds aper.ListBounds) s12.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
	codec := NASDeliveryIndicationIEValueIETableCodec(table, bounds)
	if *s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s12.NASDeliveryIndicationIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "NASDeliveryIndicationIEValueProtocolIEContainerList"
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.NASDeliveryIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.NASDeliveryIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "NASDeliveryIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "NASDeliveryIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.NASDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeNASDeliveryIndicationIEContainerValueCodecFieldEncode(&codec))(s12.NASDeliveryIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.NASDeliveryIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s12.NASDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.NASDeliveryIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeNASDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionField(v *s11.InformationForCECapableUEsExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeInformationForCECapableUEsExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeInformationForCECapableUEsExtIEsExtFieldFieldReplay(v), *s11.BridgeInformationForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionField(v *s11.InformationForCECapableUEsExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeInformationForCECapableUEsExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeInformationForCECapableUEsExtIEsExtFieldFieldReplay(v), *s11.BridgeInformationForCECapableUEsExtIEsExtFieldFieldWithoutReplay(v))
}

// handoverSuccessIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverSuccessIEValue].
type HandoverSuccessIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s11.HandoverSuccessIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s11.HandoverSuccessIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionField(v *s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionField(v *s11.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldReplay(v), *s11.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldFieldWithoutReplay(v))
}

// interSystemMeasurementItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterSystemMeasurementItemExtIEsValue].
type InterSystemMeasurementItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.InterSystemMeasurementItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.InterSystemMeasurementItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.InterSystemMeasurementItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeInterSystemMeasurementItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldReplay(v), *s11.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.InterSystemMeasurementItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeInterSystemMeasurementItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldReplay(v), *s11.BridgeInterSystemMeasurementItemExtIEsExtFieldFieldWithoutReplay(v))
}

// interSystemMeasurementParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[InterSystemMeasurementParametersExtIEsValue].
type InterSystemMeasurementParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.InterSystemMeasurementParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.InterSystemMeasurementParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s11.InterSystemMeasurementParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldReplay(v), *s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionField(v *s11.InterSystemMeasurementParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeInterSystemMeasurementParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldReplay(v), *s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldFieldWithoutReplay(v))
}

// intersystemMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[IntersystemMeasurementConfigurationExtIEsValue].
type IntersystemMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.IntersystemMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.IntersystemMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.IntersystemMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.IntersystemMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeIntersystemMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// lAIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LAIExtIEsValue].
type LAIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.LAIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.LAIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLAIExtIEsValueCaptureS1APProtocolExtensionField(v *s11.LAIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeLAIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeLAIExtIEsExtFieldFieldReplay(v), *s11.BridgeLAIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLAIExtIEsValueCompareS1APProtocolExtensionField(v *s11.LAIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeLAIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeLAIExtIEsExtFieldFieldReplay(v), *s11.BridgeLAIExtIEsExtFieldFieldWithoutReplay(v))
}

// lTENTNTAIInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LTENTNTAIInformationExtIEsValue].
type LTENTNTAIInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.LTENTNTAIInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.LTENTNTAIInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.LTENTNTAIInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeLTENTNTAIInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeLTENTNTAIInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeLTENTNTAIInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.LTENTNTAIInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeLTENTNTAIInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeLTENTNTAIInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeLTENTNTAIInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// lastVisitedPSCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LastVisitedPSCellInformationExtIEsValue].
type LastVisitedPSCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.LastVisitedPSCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.LastVisitedPSCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.LastVisitedPSCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.LastVisitedPSCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeLastVisitedPSCellInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeLastVisitedPSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// listeningSubframePatternExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ListeningSubframePatternExtIEsValue].
type ListeningSubframePatternExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.ListeningSubframePatternExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.ListeningSubframePatternExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionField(v *s11.ListeningSubframePatternExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeListeningSubframePatternExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeListeningSubframePatternExtIEsExtFieldFieldReplay(v), *s11.BridgeListeningSubframePatternExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionField(v *s11.ListeningSubframePatternExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeListeningSubframePatternExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeListeningSubframePatternExtIEsExtFieldFieldReplay(v), *s11.BridgeListeningSubframePatternExtIEsExtFieldFieldWithoutReplay(v))
}

// loggedMBSFNMDTExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[LoggedMBSFNMDTExtIEsValue].
type LoggedMBSFNMDTExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.LoggedMBSFNMDTExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.LoggedMBSFNMDTExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionField(v *s11.LoggedMBSFNMDTExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeLoggedMBSFNMDTExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionField(v *s11.LoggedMBSFNMDTExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeLoggedMBSFNMDTExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldReplay(v), *s11.BridgeLoggedMBSFNMDTExtIEsExtFieldFieldWithoutReplay(v))
}

// m1PeriodicReportingExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M1PeriodicReportingExtIEsValue].
type M1PeriodicReportingExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M1PeriodicReportingExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M1PeriodicReportingExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M1PeriodicReportingExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM1PeriodicReportingExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM1PeriodicReportingExtIEsExtFieldFieldReplay(v), *s11.BridgeM1PeriodicReportingExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionField(v *s11.M1PeriodicReportingExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM1PeriodicReportingExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM1PeriodicReportingExtIEsExtFieldFieldReplay(v), *s11.BridgeM1PeriodicReportingExtIEsExtFieldFieldWithoutReplay(v))
}

// m1ThresholdEventA2ExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M1ThresholdEventA2ExtIEsValue].
type M1ThresholdEventA2ExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M1ThresholdEventA2ExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M1ThresholdEventA2ExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M1ThresholdEventA2ExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM1ThresholdEventA2ExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldReplay(v), *s11.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionField(v *s11.M1ThresholdEventA2ExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM1ThresholdEventA2ExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldReplay(v), *s11.BridgeM1ThresholdEventA2ExtIEsExtFieldFieldWithoutReplay(v))
}

// m3ConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[M3ConfigurationExtIEsValue].
type M3ConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s05.M3ConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s05.M3ConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M3ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM3ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM3ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM3ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.M3ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM3ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM3ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM3ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M4ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM4ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM4ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM4ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.M4ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM4ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM4ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM4ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M5ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM5ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM5ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM5ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.M5ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM5ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM5ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM5ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M6ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM6ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM6ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM6ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.M6ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM6ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM6ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM6ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.M7ConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeM7ConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeM7ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM7ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s11.M7ConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeM7ConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeM7ConfigurationExtIEsExtFieldFieldReplay(v), *s11.BridgeM7ConfigurationExtIEsExtFieldFieldWithoutReplay(v))
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

func BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s11.MBSFNResultToLogInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionField(v *s11.MBSFNResultToLogInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s05.BridgeMBSFNResultToLogInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// mMECPRelocationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[MMECPRelocationIndicationIEValue].
type MMECPRelocationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s11.MMECPRelocationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s11.MMECPRelocationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(v *s11.MMECPRelocationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s11.BridgeMMECPRelocationIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s11.BridgeMMECPRelocationIndicationIEFieldFieldReplay(v), *s11.BridgeMMECPRelocationIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(v *s11.MMECPRelocationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s11.BridgeMMECPRelocationIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s11.BridgeMMECPRelocationIndicationIEFieldFieldReplay(v), *s11.BridgeMMECPRelocationIndicationIEFieldFieldWithoutReplay(v))
}

// measurementThresholdL1LoggedMDTExtIEValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementThresholdL1LoggedMDTExtIEValue].
type MeasurementThresholdL1LoggedMDTExtIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.MeasurementThresholdL1LoggedMDTExtIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.MeasurementThresholdL1LoggedMDTExtIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEField(v *s12.MeasurementThresholdL1LoggedMDTExtIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldReplay(v), *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldWithoutReplay(v))
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEField(v *s12.MeasurementThresholdL1LoggedMDTExtIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldReplay(v), *s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldFieldWithoutReplay(v))
}

// mutingPatternInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[MutingPatternInformationExtIEsValue].
type MutingPatternInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.MutingPatternInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.MutingPatternInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.MutingPatternInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeMutingPatternInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeMutingPatternInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeMutingPatternInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.MutingPatternInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeMutingPatternInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeMutingPatternInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeMutingPatternInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// nASDeliveryIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[NASDeliveryIndicationIEValue].
type NASDeliveryIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.NASDeliveryIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.NASDeliveryIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(v *s12.NASDeliveryIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeNASDeliveryIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeNASDeliveryIndicationIEFieldFieldReplay(v), *s12.BridgeNASDeliveryIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(v *s12.NASDeliveryIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeNASDeliveryIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeNASDeliveryIndicationIEFieldFieldReplay(v), *s12.BridgeNASDeliveryIndicationIEFieldFieldWithoutReplay(v))
}

// nBIoTPagingEDRXInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NBIoTPagingEDRXInformationExtIEsValue].
type NBIoTPagingEDRXInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NBIoTPagingEDRXInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NBIoTPagingEDRXInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NBIoTPagingEDRXInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.NBIoTPagingEDRXInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNBIoTPagingEDRXInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// nGENBExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NGENBExtIEsValue].
type NGENBExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NGENBExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NGENBExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NGENBExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNGENBExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNGENBExtIEsExtFieldFieldReplay(v), *s12.BridgeNGENBExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNGENBExtIEsValueCompareS1APProtocolExtensionField(v *s12.NGENBExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNGENBExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNGENBExtIEsExtFieldFieldReplay(v), *s12.BridgeNGENBExtIEsExtFieldFieldWithoutReplay(v))
}

// nRCGIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRCGIExtIEsValue].
type NRCGIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NRCGIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NRCGIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NRCGIExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNRCGIExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s12.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionField(v *s12.NRCGIExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNRCGIExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNRCGIExtIEsExtFieldFieldReplay(v), *s12.BridgeNRCGIExtIEsExtFieldFieldWithoutReplay(v))
}

// nRUESecurityCapabilitiesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRUESecurityCapabilitiesExtIEsValue].
type NRUESecurityCapabilitiesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NRUESecurityCapabilitiesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NRUESecurityCapabilitiesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NRUESecurityCapabilitiesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(v *s12.NRUESecurityCapabilitiesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNRUESecurityCapabilitiesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeNRUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}

// nRUESidelinkAggregateMaximumBitrateExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRUESidelinkAggregateMaximumBitrateExtIEsValue].
type NRUESidelinkAggregateMaximumBitrateExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldReplay(v), *s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionField(v *s12.NRUESidelinkAggregateMaximumBitrateExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldReplay(v), *s12.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldFieldWithoutReplay(v))
}

// nRV2XServicesAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[NRV2XServicesAuthorizedExtIEsValue].
type NRV2XServicesAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.NRV2XServicesAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.NRV2XServicesAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s12.NRV2XServicesAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s12.NRV2XServicesAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeNRV2XServicesAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeNRV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5FlowBitRatesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5FlowBitRatesExtIEsValue].
type PC5FlowBitRatesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PC5FlowBitRatesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PC5FlowBitRatesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PC5FlowBitRatesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePC5FlowBitRatesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePC5FlowBitRatesExtIEsExtFieldFieldReplay(v), *s12.BridgePC5FlowBitRatesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionField(v *s12.PC5FlowBitRatesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePC5FlowBitRatesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePC5FlowBitRatesExtIEsExtFieldFieldReplay(v), *s12.BridgePC5FlowBitRatesExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5QoSFlowItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSFlowItemExtIEsValue].
type PC5QoSFlowItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PC5QoSFlowItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PC5QoSFlowItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PC5QoSFlowItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePC5QoSFlowItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePC5QoSFlowItemExtIEsExtFieldFieldReplay(v), *s12.BridgePC5QoSFlowItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionField(v *s12.PC5QoSFlowItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePC5QoSFlowItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePC5QoSFlowItemExtIEsExtFieldFieldReplay(v), *s12.BridgePC5QoSFlowItemExtIEsExtFieldFieldWithoutReplay(v))
}

// pC5QoSParametersExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PC5QoSParametersExtIEsValue].
type PC5QoSParametersExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PC5QoSParametersExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PC5QoSParametersExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PC5QoSParametersExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePC5QoSParametersExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s12.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionField(v *s12.PC5QoSParametersExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePC5QoSParametersExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePC5QoSParametersExtIEsExtFieldFieldReplay(v), *s12.BridgePC5QoSParametersExtIEsExtFieldFieldWithoutReplay(v))
}

// pLMNAreaBasedQMCExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PLMNAreaBasedQMCExtIEsValue].
type PLMNAreaBasedQMCExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PLMNAreaBasedQMCExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PLMNAreaBasedQMCExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePLMNAreaBasedQMCExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s12.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionField(v *s12.PLMNAreaBasedQMCExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePLMNAreaBasedQMCExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldReplay(v), *s12.BridgePLMNAreaBasedQMCExtIEsExtFieldFieldWithoutReplay(v))
}

// pSCellInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PSCellInformationExtIEsValue].
type PSCellInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PSCellInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PSCellInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PSCellInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePSCellInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.PSCellInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePSCellInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePSCellInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePSCellInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// pagingAttemptInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PagingAttemptInformationExtIEsValue].
type PagingAttemptInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PagingAttemptInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PagingAttemptInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PagingAttemptInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePagingAttemptInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.PagingAttemptInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePagingAttemptInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePagingAttemptInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePagingAttemptInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// pagingEDRXInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[PagingEDRXInformationExtIEsValue].
type PagingEDRXInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.PagingEDRXInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.PagingEDRXInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.PagingEDRXInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgePagingEDRXInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.PagingEDRXInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgePagingEDRXInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgePagingEDRXInformationExtIEsExtFieldFieldReplay(v), *s12.BridgePagingEDRXInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// proSeAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ProSeAuthorizedExtIEsValue].
type ProSeAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ProSeAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ProSeAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s12.ProSeAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeProSeAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeProSeAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeProSeAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s12.ProSeAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeProSeAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeProSeAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeProSeAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// rATRestrictionsItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RATRestrictionsItemExtIEsValue].
type RATRestrictionsItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.RATRestrictionsItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.RATRestrictionsItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionField(v *s12.RATRestrictionsItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRATRestrictionsItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeRATRestrictionsItemExtIEsExtFieldFieldReplay(v), *s12.BridgeRATRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionField(v *s12.RATRestrictionsItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRATRestrictionsItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeRATRestrictionsItemExtIEsExtFieldFieldReplay(v), *s12.BridgeRATRestrictionsItemExtIEsExtFieldFieldWithoutReplay(v))
}

// rIMTransferExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RIMTransferExtIEsValue].
type RIMTransferExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.RIMTransferExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.RIMTransferExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionField(v *s12.RIMTransferExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRIMTransferExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeRIMTransferExtIEsExtFieldFieldReplay(v), *s12.BridgeRIMTransferExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionField(v *s12.RIMTransferExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRIMTransferExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeRIMTransferExtIEsExtFieldFieldReplay(v), *s12.BridgeRIMTransferExtIEsExtFieldFieldWithoutReplay(v))
}

// rLFReportInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[RLFReportInformationExtIEsValue].
type RLFReportInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.RLFReportInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.RLFReportInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.RLFReportInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeRLFReportInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeRLFReportInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeRLFReportInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.RLFReportInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeRLFReportInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeRLFReportInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeRLFReportInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// COUNTValueExtendedAPERValue is the concrete APERValue[COUNTValueExtended].
type COUNTValueExtendedAPERValue struct {
	context s00.BridgeCodecContext
	Value   COUNTValueExtended

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTValueExtendedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTValueExtendedAPERValue) WithoutReplay() COUNTValueExtendedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsAPERValue is the concrete APERValue[CNTypeRestrictions].
type CNTypeRestrictionsAPERValue struct {
	context s00.BridgeCodecContext
	Value   CNTypeRestrictions

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsAPERValue) WithoutReplay() CNTypeRestrictionsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BluetoothMeasurementConfigurationAPERValue is the concrete APERValue[BluetoothMeasurementConfiguration].
type BluetoothMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   BluetoothMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BluetoothMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BluetoothMeasurementConfigurationAPERValue) WithoutReplay() BluetoothMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ActivatedCellsListAPERValue is the concrete APERValue[ActivatedCellsList].
type ActivatedCellsListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ActivatedCellsList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ActivatedCellsListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ActivatedCellsListAPERValue) WithoutReplay() ActivatedCellsListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ActivatedCellsListItemAPERValue is the concrete APERValue[ActivatedCellsListItem].
type ActivatedCellsListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ActivatedCellsListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ActivatedCellsListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ActivatedCellsListItemAPERValue) WithoutReplay() ActivatedCellsListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AllocationAndRetentionPriorityAPERValue is the concrete APERValue[AllocationAndRetentionPriority].
type AllocationAndRetentionPriorityAPERValue struct {
	context s00.BridgeCodecContext
	Value   AllocationAndRetentionPriority

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AllocationAndRetentionPriorityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AllocationAndRetentionPriorityAPERValue) WithoutReplay() AllocationAndRetentionPriorityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CGIAPERValue is the concrete APERValue[CGI].
type CGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CGIAPERValue) WithoutReplay() CGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CNTypeRestrictionsItemAPERValue is the concrete APERValue[CNTypeRestrictionsItem].
type CNTypeRestrictionsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CNTypeRestrictionsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CNTypeRestrictionsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CNTypeRestrictionsItemAPERValue) WithoutReplay() CNTypeRestrictionsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvalueAPERValue is the concrete APERValue[COUNTvalue].
type COUNTvalueAPERValue struct {
	context s00.BridgeCodecContext
	Value   COUNTvalue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvalueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvalueAPERValue) WithoutReplay() COUNTvalueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemExtIEsIEField uses the ProtocolIE-Field shape for object set Bearers-SubjectToStatusTransfer-ItemExtIEs of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToStatusTransferItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsIEField) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemExtIEsIEField{}
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
	var zero BearersSubjectToStatusTransferItemExtIEsValue

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

// BearersSubjectToStatusTransferItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set Bearers-SubjectToStatusTransfer-ItemExtIEs of TS 36.413: a list of BearersSubjectToStatusTransferItemExtIEsIEField values.
type BearersSubjectToStatusTransferItemExtIEsIEContainer []BearersSubjectToStatusTransferItemExtIEsIEField

func BridgeHandoverSuccessIEValueCompareS1APERABIEContainerList(v *s11.HandoverSuccessIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCaptureS1APERABIEContainerList(v *s12.MMECPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCompareS1APERABIEContainerList(v *s12.MMECPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APERABIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APERABIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCaptureS1APERABIEContainerList(v *s12.NASDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCompareS1APERABIEContainerList(v *s12.NASDeliveryIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemExtIEsExtField].
type BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, error)
	encode  func(BearersSubjectToStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) New(value BearersSubjectToStatusTransferItemExtIEsExtField) (BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemExtIEsExtContainer].
type BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, error)
	encode  func(BearersSubjectToStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) New(value BearersSubjectToStatusTransferItemExtIEsExtContainer) (BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainer(v *s12.MeasurementThresholdL1LoggedMDTExtIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainer(v *s12.MeasurementThresholdL1LoggedMDTExtIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCompareS1APProtocolErrorIEContainerList(v *s11.HandoverSuccessIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s12.MMECPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolErrorIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s12.NASDeliveryIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainerList(v *s11.HandoverSuccessIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(v *s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(v *s12.MMECPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIEContainerList(v *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainerList(v *s12.NASDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainerList(v *s12.NASDeliveryIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverSuccessIEValueCompareS1APProtocolIESingleContainer(v *s11.HandoverSuccessIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s15.BridgeHandoverSuccessIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s12.MMECPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(v *s12.MMECPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s12.NASDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIESingleContainer(v *s12.NASDeliveryIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemExtIEsExtField].
type BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemExtIEsExtContainer].
type BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsListItem(v *ActivatedCellsListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APActivatedCellsListItem(v *ActivatedCellsListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APAllocationAndRetentionPriority(v *AllocationAndRetentionPriority, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPriorityLevel(&v.PriorityLevel, s)
	s00.BridgeCaptureS1APPreEmptionCapability(&v.PreEmptionCapability, s)
	s00.BridgeCaptureS1APPreEmptionVulnerability(&v.PreEmptionVulnerability, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeAllocationAndRetentionPriorityExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAllocationAndRetentionPriority(v *AllocationAndRetentionPriority, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPriorityLevel(&v.PriorityLevel, s)
	s02.BridgeCompareS1APPreEmptionCapability(&v.PreEmptionCapability, s)
	s02.BridgeCompareS1APPreEmptionVulnerability(&v.PreEmptionVulnerability, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeAllocationAndRetentionPriorityExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItemExtIEsValue(v *BearersSubjectToStatusTransferItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(179):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValueExtended == nil)
				if v.rowULCOUNTValueExtended != nil {
					BridgeCaptureS1APCOUNTValueExtended(v.rowULCOUNTValueExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(180):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValueExtended == nil)
				if v.rowDLCOUNTValueExtended != nil {
					BridgeCaptureS1APCOUNTValueExtended(v.rowDLCOUNTValueExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(181):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsExtended == nil)
				if v.rowReceiveStatusOfULPDCPSDUsExtended != nil {
					s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsExtended(v.rowReceiveStatusOfULPDCPSDUsExtended, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(217):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValuePDCPSNlength18 == nil)
				if v.rowULCOUNTValuePDCPSNlength18 != nil {
					BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.rowULCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(218):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValuePDCPSNlength18 == nil)
				if v.rowDLCOUNTValuePDCPSNlength18 != nil {
					BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.rowDLCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(219):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil)
				if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil {
					s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToStatusTransferItemExtIEsValue {
	BridgeCaptureS1APBearersSubjectToStatusTransferItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToStatusTransferItemExtIEsValue(v *BearersSubjectToStatusTransferItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(179):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValueExtended == nil)
				if v.rowULCOUNTValueExtended != nil {
					BridgeCompareS1APCOUNTValueExtended(v.rowULCOUNTValueExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(180):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValueExtended == nil)
				if v.rowDLCOUNTValueExtended != nil {
					BridgeCompareS1APCOUNTValueExtended(v.rowDLCOUNTValueExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(181):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsExtended == nil)
				if v.rowReceiveStatusOfULPDCPSDUsExtended != nil {
					s08.BridgeCompareS1APReceiveStatusOfULPDCPSDUsExtended(v.rowReceiveStatusOfULPDCPSDUsExtended, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(217):
			{
				f := s.Begin()
				s.Bool(v.rowULCOUNTValuePDCPSNlength18 == nil)
				if v.rowULCOUNTValuePDCPSNlength18 != nil {
					BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.rowULCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(218):
			{
				f := s.Begin()
				s.Bool(v.rowDLCOUNTValuePDCPSNlength18 == nil)
				if v.rowDLCOUNTValuePDCPSNlength18 != nil {
					BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.rowDLCOUNTValuePDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(219):
			{
				f := s.Begin()
				s.Bool(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil)
				if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil {
					s08.BridgeCompareS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToStatusTransferItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APBluetoothMeasurementConfiguration(v *BluetoothMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBluetoothMeasConfig(&v.BluetoothMeasConfig, s)
	s.Bool(v.BluetoothMeasConfigNameList == nil)
	s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.BtRssi == nil)
		if v.BtRssi != nil {
			s.Int(int64((*v.BtRssi)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBluetoothMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBluetoothMeasurementConfiguration(v *BluetoothMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBluetoothMeasConfig(&v.BluetoothMeasConfig, s)
	s.Bool(v.BluetoothMeasConfigNameList == nil)
	s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, s)
	{
		f := s.Begin()
		s.Bool(v.BtRssi == nil)
		if v.BtRssi != nil {
			s.Int(int64((*v.BtRssi)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBluetoothMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCGI(v *CGI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APLAC(&v.LAC, s)
	s00.BridgeCaptureS1APCI(&v.CI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s00.BridgeCaptureS1APRAC(v.RAC, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCGI(v *CGI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APLAC(&v.LAC, s)
	s02.BridgeCompareS1APCI(&v.CI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s08.BridgeCompareS1APRAC(v.RAC, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCNTypeRestrictionsItem(v *CNTypeRestrictionsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APCNType(&v.CNType, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCNTypeRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCNTypeRestrictionsItem(v *CNTypeRestrictionsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s02.BridgeCompareS1APCNType(&v.CNType, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCNTypeRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTValueExtended(v *COUNTValueExtended, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSNExtended(&v.PDCPSNExtended, s)
	s00.BridgeCaptureS1APHFNModified(&v.HFNModified, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTValueExtendedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTValueExtended(v *COUNTValueExtended, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSNExtended(&v.PDCPSNExtended, s)
	s02.BridgeCompareS1APHFNModified(&v.HFNModified, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTValueExtendedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTvalue(v *COUNTvalue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSN(&v.PDCPSN, s)
	s00.BridgeCaptureS1APHFN(&v.HFN, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTvalueExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTvalue(v *COUNTvalue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSN(&v.PDCPSN, s)
	s02.BridgeCompareS1APHFN(&v.HFN, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTvalueExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v *COUNTvaluePDCPSNlength18, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPDCPSNlength18(&v.PDCPSNlength18, s)
	s00.BridgeCaptureS1APHFNforPDCPSNlength18(&v.HFNforPDCPSNlength18, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCOUNTvaluePDCPSNlength18(v *COUNTvaluePDCPSNlength18, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPDCPSNlength18(&v.PDCPSNlength18, s)
	s02.BridgeCompareS1APHFNforPDCPSNlength18(&v.HFNforPDCPSNlength18, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// AllocationAndRetentionPriority represents the ASN.1 type AllocationAndRetentionPriority (SEQUENCE).
type AllocationAndRetentionPriority struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	PriorityLevel           s00.PriorityLevel                                    `asn1:"tag:0,context,implicit"`
	PreEmptionCapability    s00.PreEmptionCapability                             `asn1:"tag:1,context,implicit"`
	PreEmptionVulnerability s00.PreEmptionVulnerability                          `asn1:"tag:2,context,implicit"`
	IEExtensions            s08.AllocationAndRetentionPriorityExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                                 `asn1:"-" json:"-"`
	extCount                int64                                                `asn1:"-" json:"-"`
	extPresent              []bool                                               `asn1:"-" json:"-"`
	extData                 [][]byte                                             `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// BluetoothMeasurementConfiguration represents the ASN.1 type BluetoothMeasurementConfiguration (SEQUENCE).
type BluetoothMeasurementConfiguration struct {
	replay                           aper.Snapshot
	stream                           aper.WireSpan
	received                         bool
	withoutReplay                    bool
	receivedAbsolute                 bool
	receivedBytes                    aper.WireSpan
	receivedLocation                 aper.Location
	BluetoothMeasConfig              s00.BluetoothMeasConfig                                 `asn1:"tag:0,context,implicit"`
	BluetoothMeasConfigNameList      s00.BluetoothMeasConfigNameList                         `asn1:"tag:1,context,implicit,optional" json:"BluetoothMeasConfigNameList,omitzero"`
	bluetoothMeasConfigNameListIndef bool                                                    `asn1:"-" json:"-"`
	BtRssi                           *int64                                                  `asn1:"tag:2,context,implicit,optional" json:"BtRssi,omitempty"`
	IEExtensions                     s08.BluetoothMeasurementConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                bool                                                    `asn1:"-" json:"-"`
	extCount                         int64                                                   `asn1:"-" json:"-"`
	extPresent                       []bool                                                  `asn1:"-" json:"-"`
	extData                          [][]byte                                                `asn1:"-" json:"-"`
	perPadding                       aper.FinalPadding                                       `asn1:"-" json:"-"`
	perExtPadding                    []aper.CompletePadding                                  `asn1:"-" json:"-"`
	extOrigin                        []aper.OpaqueOrigin
	extWire                          []aper.WireSpan
}

// CGI represents the ASN.1 type CGI (SEQUENCE).
type CGI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity          `asn1:"tag:0,context,implicit"`
	LAC               s00.LAC                   `asn1:"tag:1,context,implicit"`
	CI                s00.CI                    `asn1:"tag:2,context,implicit"`
	RAC               *s00.RAC                  `asn1:"tag:3,context,implicit,optional" json:"RAC,omitempty"`
	IEExtensions      s08.CGIExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                      `asn1:"-" json:"-"`
	extCount          int64                     `asn1:"-" json:"-"`
	extPresent        []bool                    `asn1:"-" json:"-"`
	extData           [][]byte                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CNTypeRestrictions = []CNTypeRestrictionsItem

// CNTypeRestrictionsItem represents the ASN.1 type CNTypeRestrictions-Item (SEQUENCE).
type CNTypeRestrictionsItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNIdentity      s00.PLMNidentity                             `asn1:"tag:0,context,implicit"`
	CNType            s00.CNType                                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.CNTypeRestrictionsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTvalue represents the ASN.1 type COUNTvalue (SEQUENCE).
type COUNTvalue struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PDCPSN            s00.PDCPSN                       `asn1:"tag:0,context,implicit"`
	HFN               s00.HFN                          `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.COUNTvalueExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                             `asn1:"-" json:"-"`
	extCount          int64                            `asn1:"-" json:"-"`
	extPresent        []bool                           `asn1:"-" json:"-"`
	extData           [][]byte                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTValueExtended represents the ASN.1 type COUNTValueExtended (SEQUENCE).
type COUNTValueExtended struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PDCPSNExtended    s00.PDCPSNExtended                       `asn1:"tag:0,context,implicit"`
	HFNModified       s00.HFNModified                          `asn1:"tag:1,context,implicit"`
	IEExtensions      s08.COUNTValueExtendedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                     `asn1:"-" json:"-"`
	extCount          int64                                    `asn1:"-" json:"-"`
	extPresent        []bool                                   `asn1:"-" json:"-"`
	extData           [][]byte                                 `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// COUNTvaluePDCPSNlength18 represents the ASN.1 type COUNTvaluePDCP-SNlength18 (SEQUENCE).
type COUNTvaluePDCPSNlength18 struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	PDCPSNlength18       s00.PDCPSNlength18                             `asn1:"tag:0,context,implicit"`
	HFNforPDCPSNlength18 s00.HFNforPDCPSNlength18                       `asn1:"tag:1,context,implicit"`
	IEExtensions         s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                           `asn1:"-" json:"-"`
	extCount             int64                                          `asn1:"-" json:"-"`
	extPresent           []bool                                         `asn1:"-" json:"-"`
	extData              [][]byte                                       `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// MarshalAPER encodes AllocationAndRetentionPriority to APER format.
func (v *AllocationAndRetentionPriority) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AllocationAndRetentionPriority) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.PriorityLevel), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(15), false); err != nil {
		return fmt.Errorf("encoding priorityLevel: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PreEmptionCapability), 2, false); err != nil {
		return fmt.Errorf("encoding pre-emptionCapability: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PreEmptionVulnerability), 2, false); err != nil {
		return fmt.Errorf("encoding pre-emptionVulnerability: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes AllocationAndRetentionPriority from APER format.
func (v *AllocationAndRetentionPriority) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AllocationAndRetentionPriority) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	bb.EnterComponent("AllocationAndRetentionPriority")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	padding, err := aper.CaptureFinalBits(bb, "AllocationAndRetentionPriority")
	if err != nil {
		return runtime.WrapDecodePath(err, "AllocationAndRetentionPriority")
	}
	v.perPadding = padding
	return nil
}
func (v *AllocationAndRetentionPriority) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AllocationAndRetentionPriority{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_prioritylevel, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(15), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PriorityLevel")
	}
	v.PriorityLevel = s00.PriorityLevel(val_prioritylevel)
	val_preemptioncapability, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "PreEmptionCapability"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PreEmptionCapability")
	}
	v.PreEmptionCapability = s00.PreEmptionCapability(val_preemptioncapability)
	val_preemptionvulnerability, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "PreEmptionVulnerability"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PreEmptionVulnerability")
	}
	v.PreEmptionVulnerability = s00.PreEmptionVulnerability(val_preemptionvulnerability)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.AllocationAndRetentionPriorityExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.AllocationAndRetentionPriorityExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeAllocationAndRetentionPriorityExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes BluetoothMeasurementConfiguration to APER format.
func (v *BluetoothMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.BluetoothMeasConfigNameList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.BtRssi != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.BluetoothMeasConfig), 1, true); err != nil {
		return fmt.Errorf("encoding bluetoothMeasConfig: %w", err)
	}
	if v.BluetoothMeasConfigNameList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.BluetoothMeasConfigNameList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_bluetoothmeasconfignamelist, fragmentLength_bluetoothmeasconfignamelist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_bluetoothmeasconfignamelist < 0 || fragmentOffset_bluetoothmeasconfignamelist > int64(len(v.BluetoothMeasConfigNameList)) || fragmentLength_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist > int64(len(v.BluetoothMeasConfigNameList[fragmentOffset_bluetoothmeasconfignamelist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.BluetoothMeasConfigNameList[fragmentOffset_bluetoothmeasconfignamelist : fragmentOffset_bluetoothmeasconfignamelist+fragmentLength_bluetoothmeasconfignamelist] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 248, true); err != nil {
					return fmt.Errorf("encoding bluetoothMeasConfigNameList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding bluetoothMeasConfigNameList: %w", err)
		}
	}
	if v.BtRssi != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.BtRssi), 1, true); err != nil {
			return fmt.Errorf("encoding bt-rssi: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes BluetoothMeasurementConfiguration from APER format.
func (v *BluetoothMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BluetoothMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	bb.EnterComponent("BluetoothMeasurementConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "BluetoothMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasurementConfiguration")
	}
	v.perPadding = padding
	return nil
}
func (v *BluetoothMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BluetoothMeasurementConfiguration{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_bluetoothmeasconfignamelist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_btrssi, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_bluetoothmeasconfig, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BluetoothMeasConfig"})
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfig")
	}
	v.BluetoothMeasConfig = s00.BluetoothMeasConfig(val_bluetoothmeasconfig)
	if opt_bluetoothmeasconfignamelist {
		toleranceMark_bluetoothmeasconfignamelist := bb.EnterComponent("BluetoothMeasConfigNameList")
		tmp_bluetoothmeasconfignamelist := make(s00.BluetoothMeasConfigNameList, 0)
		_, errCollection_bluetoothmeasconfignamelist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_bluetoothmeasconfignamelist, fragmentLength_bluetoothmeasconfignamelist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
			if fragmentOffset_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist < 0 || fragmentLength_bluetoothmeasconfignamelist > int64(^uint(0)>>1) || fragmentOffset_bluetoothmeasconfignamelist > int64(^uint(0)>>1)-fragmentLength_bluetoothmeasconfignamelist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_bluetoothmeasconfignamelist; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 1, 248, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasConfigNameList[%d]", fragmentOffset_bluetoothmeasconfignamelist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_bluetoothmeasconfignamelist, val); err != nil {
					return err
				} else {
					tmp_bluetoothmeasconfignamelist = next
				}
			}
			return nil
		})
		if errCollection_bluetoothmeasconfignamelist != nil {
			return runtime.WrapDecodePath(errCollection_bluetoothmeasconfignamelist, "BluetoothMeasConfigNameList")
		}
		v.BluetoothMeasConfigNameList = tmp_bluetoothmeasconfignamelist
		bb.LeaveComponent(toleranceMark_bluetoothmeasconfignamelist)
	}
	if opt_btrssi {
		val_btrssi, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BtRssi"})
		if err != nil {
			return runtime.WrapDecodePath(err, "BtRssi")
		}
		if err := aper.ChargeValue(bb, val_btrssi); err != nil {
			return err
		}
		v.BtRssi = (*int64)(bb.OwnInt64(int64(val_btrssi)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.BluetoothMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.BluetoothMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeBluetoothMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes CGI to APER format.
func (v *CGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.RAC != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.LAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding lAC: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.CI), 2, 2, true); err != nil {
		return fmt.Errorf("encoding cI: %w", err)
	}
	if v.RAC != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.RAC), 1, 1, true); err != nil {
			return fmt.Errorf("encoding rAC: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes CGI from APER format.
func (v *CGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	bb.EnterComponent("CGI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CGI")
	}
	v.perPadding = padding
	return nil
}
func (v *CGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CGI{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rac, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	val_lac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "LAC")
	}
	v.LAC = s00.LAC(val_lac)
	val_ci, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CI")
	}
	v.CI = s00.CI(val_ci)
	if opt_rac {
		val_rac, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "RAC")
		}
		tmp_rac := s00.RAC(val_rac)
		if err := aper.ChargeValue(bb, tmp_rac); err != nil {
			return err
		}
		v.RAC = &tmp_rac
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CGIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes CNTypeRestrictionsItem to APER format.
func (v *CNTypeRestrictionsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CNTypeRestrictionsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CNType), 1, true); err != nil {
		return fmt.Errorf("encoding cNType: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes CNTypeRestrictionsItem from APER format.
func (v *CNTypeRestrictionsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CNTypeRestrictionsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	bb.EnterComponent("CNTypeRestrictionsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CNTypeRestrictionsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictionsItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CNTypeRestrictionsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CNTypeRestrictionsItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	val_cntype, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "CNType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CNType")
	}
	v.CNType = s00.CNType(val_cntype)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CNTypeRestrictionsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CNTypeRestrictionsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCNTypeRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes COUNTvalue to APER format.
func (v *COUNTvalue) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTvalue) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSN), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false); err != nil {
		return fmt.Errorf("encoding pDCP-SN: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFN), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false); err != nil {
		return fmt.Errorf("encoding hFN: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes COUNTvalue from APER format.
func (v *COUNTvalue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *COUNTvalue) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	bb.EnterComponent("COUNTvalue")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTvalue")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTvalue")
	}
	v.perPadding = padding
	return nil
}
func (v *COUNTvalue) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvalue{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pdcpsn, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4095), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSN")
	}
	v.PDCPSN = s00.PDCPSN(val_pdcpsn)
	val_hfn, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFN")
	}
	v.HFN = s00.HFN(val_hfn)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.COUNTvalueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.COUNTvalueExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCOUNTvalueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes COUNTValueExtended to APER format.
func (v *COUNTValueExtended) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTValueExtended) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSNExtended), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding pDCP-SNExtended: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFNModified), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(131071), false); err != nil {
		return fmt.Errorf("encoding hFNModified: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes COUNTValueExtended from APER format.
func (v *COUNTValueExtended) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *COUNTValueExtended) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	bb.EnterComponent("COUNTValueExtended")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTValueExtended")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTValueExtended")
	}
	v.perPadding = padding
	return nil
}
func (v *COUNTValueExtended) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTValueExtended{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pdcpsnextended, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSNExtended")
	}
	v.PDCPSNExtended = s00.PDCPSNExtended(val_pdcpsnextended)
	val_hfnmodified, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(131071), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFNModified")
	}
	v.HFNModified = s00.HFNModified(val_hfnmodified)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.COUNTValueExtendedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.COUNTValueExtendedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCOUNTValueExtendedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// MarshalAPER encodes COUNTvaluePDCPSNlength18 to APER format.
func (v *COUNTvaluePDCPSNlength18) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.PDCPSNlength18), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(262143), false); err != nil {
		return fmt.Errorf("encoding pDCP-SNlength18: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HFNforPDCPSNlength18), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16383), false); err != nil {
		return fmt.Errorf("encoding hFNforPDCP-SNlength18: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes COUNTvaluePDCPSNlength18 from APER format.
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	bb.EnterComponent("COUNTvaluePDCPSNlength18")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	padding, err := aper.CaptureFinalBits(bb, "COUNTvaluePDCPSNlength18")
	if err != nil {
		return runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
	}
	v.perPadding = padding
	return nil
}
func (v *COUNTvaluePDCPSNlength18) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = COUNTvaluePDCPSNlength18{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pdcpsnlength18, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(262143), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PDCPSNlength18")
	}
	v.PDCPSNlength18 = s00.PDCPSNlength18(val_pdcpsnlength18)
	val_hfnforpdcpsnlength18, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16383), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HFNforPDCPSNlength18")
	}
	v.HFNforPDCPSNlength18 = s00.HFNforPDCPSNlength18(val_hfnforpdcpsnlength18)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.COUNTvaluePDCPSNlength18ExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.COUNTvaluePDCPSNlength18ExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCOUNTvaluePDCPSNlength18ExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AllocationAndRetentionPriority) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "AllocationAndRetentionPriority", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AllocationAndRetentionPriority", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AllocationAndRetentionPriority) WithoutReplay() AllocationAndRetentionPriority {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AllocationAndRetentionPriority
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BluetoothMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "BluetoothMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BluetoothMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BluetoothMeasurementConfiguration) WithoutReplay() BluetoothMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BluetoothMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CGI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CGI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CGI) WithoutReplay() CGI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CNTypeRestrictionsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "CNTypeRestrictionsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CNTypeRestrictionsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CNTypeRestrictionsItem) WithoutReplay() CNTypeRestrictionsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CNTypeRestrictionsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTValueExtended) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTValueExtended", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTValueExtended", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTValueExtended) WithoutReplay() COUNTValueExtended {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTValueExtended
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTvalue) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTvalue", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTvalue", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTvalue) WithoutReplay() COUNTvalue {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTvalue
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *COUNTvaluePDCPSNlength18) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "COUNTvaluePDCPSNlength18", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "COUNTvaluePDCPSNlength18", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v COUNTvaluePDCPSNlength18) WithoutReplay() COUNTvaluePDCPSNlength18 {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero COUNTvaluePDCPSNlength18
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AllocationAndRetentionPriority) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AllocationAndRetentionPriority) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AllocationAndRetentionPriority) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AllocationAndRetentionPriority.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *BluetoothMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BluetoothMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BluetoothMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BluetoothMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CNTypeRestrictionsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CNTypeRestrictionsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CNTypeRestrictionsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CNTypeRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTValueExtended) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTValueExtended) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTValueExtended) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTValueExtended.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTvalue) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTvalue) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTvalue) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvalue.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *COUNTvaluePDCPSNlength18) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *COUNTvaluePDCPSNlength18) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *COUNTvaluePDCPSNlength18) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("COUNTvaluePDCPSNlength18.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AllocationAndRetentionPriority) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AllocationAndRetentionPriority")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AllocationAndRetentionPriority) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AllocationAndRetentionPriority")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAllocationAndRetentionPriority(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AllocationAndRetentionPriority")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AllocationAndRetentionPriority")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AllocationAndRetentionPriority) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AllocationAndRetentionPriority")
}
func (v *AllocationAndRetentionPriority) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AllocationAndRetentionPriority")
}
func (v *AllocationAndRetentionPriority) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAllocationAndRetentionPriority(v, &s)
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
func (v *AllocationAndRetentionPriority) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AllocationAndRetentionPriority) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BluetoothMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BluetoothMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BluetoothMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBluetoothMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BluetoothMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
}
func (v *BluetoothMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BluetoothMeasurementConfiguration")
}
func (v *BluetoothMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBluetoothMeasurementConfiguration(v, &s)
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
func (v *BluetoothMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BluetoothMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CGI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CGI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CGI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCGI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CGI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CGI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CGI")
}
func (v *CGI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CGI")
}
func (v *CGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCGI(v, &s)
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
func (v *CGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CNTypeRestrictionsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CNTypeRestrictionsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CNTypeRestrictionsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCNTypeRestrictionsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CNTypeRestrictionsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CNTypeRestrictionsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CNTypeRestrictionsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CNTypeRestrictionsItem")
}
func (v *CNTypeRestrictionsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CNTypeRestrictionsItem")
}
func (v *CNTypeRestrictionsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCNTypeRestrictionsItem(v, &s)
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
func (v *CNTypeRestrictionsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CNTypeRestrictionsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTValueExtended) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTValueExtended")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTValueExtended) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTValueExtended")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTValueExtended(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTValueExtended")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTValueExtended")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTValueExtended) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTValueExtended")
}
func (v *COUNTValueExtended) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTValueExtended")
}
func (v *COUNTValueExtended) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTValueExtended(v, &s)
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
func (v *COUNTValueExtended) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTValueExtended) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTvalue) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTvalue")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTvalue) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTvalue")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTvalue(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTvalue")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTvalue")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTvalue) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTvalue")
}
func (v *COUNTvalue) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTvalue")
}
func (v *COUNTvalue) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTvalue(v, &s)
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
func (v *COUNTvalue) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTvalue) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *COUNTvaluePDCPSNlength18) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "COUNTvaluePDCPSNlength18")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCOUNTvaluePDCPSNlength18(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "COUNTvaluePDCPSNlength18")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCOUNTvaluePDCPSNlength18(v, &s)
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
func (v *COUNTvaluePDCPSNlength18) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *COUNTvaluePDCPSNlength18) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AllocationAndRetentionPriority) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AllocationAndRetentionPriority")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AllocationAndRetentionPriority
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAllocationAndRetentionPriority(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AllocationAndRetentionPriority{}
		return report, aper.OperationError(err, "AllocationAndRetentionPriority")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AllocationAndRetentionPriority")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BluetoothMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BluetoothMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBluetoothMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BluetoothMeasurementConfiguration{}
		return report, aper.OperationError(err, "BluetoothMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BluetoothMeasurementConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CGI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CGI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CGI{}
		return report, aper.OperationError(err, "CGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CGI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CNTypeRestrictionsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CNTypeRestrictionsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCNTypeRestrictionsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CNTypeRestrictionsItem{}
		return report, aper.OperationError(err, "CNTypeRestrictionsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CNTypeRestrictionsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTValueExtended) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTValueExtended")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTValueExtended
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTValueExtended(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTValueExtended{}
		return report, aper.OperationError(err, "COUNTValueExtended")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTValueExtended")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTvalue) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTvalue")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTvalue
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTvalue(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTvalue{}
		return report, aper.OperationError(err, "COUNTvalue")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTvalue")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *COUNTvaluePDCPSNlength18) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "COUNTvaluePDCPSNlength18")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded COUNTvaluePDCPSNlength18
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = COUNTvaluePDCPSNlength18{}
		return report, aper.OperationError(err, "COUNTvaluePDCPSNlength18")
	}
	*v = decoded
	return report, aper.OperationError(nil, "COUNTvaluePDCPSNlength18")
}

type ActivatedCellsList = []ActivatedCellsListItem

// ActivatedCellsListItem represents the ASN.1 type ActivatedCellsList-Item (SEQUENCE).
type ActivatedCellsListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           []byte                 `asn1:"tag:0,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ActivatedCellsListItem to APER format.
func (v *ActivatedCellsListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ActivatedCellsListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
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
		extensionCount, _ = BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := aper.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes ActivatedCellsListItem from APER format.
func (v *ActivatedCellsListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ActivatedCellsListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	bb.EnterComponent("ActivatedCellsListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ActivatedCellsListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsListItem")
	}
	v.perPadding = padding
	return nil
}
func (v *ActivatedCellsListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ActivatedCellsListItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "Annex B.2"})
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
func (v *ActivatedCellsListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return BridgeReceivedFormAt(v.received, v.receivedBytes, "ActivatedCellsListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ActivatedCellsListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ActivatedCellsListItem) WithoutReplay() ActivatedCellsListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ActivatedCellsListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ActivatedCellsListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ActivatedCellsListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ActivatedCellsListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ActivatedCellsListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ActivatedCellsListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ActivatedCellsListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APActivatedCellsListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ActivatedCellsListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ActivatedCellsListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ActivatedCellsListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ActivatedCellsListItem")
}
func (v *ActivatedCellsListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ActivatedCellsListItem")
}
func (v *ActivatedCellsListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APActivatedCellsListItem(v, &s)
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
func (v *ActivatedCellsListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ActivatedCellsListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ActivatedCellsListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ActivatedCellsListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APActivatedCellsListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ActivatedCellsListItem{}
		return report, aper.OperationError(err, "ActivatedCellsListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ActivatedCellsListItem")
}

type BearersSubjectToStatusTransferItemExtIEsValue struct {
	id                                         s00.ProtocolIEID
	received                                   aper.WireSpan
	replay                                     aper.Snapshot
	opaque                                     aper.OpaqueOpenType
	isOpaque                                   bool
	rowULCOUNTValueExtended                    *COUNTValueExtended
	rowDLCOUNTValueExtended                    *COUNTValueExtended
	rowReceiveStatusOfULPDCPSDUsExtended       *s00.ReceiveStatusOfULPDCPSDUsExtended
	rowULCOUNTValuePDCPSNlength18              *COUNTvaluePDCPSNlength18
	rowDLCOUNTValuePDCPSNlength18              *COUNTvaluePDCPSNlength18
	rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 *s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
}

func (v BearersSubjectToStatusTransferItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(179):
		return v.rowULCOUNTValueExtended != nil
	case s00.ProtocolIEID(180):
		return v.rowDLCOUNTValueExtended != nil
	case s00.ProtocolIEID(181):
		return v.rowReceiveStatusOfULPDCPSDUsExtended != nil
	case s00.ProtocolIEID(217):
		return v.rowULCOUNTValuePDCPSNlength18 != nil
	case s00.ProtocolIEID(218):
		return v.rowDLCOUNTValuePDCPSNlength18 != nil
	case s00.ProtocolIEID(219):
		return v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToStatusTransferItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs"}}
}
func (BearersSubjectToStatusTransferItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(179):
		return aper.UnknownSelector
	case s00.ProtocolIEID(180):
		return aper.UnknownSelector
	case s00.ProtocolIEID(181):
		return aper.UnknownSelector
	case s00.ProtocolIEID(217):
		return aper.UnknownSelector
	case s00.ProtocolIEID(218):
		return aper.UnknownSelector
	case s00.ProtocolIEID(219):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(12):
		return aper.NotInTable
	case s00.ProtocolIEID(13):
		return aper.NotInTable
	case s00.ProtocolIEID(14):
		return aper.NotInTable
	case s00.ProtocolIEID(15):
		return aper.NotInTable
	case s00.ProtocolIEID(16):
		return aper.NotInTable
	case s00.ProtocolIEID(17):
		return aper.NotInTable
	case s00.ProtocolIEID(18):
		return aper.NotInTable
	case s00.ProtocolIEID(19):
		return aper.NotInTable
	case s00.ProtocolIEID(20):
		return aper.NotInTable
	case s00.ProtocolIEID(21):
		return aper.NotInTable
	case s00.ProtocolIEID(22):
		return aper.NotInTable
	case s00.ProtocolIEID(23):
		return aper.NotInTable
	case s00.ProtocolIEID(24):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
		return aper.NotInTable
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsULCOUNTValueExtended returns the selected ULCOUNTValueExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsULCOUNTValueExtended() (*COUNTValueExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(179) || v.rowULCOUNTValueExtended == nil {
		return nil, false
	}
	return v.rowULCOUNTValueExtended, true
}

// AsDLCOUNTValueExtended returns the selected DLCOUNTValueExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsDLCOUNTValueExtended() (*COUNTValueExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(180) || v.rowDLCOUNTValueExtended == nil {
		return nil, false
	}
	return v.rowDLCOUNTValueExtended, true
}

// AsReceiveStatusOfULPDCPSDUsExtended returns the selected ReceiveStatusOfULPDCPSDUsExtended value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsReceiveStatusOfULPDCPSDUsExtended() (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
	if v == nil || v.id != s00.ProtocolIEID(181) || v.rowReceiveStatusOfULPDCPSDUsExtended == nil {
		return nil, false
	}
	return v.rowReceiveStatusOfULPDCPSDUsExtended, true
}

// AsULCOUNTValuePDCPSNlength18 returns the selected ULCOUNTValuePDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsULCOUNTValuePDCPSNlength18() (*COUNTvaluePDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(217) || v.rowULCOUNTValuePDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowULCOUNTValuePDCPSNlength18, true
}

// AsDLCOUNTValuePDCPSNlength18 returns the selected DLCOUNTValuePDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsDLCOUNTValuePDCPSNlength18() (*COUNTvaluePDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(218) || v.rowDLCOUNTValuePDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowDLCOUNTValuePDCPSNlength18, true
}

// AsReceiveStatusOfULPDCPSDUsPDCPSNlength18 returns the selected ReceiveStatusOfULPDCPSDUsPDCPSNlength18 value of BearersSubjectToStatusTransferItemExtIEsValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) AsReceiveStatusOfULPDCPSDUsPDCPSNlength18() (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool) {
	if v == nil || v.id != s00.ProtocolIEID(219) || v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil {
		return nil, false
	}
	return v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, true
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemExtIEsValue, error) {
	out := BearersSubjectToStatusTransferItemExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(179):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTValueExtended
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCOUNTValueExtended:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTValueExtended")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCOUNTValueExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(180):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTValueExtended
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCOUNTValueExtended:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTValueExtended")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDLCOUNTValueExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(181):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ReceiveStatusOfULPDCPSDUsExtended, error) {
			var v struct {
				Value s00.ReceiveStatusOfULPDCPSDUsExtended
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 1, 16384, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowReceiveStatusOfULPDCPSDUsExtended = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(217):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTvaluePDCPSNlength18
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCOUNTValuePDCPSNlength18:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTvaluePDCPSNlength18")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCOUNTValuePDCPSNlength18 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(218):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value COUNTvaluePDCPSNlength18
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DLCOUNTValuePDCPSNlength18:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "COUNTvaluePDCPSNlength18")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDLCOUNTValuePDCPSNlength18 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(219):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, error) {
			var v struct {
				Value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 1, 131072, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 = &value
		raw.RetainContents(&out.received)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToStatusTransferItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	switch v.id {
	case s00.ProtocolIEID(179):
		if v.rowULCOUNTValueExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValueExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCOUNTValueExtended.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(180):
		if v.rowDLCOUNTValueExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValueExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDLCOUNTValueExtended.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(181):
		if v.rowReceiveStatusOfULPDCPSDUsExtended == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsExtended:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ReceiveStatusOfULPDCPSDUsExtended, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ReceiveStatusOfULPDCPSDUsExtended
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 1, 16384, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowReceiveStatusOfULPDCPSDUsExtended, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(217):
		if v.rowULCOUNTValuePDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValuePDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCOUNTValuePDCPSNlength18.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(218):
		if v.rowDLCOUNTValuePDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValuePDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDLCOUNTValuePDCPSNlength18.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(219):
		if v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18 == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 1, 131072, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToStatusTransferItemExtIEsValue:", v.id)
	}
}

// preferredSequenceTail chooses the shortest extension bitmap containing all
// semantic additions. X.691 (02/2021) §19.8 defines its index and length.
func BridgePreferredSequenceTail(present []bool, data [][]byte) (int64, bool) {
	var last int64
	found := false
	for i, set := range present {
		if set {
			last = int64(i)
			found = true
		}
	}
	for i, contents := range data {
		if contents != nil {
			last = int64(i)
			found = true
		}
	}
	return last, found
}
func BridgeReceivedFormAt(present bool, original aper.WireSpan, path aper.Path, location aper.Location, complete interface{ Bits() (uint8, uint8) }) aper.ReceivedForm {
	location.Path = path
	var padding []aper.PaddingSpan
	if location.HasWireLocation && len(location.Spans) != 0 {
		last := location.Spans[len(location.Spans)-1]
		value, count := complete.Bits()
		width, borrow := bits.Sub64(last.End, last.Start, 0)
		if count != 0 && borrow == 0 && uint64(count) <= width {
			start, borrow := bits.Sub64(last.End, uint64(count), 0)
			if borrow == 0 {
				padding = []aper.PaddingSpan{{Span: aper.BitSpan{Start: start, End: last.End}, Value: value, Width: count}}
			}
		}
	}
	return aper.NewReceivedSpanForm(present, original, location, padding)
}

// ActivatedCellsListItemCodec binds the complete source value type.
func ActivatedCellsListItemCodec() ActivatedCellsListItemValueCodec {
	return ActivatedCellsListItemValueCodec{path: "ActivatedCellsListItem", decode: func(data []byte, options aper.DecodeState) (ActivatedCellsListItem, error) {
		var value ActivatedCellsListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ActivatedCellsListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ActivatedCellsListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ActivatedCellsListItem, options aper.DecodeState) (ActivatedCellsListItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APActivatedCellsListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ActivatedCellsListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APActivatedCellsListItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ActivatedCellsListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// AllocationAndRetentionPriorityCodec binds the complete source value type.
func AllocationAndRetentionPriorityCodec() AllocationAndRetentionPriorityValueCodec {
	return AllocationAndRetentionPriorityValueCodec{path: "AllocationAndRetentionPriority", decode: func(data []byte, options aper.DecodeState) (AllocationAndRetentionPriority, error) {
		var value AllocationAndRetentionPriority
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AllocationAndRetentionPriority{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AllocationAndRetentionPriority, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AllocationAndRetentionPriority, options aper.DecodeState) (AllocationAndRetentionPriority, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAllocationAndRetentionPriority(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v AllocationAndRetentionPriority, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APAllocationAndRetentionPriority(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AllocationAndRetentionPriority"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CGICodec binds the complete source value type.
func CGICodec() CGIValueCodec {
	return CGIValueCodec{path: "CGI", decode: func(data []byte, options aper.DecodeState) (CGI, error) {
		var value CGI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CGI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CGI, options aper.DecodeState) (CGI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCGI(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v CGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCGI(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CGI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CNTypeRestrictionsItemCodec binds the complete source value type.
func CNTypeRestrictionsItemCodec() CNTypeRestrictionsItemValueCodec {
	return CNTypeRestrictionsItemValueCodec{path: "CNTypeRestrictionsItem", decode: func(data []byte, options aper.DecodeState) (CNTypeRestrictionsItem, error) {
		var value CNTypeRestrictionsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CNTypeRestrictionsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CNTypeRestrictionsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CNTypeRestrictionsItem, options aper.DecodeState) (CNTypeRestrictionsItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCNTypeRestrictionsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CNTypeRestrictionsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCNTypeRestrictionsItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNTypeRestrictionsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
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

func BridgeActivatedCellsListItemMethodMarshalAPERTo(v *ActivatedCellsListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(v *ActivatedCellsListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeActivatedCellsListValueCodecFieldCapture(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, aper.DecodeState) (ActivatedCellsList, aper.Snapshot) {
	return &v.capture
}
func BridgeActivatedCellsListValueCodecFieldCompare(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeActivatedCellsListValueCodecFieldContext(v *ActivatedCellsListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeActivatedCellsListValueCodecFieldDecode(v *ActivatedCellsListValueCodec) *func([]byte, aper.DecodeState) (ActivatedCellsList, error) {
	return &v.decode
}
func BridgeActivatedCellsListValueCodecFieldEncode(v *ActivatedCellsListValueCodec) *func(ActivatedCellsList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeActivatedCellsListValueCodecFieldPath(v *ActivatedCellsListValueCodec) *aper.Path {
	return &v.path
}
func BridgeAllocationAndRetentionPriorityMethodMarshalAPERTo(v *AllocationAndRetentionPriority, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAllocationAndRetentionPriorityMethodUnmarshalAPERFrom(v *AllocationAndRetentionPriority, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *COUNTValueExtendedValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*COUNTValueExtended, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding) *func(COUNTValueExtended) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldPath(v *BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v *BearersSubjectToStatusTransferItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v *BearersSubjectToStatusTransferItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldContext(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *func(BearersSubjectToStatusTransferItemExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldPath(v *BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldCodec(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldGet(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *func(*BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
	return &v.get
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInfo(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInject(v *BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding) *func(s00.ReceiveStatusOfULPDCPSDUsExtended) BearersSubjectToStatusTransferItemExtIEsValue {
	return &v.inject
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(v *BearersSubjectToStatusTransferItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldIsOpaque(v *BearersSubjectToStatusTransferItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldOpaque(v *BearersSubjectToStatusTransferItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTValueExtended {
	return &v.rowDLCOUNTValueExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTvaluePDCPSNlength18 {
	return &v.rowDLCOUNTValuePDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **s00.ReceiveStatusOfULPDCPSDUsExtended {
	return &v.rowReceiveStatusOfULPDCPSDUsExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18 {
	return &v.rowReceiveStatusOfULPDCPSDUsPDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTValueExtended {
	return &v.rowULCOUNTValueExtended
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(v *BearersSubjectToStatusTransferItemExtIEsValue) **COUNTvaluePDCPSNlength18 {
	return &v.rowULCOUNTValuePDCPSNlength18
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCaptureSemantics(v BearersSubjectToStatusTransferItemExtIEsValue, a0 aper.SemanticCapture) BearersSubjectToStatusTransferItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCompareSemantics(v BearersSubjectToStatusTransferItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(v BearersSubjectToStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh(v BearersSubjectToStatusTransferItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodMatchesID(v BearersSubjectToStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodRule(v BearersSubjectToStatusTransferItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeBluetoothMeasurementConfigurationFieldPerPadding(v *BluetoothMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeBluetoothMeasurementConfigurationFieldReceived(v *BluetoothMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeBluetoothMeasurementConfigurationFieldReceivedBytes(v *BluetoothMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBluetoothMeasurementConfigurationFieldReceivedLocation(v *BluetoothMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeBluetoothMeasurementConfigurationMethodMarshalAPERBudget(v *BluetoothMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationMethodUnmarshalAPERFrom(v *BluetoothMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldCapture(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, aper.DecodeState) (BluetoothMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldCompare(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldContext(v *BluetoothMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldDecode(v *BluetoothMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (BluetoothMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldEncode(v *BluetoothMeasurementConfigurationValueCodec) *func(BluetoothMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBluetoothMeasurementConfigurationValueCodecFieldPath(v *BluetoothMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeCGIMethodMarshalAPERTo(v *CGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCGIMethodUnmarshalAPERFrom(v *CGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCNTypeRestrictionsItemMethodMarshalAPERTo(v *CNTypeRestrictionsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCNTypeRestrictionsItemMethodUnmarshalAPERFrom(v *CNTypeRestrictionsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCNTypeRestrictionsValueCodecFieldCapture(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, aper.DecodeState) (CNTypeRestrictions, aper.Snapshot) {
	return &v.capture
}
func BridgeCNTypeRestrictionsValueCodecFieldCompare(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCNTypeRestrictionsValueCodecFieldContext(v *CNTypeRestrictionsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCNTypeRestrictionsValueCodecFieldDecode(v *CNTypeRestrictionsValueCodec) *func([]byte, aper.DecodeState) (CNTypeRestrictions, error) {
	return &v.decode
}
func BridgeCNTypeRestrictionsValueCodecFieldEncode(v *CNTypeRestrictionsValueCodec) *func(CNTypeRestrictions, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCNTypeRestrictionsValueCodecFieldPath(v *CNTypeRestrictionsValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTValueExtendedMethodMarshalAPERTo(v *COUNTValueExtended, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTValueExtendedMethodUnmarshalAPERFrom(v *COUNTValueExtended, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTValueExtendedValueCodecFieldCapture(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, aper.DecodeState) (COUNTValueExtended, aper.Snapshot) {
	return &v.capture
}
func BridgeCOUNTValueExtendedValueCodecFieldCompare(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCOUNTValueExtendedValueCodecFieldContext(v *COUNTValueExtendedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTValueExtendedValueCodecFieldDecode(v *COUNTValueExtendedValueCodec) *func([]byte, aper.DecodeState) (COUNTValueExtended, error) {
	return &v.decode
}
func BridgeCOUNTValueExtendedValueCodecFieldEncode(v *COUNTValueExtendedValueCodec) *func(COUNTValueExtended, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCOUNTValueExtendedValueCodecFieldPath(v *COUNTValueExtendedValueCodec) *aper.Path {
	return &v.path
}
func BridgeCOUNTvalueAPERValueFieldContext(v *COUNTvalueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCOUNTvalueAPERValueFieldReceived(v *COUNTvalueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTvalueAPERValueFieldReplay(v *COUNTvalueAPERValue) *aper.Snapshot { return &v.replay }
func BridgeCOUNTvalueAPERValueFieldWithoutReplay(v *COUNTvalueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCOUNTvalueFieldReceived(v *COUNTvalue) *bool               { return &v.received }
func BridgeCOUNTvalueFieldReceivedAbsolute(v *COUNTvalue) *bool       { return &v.receivedAbsolute }
func BridgeCOUNTvalueFieldReceivedBytes(v *COUNTvalue) *aper.WireSpan { return &v.receivedBytes }
func BridgeCOUNTvalueMethodMarshalAPERBudget(v *COUNTvalue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCOUNTvalueMethodMarshalAPERTo(v *COUNTvalue, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvalueMethodUnmarshalAPERFrom(v *COUNTvalue, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCOUNTvalueMethodUnmarshalAPERWithOptions(v *COUNTvalue, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERTo(v *COUNTvaluePDCPSNlength18, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERFrom(v *COUNTvaluePDCPSNlength18, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *BearersSubjectToStatusTransferItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 179:
		if value, ok := v.AsULCOUNTValueExtended(); ok {
			return value, true
		}
	case 180:
		if value, ok := v.AsDLCOUNTValueExtended(); ok {
			return value, true
		}
	case 181:
		if value, ok := v.AsReceiveStatusOfULPDCPSDUsExtended(); ok {
			return value, true
		}
	case 217:
		if value, ok := v.AsULCOUNTValuePDCPSNlength18(); ok {
			return value, true
		}
	case 218:
		if value, ok := v.AsDLCOUNTValuePDCPSNlength18(); ok {
			return value, true
		}
	case 219:
		if value, ok := v.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18(); ok {
			return value, true
		}
	}
	return nil, false
}
