// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	json "encoding/json"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	reflect "reflect"
	strconv "strconv"
	strings "strings"
	testing "testing"
)

func asn1VectorHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
func asn1VectorHexForFuzz(input string) []byte {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return decoded
}
func TestASN1VectorPathRejectsNegativeIndex(t *testing.T) {
	if _, err := asn1VectorValueAtPath(reflect.ValueOf([]int{1}), "[-1]"); err == nil {
		t.Fatal("asn1VectorValueAtPath accepted a negative index")
	}
}
func TestASN1VectorPathRejectsEmptySegments(t *testing.T) {
	value := reflect.ValueOf(struct{ Field int }{Field: 1})
	for _, path := range []string{"", ".Field", "Field.", "Field..Nested"} {
		if _, err := asn1VectorValueAtPath(value, path); err == nil {
			t.Errorf("asn1VectorValueAtPath accepted malformed path %q", path)
		}
	}
}
func asn1VectorAssertPath(t *testing.T, value any, path, expectedJSON string) {
	t.Helper()
	actual, err := asn1VectorValueAtPath(reflect.ValueOf(value), path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != expectedJSON {
		t.Fatalf("%s = %s, want %s", path, encoded, expectedJSON)
	}
}
func asn1VectorValueAtPath(current reflect.Value, path string) (any, error) {
	if path == "$" {
		return asn1VectorInterface(current)
	}
	segments := strings.Split(path, ".")
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("path %s: malformed empty segment", path)
		}
	}
	for _, segment := range segments {
		var err error
		current, err = asn1VectorDereference(current)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", path, err)
		}
		fieldEnd := strings.IndexByte(segment, '[')
		if fieldEnd == -1 {
			fieldEnd = len(segment)
		}
		field := segment[:fieldEnd]
		if field != "" {
			if current.Kind() == reflect.Map {
				current = current.MapIndex(reflect.ValueOf(field))
			} else {
				if current.Kind() != reflect.Struct {
					return nil, fmt.Errorf("path %s: %s is not a struct", path, field)
				}
				current = current.FieldByName(field)
			}
			if !current.IsValid() {
				return nil, fmt.Errorf("path %s: field %s is absent", path, field)
			}
		}
		for suffix := segment[fieldEnd:]; suffix != ""; {
			closeIndex := strings.IndexByte(suffix, ']')
			if closeIndex < 2 || suffix[0] != '[' {
				return nil, fmt.Errorf("path %s: malformed index", path)
			}
			index, err := strconv.Atoi(suffix[1:closeIndex])
			if err != nil {
				return nil, fmt.Errorf("path %s: malformed index: %w", path, err)
			}
			current, err = asn1VectorDereference(current)
			if err != nil {
				return nil, fmt.Errorf("path %s: %w", path, err)
			}
			if current.Kind() != reflect.Array && current.Kind() != reflect.Slice {
				return nil, fmt.Errorf("path %s: indexed value is not a list", path)
			}
			if index < 0 {
				return nil, fmt.Errorf("path %s: index %d is negative", path, index)
			}
			if index >= current.Len() {
				return nil, fmt.Errorf("path %s: index %d exceeds length %d", path, index, current.Len())
			}
			current = current.Index(index)
			suffix = suffix[closeIndex+1:]
		}
	}
	return asn1VectorInterface(current)
}
func asn1VectorDereference(value reflect.Value) (reflect.Value, error) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}, fmt.Errorf("encountered nil")
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return reflect.Value{}, fmt.Errorf("encountered invalid value")
	}
	return value, nil
}
func asn1VectorInterface(value reflect.Value) (any, error) {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, nil
		}
		value = value.Elem()
	}
	if value.IsValid() && value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, nil
	}
	if !value.IsValid() || !value.CanInterface() {
		return nil, fmt.Errorf("value is not accessible")
	}
	return value.Interface(), nil
}

var asn1TypedTableNames = map[string]string{
	"AdditionalGUTIExtIEsValue":                                s07.AdditionalGUTIExtIEs().ID().Source().Assignment,
	"AllocationAndRetentionPriorityExtIEsValue":                s07.AllocationAndRetentionPriorityExtIEs().ID().Source().Assignment,
	"InformationForCECapableUEsExtIEsValue":                    s09.InformationForCECapableUEsExtIEs().ID().Source().Assignment,
	"AssistanceDataForPagingExtIEsValue":                       s07.AssistanceDataForPagingExtIEs().ID().Source().Assignment,
	"AssistanceDataForRecommendedCellsExtIEsValue":             s07.AssistanceDataForRecommendedCellsExtIEs().ID().Source().Assignment,
	"BearersSubjectToStatusTransferItemIEValue":                s21.BearersSubjectToStatusTransferItemIEs().ID().Source().Assignment,
	"BearersSubjectToStatusTransferItemExtIEsValue":            s14.BearersSubjectToStatusTransferItemExtIEs().ID().Source().Assignment,
	"BearersSubjectToEarlyStatusTransferItemIEValue":           s15.BearersSubjectToEarlyStatusTransferItemIEs().ID().Source().Assignment,
	"BearersSubjectToEarlyStatusTransferItemExtIEsValue":       s07.BearersSubjectToEarlyStatusTransferItemExtIEs().ID().Source().Assignment,
	"BearersSubjectToDLDiscardingItemIEValue":                  s15.BearersSubjectToDLDiscardingItemIEs().ID().Source().Assignment,
	"BearersSubjectToDLDiscardingItemExtIEsValue":              s07.BearersSubjectToDLDiscardingItemExtIEs().ID().Source().Assignment,
	"BluetoothMeasurementConfigurationExtIEsValue":             s07.BluetoothMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"CancelledCellinEAIItemExtIEsValue":                        s07.CancelledCellinEAIItemExtIEs().ID().Source().Assignment,
	"CancelledCellinTAIItemExtIEsValue":                        s07.CancelledCellinTAIItemExtIEs().ID().Source().Assignment,
	"CellIdentifierAndCELevelForCECapableUEsExtIEsValue":       s07.CellIdentifierAndCELevelForCECapableUEsExtIEs().ID().Source().Assignment,
	"CellIDBroadcastItemExtIEsValue":                           s07.CellIDBroadcastItemExtIEs().ID().Source().Assignment,
	"CellIDCancelledItemExtIEsValue":                           s07.CellIDCancelledItemExtIEs().ID().Source().Assignment,
	"CellBasedMDTExtIEsValue":                                  s07.CellBasedMDTExtIEs().ID().Source().Assignment,
	"CellBasedQMCExtIEsValue":                                  s07.CellBasedQMCExtIEs().ID().Source().Assignment,
	"Cdma2000OneXSRVCCInfoExtIEsValue":                         s07.Cdma2000OneXSRVCCInfoExtIEs().ID().Source().Assignment,
	"CellTypeExtIEsValue":                                      s07.CellTypeExtIEs().ID().Source().Assignment,
	"CGIExtIEsValue":                                           s07.CGIExtIEs().ID().Source().Assignment,
	"CNTypeRestrictionsItemExtIEsValue":                        s07.CNTypeRestrictionsItemExtIEs().ID().Source().Assignment,
	"ConnectedengNBItemExtIEsValue":                            s07.ConnectedengNBItemExtIEs().ID().Source().Assignment,
	"ContextatSourceExtIEsValue":                               s07.ContextatSourceExtIEs().ID().Source().Assignment,
	"CSGIdListItemExtIEsValue":                                 s07.CSGIdListItemExtIEs().ID().Source().Assignment,
	"COUNTvalueExtIEsValue":                                    s07.COUNTvalueExtIEs().ID().Source().Assignment,
	"COUNTValueExtendedExtIEsValue":                            s07.COUNTValueExtendedExtIEs().ID().Source().Assignment,
	"COUNTvaluePDCPSNlength18ExtIEsValue":                      s07.COUNTvaluePDCPSNlength18ExtIEs().ID().Source().Assignment,
	"CriticalityDiagnosticsExtIEsValue":                        s07.CriticalityDiagnosticsExtIEs().ID().Source().Assignment,
	"CriticalityDiagnosticsIEItemExtIEsValue":                  s07.CriticalityDiagnosticsIEItemExtIEs().ID().Source().Assignment,
	"DAPSRequestInfoExtIEsValue":                               s07.DAPSRequestInfoExtIEs().ID().Source().Assignment,
	"DAPSResponseInfoListIEValue":                              s15.DAPSResponseInfoListIEs().ID().Source().Assignment,
	"DAPSResponseInfoItemExtIEsValue":                          s08.DAPSResponseInfoItemExtIEs().ID().Source().Assignment,
	"DAPSResponseInfoExtIEsValue":                              s08.DAPSResponseInfoExtIEs().ID().Source().Assignment,
	"ServedDCNsItemExtIEsValue":                                s11.ServedDCNsItemExtIEs().ID().Source().Assignment,
	"DLCPSecurityInformationExtIEsValue":                       s08.DLCPSecurityInformationExtIEs().ID().Source().Assignment,
	"EmergencyAreaIDBroadcastItemExtIEsValue":                  s09.EmergencyAreaIDBroadcastItemExtIEs().ID().Source().Assignment,
	"EmergencyAreaIDCancelledItemExtIEsValue":                  s09.EmergencyAreaIDCancelledItemExtIEs().ID().Source().Assignment,
	"CompletedCellinEAIItemExtIEsValue":                        s07.CompletedCellinEAIItemExtIEs().ID().Source().Assignment,
	"ENBEarlyStatusTransferTransparentContainerExtIEsValue":    s38.ENBEarlyStatusTransferTransparentContainerExtIEs().ID().Source().Assignment,
	"GERANCellIDExtIEsValue":                                   s09.GERANCellIDExtIEs().ID().Source().Assignment,
	"GlobalENBIDExtIEsValue":                                   s09.GlobalENBIDExtIEs().ID().Source().Assignment,
	"GlobalEnGNBIDExtIEsValue":                                 s09.GlobalEnGNBIDExtIEs().ID().Source().Assignment,
	"ENBStatusTransferTransparentContainerExtIEsValue":         s08.ENBStatusTransferTransparentContainerExtIEs().ID().Source().Assignment,
	"ENDCSONConfigurationTransferExtIEsValue":                  s08.ENDCSONConfigurationTransferExtIEs().ID().Source().Assignment,
	"ENDCTransferTypeRequestExtIEsValue":                       s08.ENDCTransferTypeRequestExtIEs().ID().Source().Assignment,
	"ENDCTransferTypeReplyExtIEsValue":                         s08.ENDCTransferTypeReplyExtIEs().ID().Source().Assignment,
	"ENDCSONeNBIdentificationExtIEsValue":                      s08.ENDCSONeNBIdentificationExtIEs().ID().Source().Assignment,
	"ENDCSONengNBIdentificationExtIEsValue":                    s08.ENDCSONengNBIdentificationExtIEs().ID().Source().Assignment,
	"ERABInformationListIEValue":                               s29.ERABInformationListIEs().ID().Source().Assignment,
	"ERABInformationListItemExtIEsValue":                       s29.ERABInformationListItemExtIEs().ID().Source().Assignment,
	"ERABItemIEValue":                                          s16.ERABItemIEs().ID().Source().Assignment,
	"ERABItemExtIEsValue":                                      s08.ERABItemExtIEs().ID().Source().Assignment,
	"ERABSecurityResultListIEValue":                            s30.ERABSecurityResultListIEs().ID().Source().Assignment,
	"ERABSecurityResultItemExtIEsValue":                        s08.ERABSecurityResultItemExtIEs().ID().Source().Assignment,
	"ERABUsageReportItemIEValue":                               s17.ERABUsageReportItemIEs().ID().Source().Assignment,
	"ERABUsageReportItemExtIEsValue":                           s09.ERABUsageReportItemExtIEs().ID().Source().Assignment,
	"ERABQoSParametersExtIEsValue":                             s08.ERABQoSParametersExtIEs().ID().Source().Assignment,
	"EUTRANCGIExtIEsValue":                                     s09.EUTRANCGIExtIEs().ID().Source().Assignment,
	"EventL1LoggedMDTConfigExtIEsValue":                        s09.EventL1LoggedMDTConfigExtIEs().ID().Source().Assignment,
	"EventTriggerExtIEValue":                                   s09.EventTriggerExtIEs().ID().Source().Assignment,
	"ExpectedUEBehaviourExtIEsValue":                           s09.ExpectedUEBehaviourExtIEs().ID().Source().Assignment,
	"ExpectedUEActivityBehaviourExtIEsValue":                   s09.ExpectedUEActivityBehaviourExtIEs().ID().Source().Assignment,
	"FiveGSTAIExtIEsValue":                                     s09.FiveGSTAIExtIEs().ID().Source().Assignment,
	"ForbiddenTAsItemExtIEsValue":                              s09.ForbiddenTAsItemExtIEs().ID().Source().Assignment,
	"ForbiddenLAsItemExtIEsValue":                              s09.ForbiddenLAsItemExtIEs().ID().Source().Assignment,
	"GBRQosInformationExtIEsValue":                             s09.GBRQosInformationExtIEs().ID().Source().Assignment,
	"GUMMEIExtIEsValue":                                        s09.GUMMEIExtIEs().ID().Source().Assignment,
	"HandoverRestrictionListExtIEsValue":                       s43.HandoverRestrictionListExtIEs().ID().Source().Assignment,
	"ImmediateMDTExtIEsValue":                                  s48.ImmediateMDTExtIEs().ID().Source().Assignment,
	"InformationOnRecommendedCellsAndENBsForPagingExtIEsValue": s09.InformationOnRecommendedCellsAndENBsForPagingExtIEs().ID().Source().Assignment,
	"IntersystemMeasurementConfigurationExtIEsValue":           s09.IntersystemMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"InterSystemMeasurementParametersExtIEsValue":              s09.InterSystemMeasurementParametersExtIEs().ID().Source().Assignment,
	"InterSystemMeasurementItemExtIEsValue":                    s09.InterSystemMeasurementItemExtIEs().ID().Source().Assignment,
	"LAIExtIEsValue":                                           s09.LAIExtIEs().ID().Source().Assignment,
	"LastVisitedEUTRANCellInformationExtIEsValue":              s42.LastVisitedEUTRANCellInformationExtIEs().ID().Source().Assignment,
	"LastVisitedPSCellInformationExtIEsValue":                  s09.LastVisitedPSCellInformationExtIEs().ID().Source().Assignment,
	"ListeningSubframePatternExtIEsValue":                      s09.ListeningSubframePatternExtIEs().ID().Source().Assignment,
	"LoggedMDTExtIEsValue":                                     s48.LoggedMDTExtIEs().ID().Source().Assignment,
	"LoggedMBSFNMDTExtIEsValue":                                s09.LoggedMBSFNMDTExtIEs().ID().Source().Assignment,
	"LTENTNTAIInformationExtIEsValue":                          s09.LTENTNTAIInformationExtIEs().ID().Source().Assignment,
	"M3ConfigurationExtIEsValue":                               s10.M3ConfigurationExtIEs().ID().Source().Assignment,
	"M4ConfigurationExtIEsValue":                               s10.M4ConfigurationExtIEs().ID().Source().Assignment,
	"M5ConfigurationExtIEsValue":                               s10.M5ConfigurationExtIEs().ID().Source().Assignment,
	"M6ConfigurationExtIEsValue":                               s10.M6ConfigurationExtIEs().ID().Source().Assignment,
	"M7ConfigurationExtIEsValue":                               s10.M7ConfigurationExtIEs().ID().Source().Assignment,
	"MDTConfigurationExtIEsValue":                              s42.MDTConfigurationExtIEs().ID().Source().Assignment,
	"MBSFNResultToLogInfoExtIEsValue":                          s10.MBSFNResultToLogInfoExtIEs().ID().Source().Assignment,
	"MDTModeExtensionIEIEValue":                                s24.MDTModeExtensionIE().ID().Source().Assignment,
	"MeasurementThresholdL1LoggedMDTExtIEValue":                s10.MeasurementThresholdL1LoggedMDTExtIEs().ID().Source().Assignment,
	"MutingPatternInformationExtIEsValue":                      s10.MutingPatternInformationExtIEs().ID().Source().Assignment,
	"NBIoTPagingEDRXInformationExtIEsValue":                    s10.NBIoTPagingEDRXInformationExtIEs().ID().Source().Assignment,
	"NRCGIExtIEsValue":                                         s10.NRCGIExtIEs().ID().Source().Assignment,
	"NRUESecurityCapabilitiesExtIEsValue":                      s10.NRUESecurityCapabilitiesExtIEs().ID().Source().Assignment,
	"NRV2XServicesAuthorizedExtIEsValue":                       s10.NRV2XServicesAuthorizedExtIEs().ID().Source().Assignment,
	"NRUESidelinkAggregateMaximumBitrateExtIEsValue":           s10.NRUESidelinkAggregateMaximumBitrateExtIEs().ID().Source().Assignment,
	"PagingAttemptInformationExtIEsValue":                      s10.PagingAttemptInformationExtIEs().ID().Source().Assignment,
	"PagingEDRXInformationExtIEsValue":                         s10.PagingEDRXInformationExtIEs().ID().Source().Assignment,
	"PC5QoSParametersExtIEsValue":                              s10.PC5QoSParametersExtIEs().ID().Source().Assignment,
	"PC5QoSFlowItemExtIEsValue":                                s10.PC5QoSFlowItemExtIEs().ID().Source().Assignment,
	"PC5FlowBitRatesExtIEsValue":                               s10.PC5FlowBitRatesExtIEs().ID().Source().Assignment,
	"M1PeriodicReportingExtIEsValue":                           s10.M1PeriodicReportingExtIEs().ID().Source().Assignment,
	"PLMNAreaBasedQMCExtIEsValue":                              s10.PLMNAreaBasedQMCExtIEs().ID().Source().Assignment,
	"ProSeAuthorizedExtIEsValue":                               s10.ProSeAuthorizedExtIEs().ID().Source().Assignment,
	"PSCellInformationExtIEsValue":                             s10.PSCellInformationExtIEs().ID().Source().Assignment,
	"RecommendedCellsForPagingExtIEsValue":                     s11.RecommendedCellsForPagingExtIEs().ID().Source().Assignment,
	"RecommendedCellItemIEValue":                               s26.RecommendedCellItemIEs().ID().Source().Assignment,
	"RecommendedCellsForPagingItemExtIEsValue":                 s11.RecommendedCellsForPagingItemExtIEs().ID().Source().Assignment,
	"RecommendedENBsForPagingExtIEsValue":                      s11.RecommendedENBsForPagingExtIEs().ID().Source().Assignment,
	"RecommendedENBItemIEValue":                                s32.RecommendedENBItemIEs().ID().Source().Assignment,
	"RecommendedENBItemExtIEsValue":                            s11.RecommendedENBItemExtIEs().ID().Source().Assignment,
	"RATRestrictionsItemExtIEsValue":                           s10.RATRestrictionsItemExtIEs().ID().Source().Assignment,
	"RequestedTNLInfoExtIEsValue":                              s11.RequestedTNLInfoExtIEs().ID().Source().Assignment,
	"RequestTypeExtIEsValue":                                   s11.RequestTypeExtIEs().ID().Source().Assignment,
	"RIMTransferExtIEsValue":                                   s10.RIMTransferExtIEs().ID().Source().Assignment,
	"RLFReportInformationExtIEsValue":                          s10.RLFReportInformationExtIEs().ID().Source().Assignment,
	"SecurityContextExtIEsValue":                               s11.SecurityContextExtIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportItemIEValue":                   s28.SecondaryRATDataUsageReportItemIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportItemExtIEsValue":               s11.SecondaryRATDataUsageReportItemExtIEs().ID().Source().Assignment,
	"SecurityIndicationExtIEsValue":                            s11.SecurityIndicationExtIEs().ID().Source().Assignment,
	"SecurityResultExtIEsValue":                                s11.SecurityResultExtIEs().ID().Source().Assignment,
	"SensorMeasConfigNameItemExtIEsValue":                      s11.SensorMeasConfigNameItemExtIEs().ID().Source().Assignment,
	"SensorMeasurementConfigurationExtIEsValue":                s11.SensorMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"SensorNameConfigExtIEValue":                               s11.SensorNameConfigExtIEs().ID().Source().Assignment,
	"SONInformationExtensionIEIEValue":                         s20.SONInformationExtensionIE().ID().Source().Assignment,
	"SONInformationReplyExtIEsValue":                           s35.SONInformationReplyExtIEs().ID().Source().Assignment,
	"SONConfigurationTransferExtIEsValue":                      s51.SONConfigurationTransferExtIEs().ID().Source().Assignment,
	"SynchronisationInformationExtIEsValue":                    s11.SynchronisationInformationExtIEs().ID().Source().Assignment,
	"SourceeNBIDExtIEsValue":                                   s11.SourceeNBIDExtIEs().ID().Source().Assignment,
	"SourceNodeIDExtensionIEIEValue":                           s11.SourceNodeIDExtensionIE().ID().Source().Assignment,
	"SourceeNBToTargeteNBTransparentContainerExtIEsValue":      s35.SourceeNBToTargeteNBTransparentContainerExtIEs().ID().Source().Assignment,
	"SourceNgRanNodeIDExtIEsValue":                             s11.SourceNgRanNodeIDExtIEs().ID().Source().Assignment,
	"ServedGUMMEIsItemExtIEsValue":                             s11.ServedGUMMEIsItemExtIEs().ID().Source().Assignment,
	"SubscriptionBasedUEDifferentiationInfoExtIEsValue":        s11.SubscriptionBasedUEDifferentiationInfoExtIEs().ID().Source().Assignment,
	"ScheduledCommunicationTimeExtIEsValue":                    s11.ScheduledCommunicationTimeExtIEs().ID().Source().Assignment,
	"SupportedTAsItemExtIEsValue":                              s11.SupportedTAsItemExtIEs().ID().Source().Assignment,
	"TimeSynchronisationInfoExtIEsValue":                       s12.TimeSynchronisationInfoExtIEs().ID().Source().Assignment,
	"STMSIExtIEsValue":                                         s11.STMSIExtIEs().ID().Source().Assignment,
	"TAIBasedMDTExtIEsValue":                                   s11.TAIBasedMDTExtIEs().ID().Source().Assignment,
	"TAIExtIEsValue":                                           s11.TAIExtIEs().ID().Source().Assignment,
	"TAIBroadcastItemExtIEsValue":                              s11.TAIBroadcastItemExtIEs().ID().Source().Assignment,
	"TAICancelledItemExtIEsValue":                              s11.TAICancelledItemExtIEs().ID().Source().Assignment,
	"TABasedMDTExtIEsValue":                                    s11.TABasedMDTExtIEs().ID().Source().Assignment,
	"TABasedQMCExtIEsValue":                                    s11.TABasedQMCExtIEs().ID().Source().Assignment,
	"TAIBasedQMCExtIEsValue":                                   s11.TAIBasedQMCExtIEs().ID().Source().Assignment,
	"CompletedCellinTAIItemExtIEsValue":                        s07.CompletedCellinTAIItemExtIEs().ID().Source().Assignment,
	"TargeteNBIDExtIEsValue":                                   s11.TargeteNBIDExtIEs().ID().Source().Assignment,
	"TargetRNCIDExtIEsValue":                                   s11.TargetRNCIDExtIEs().ID().Source().Assignment,
	"TargetNgRanNodeIDExtIEsValue":                             s11.TargetNgRanNodeIDExtIEs().ID().Source().Assignment,
	"GNBExtIEsValue":                                           s09.GNBExtIEs().ID().Source().Assignment,
	"GlobalGNBIDExtIEsValue":                                   s09.GlobalGNBIDExtIEs().ID().Source().Assignment,
	"NGENBExtIEsValue":                                         s10.NGENBExtIEs().ID().Source().Assignment,
	"TargeteNBToSourceeNBTransparentContainerExtIEsValue":      s40.TargeteNBToSourceeNBTransparentContainerExtIEs().ID().Source().Assignment,
	"M1ThresholdEventA2ExtIEsValue":                            s10.M1ThresholdEventA2ExtIEs().ID().Source().Assignment,
	"TimeBasedHandoverInformationExtIEsValue":                  s11.TimeBasedHandoverInformationExtIEs().ID().Source().Assignment,
	"TraceActivationExtIEsValue":                               s48.TraceActivationExtIEs().ID().Source().Assignment,
	"TunnelInformationExtIEsValue":                             s12.TunnelInformationExtIEs().ID().Source().Assignment,
	"UEAggregateMaximumBitratesExtIEsValue":                    s12.UEAggregateMaximumBitratesExtIEs().ID().Source().Assignment,
	"UEAppLayerMeasConfigExtIEsValue":                          s12.UEAppLayerMeasConfigExtIEs().ID().Source().Assignment,
	"UES1APIDPairExtIEsValue":                                  s12.UES1APIDPairExtIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemExtIEsValue":           s12.UEAssociatedLogicalS1ConnectionItemExtIEs().ID().Source().Assignment,
	"UESecurityCapabilitiesExtIEsValue":                        s12.UESecurityCapabilitiesExtIEs().ID().Source().Assignment,
	"UESidelinkAggregateMaximumBitratesExtIEsValue":            s12.UESidelinkAggregateMaximumBitratesExtIEs().ID().Source().Assignment,
	"ULCPSecurityInformationExtIEsValue":                       s12.ULCPSecurityInformationExtIEs().ID().Source().Assignment,
	"UserLocationInformationExtIEsValue":                       s21.UserLocationInformationExtIEs().ID().Source().Assignment,
	"V2XServicesAuthorizedExtIEsValue":                         s12.V2XServicesAuthorizedExtIEs().ID().Source().Assignment,
	"WLANMeasurementConfigurationExtIEsValue":                  s12.WLANMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"WUSAssistanceInformationExtIEsValue":                      s12.WUSAssistanceInformationExtIEs().ID().Source().Assignment,
	"X2TNLConfigurationInfoExtIEsValue":                        s39.X2TNLConfigurationInfoExtIEs().ID().Source().Assignment,
	"ENBX2ExtTLAExtIEsValue":                                   s08.ENBX2ExtTLAExtIEs().ID().Source().Assignment,
	"HandoverRequiredIEValue":                                  s34.HandoverRequiredIEs().ID().Source().Assignment,
	"HandoverCommandIEValue":                                   s41.HandoverCommandIEs().ID().Source().Assignment,
	"ERABDataForwardingItemIEValue":                            s15.ERABDataForwardingItemIEs().ID().Source().Assignment,
	"ERABDataForwardingItemExtIEsValue":                        s08.ERABDataForwardingItemExtIEs().ID().Source().Assignment,
	"HandoverPreparationFailureIEValue":                        s22.HandoverPreparationFailureIEs().ID().Source().Assignment,
	"HandoverRequestIEValue":                                   s49.HandoverRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemHOReqIEValue":                            s30.ERABToBeSetupItemHOReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemHOReqExtIEsValue":                        s29.ERABToBeSetupItemHOReqExtIEs().ID().Source().Assignment,
	"HandoverRequestAcknowledgeIEValue":                        s39.HandoverRequestAcknowledgeIEs().ID().Source().Assignment,
	"ERABAdmittedItemIEValue":                                  s15.ERABAdmittedItemIEs().ID().Source().Assignment,
	"ERABAdmittedItemExtIEsValue":                              s08.ERABAdmittedItemExtIEs().ID().Source().Assignment,
	"ERABFailedtoSetupItemHOReqAckIEValue":                     s16.ERABFailedtoSetupItemHOReqAckIEs().ID().Source().Assignment,
	"ERABFailedToSetupItemHOReqAckExtIEsValue":                 s08.ERABFailedToSetupItemHOReqAckExtIEs().ID().Source().Assignment,
	"HandoverFailureIEValue":                                   s22.HandoverFailureIEs().ID().Source().Assignment,
	"HandoverNotifyIEValue":                                    s35.HandoverNotifyIEs().ID().Source().Assignment,
	"PathSwitchRequestIEValue":                                 s41.PathSwitchRequestIEs().ID().Source().Assignment,
	"ERABToBeSwitchedDLItemIEValue":                            s30.ERABToBeSwitchedDLItemIEs().ID().Source().Assignment,
	"ERABToBeSwitchedDLItemExtIEsValue":                        s29.ERABToBeSwitchedDLItemExtIEs().ID().Source().Assignment,
	"PathSwitchRequestAcknowledgeIEValue":                      s47.PathSwitchRequestAcknowledgeIEs().ID().Source().Assignment,
	"ERABToBeSwitchedULItemIEValue":                            s17.ERABToBeSwitchedULItemIEs().ID().Source().Assignment,
	"ERABToBeSwitchedULItemExtIEsValue":                        s09.ERABToBeSwitchedULItemExtIEs().ID().Source().Assignment,
	"ERABToBeUpdatedItemIEValue":                               s29.ERABToBeUpdatedItemIEs().ID().Source().Assignment,
	"ERABToBeUpdatedItemExtIEsValue":                           s09.ERABToBeUpdatedItemExtIEs().ID().Source().Assignment,
	"PathSwitchRequestFailureIEValue":                          s23.PathSwitchRequestFailureIEs().ID().Source().Assignment,
	"HandoverCancelIEValue":                                    s18.HandoverCancelIEs().ID().Source().Assignment,
	"HandoverCancelAcknowledgeIEValue":                         s22.HandoverCancelAcknowledgeIEs().ID().Source().Assignment,
	"HandoverSuccessIEValue":                                   s09.HandoverSuccessIEs().ID().Source().Assignment,
	"ENBEarlyStatusTransferIEValue":                            s38.ENBEarlyStatusTransferIEs().ID().Source().Assignment,
	"MMEEarlyStatusTransferIEValue":                            s38.MMEEarlyStatusTransferIEs().ID().Source().Assignment,
	"ERABSetupRequestIEValue":                                  s41.ERABSetupRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemBearerSUReqIEValue":                      s30.ERABToBeSetupItemBearerSUReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemBearerSUReqExtIEsValue":                  s29.ERABToBeSetupItemBearerSUReqExtIEs().ID().Source().Assignment,
	"ERABSetupResponseIEValue":                                 s46.ERABSetupResponseIEs().ID().Source().Assignment,
	"ERABSetupItemBearerSUResIEValue":                          s17.ERABSetupItemBearerSUResIEs().ID().Source().Assignment,
	"ERABSetupItemBearerSUResExtIEsValue":                      s08.ERABSetupItemBearerSUResExtIEs().ID().Source().Assignment,
	"ERABModifyRequestIEValue":                                 s41.ERABModifyRequestIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModReqIEValue":                  s25.ERABToBeModifiedItemBearerModReqIEs().ID().Source().Assignment,
	"ERABToBeModifyItemBearerModReqExtIEsValue":                s21.ERABToBeModifyItemBearerModReqExtIEs().ID().Source().Assignment,
	"ERABModifyResponseIEValue":                                s46.ERABModifyResponseIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModResIEValue":                        s16.ERABModifyItemBearerModResIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModResExtIEsValue":                    s08.ERABModifyItemBearerModResExtIEs().ID().Source().Assignment,
	"ERABReleaseCommandIEValue":                                s40.ERABReleaseCommandIEs().ID().Source().Assignment,
	"ERABReleaseResponseIEValue":                               s46.ERABReleaseResponseIEs().ID().Source().Assignment,
	"ERABReleaseItemBearerRelCompIEValue":                      s16.ERABReleaseItemBearerRelCompIEs().ID().Source().Assignment,
	"ERABReleaseItemBearerRelCompExtIEsValue":                  s08.ERABReleaseItemBearerRelCompExtIEs().ID().Source().Assignment,
	"ERABReleaseIndicationIEValue":                             s46.ERABReleaseIndicationIEs().ID().Source().Assignment,
	"InitialContextSetupRequestIEValue":                        s49.InitialContextSetupRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemCtxtSUReqIEValue":                        s30.ERABToBeSetupItemCtxtSUReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemCtxtSUReqExtIEsValue":                    s29.ERABToBeSetupItemCtxtSUReqExtIEs().ID().Source().Assignment,
	"InitialContextSetupResponseIEValue":                       s40.InitialContextSetupResponseIEs().ID().Source().Assignment,
	"ERABSetupItemCtxtSUResIEValue":                            s17.ERABSetupItemCtxtSUResIEs().ID().Source().Assignment,
	"ERABSetupItemCtxtSUResExtIEsValue":                        s09.ERABSetupItemCtxtSUResExtIEs().ID().Source().Assignment,
	"InitialContextSetupFailureIEValue":                        s23.InitialContextSetupFailureIEs().ID().Source().Assignment,
	"PagingIEValue":                                            s50.PagingIEs().ID().Source().Assignment,
	"TAIItemIEValue":                                           s34.TAIItemIEs().ID().Source().Assignment,
	"TAIItemExtIEsValue":                                       s11.TAIItemExtIEs().ID().Source().Assignment,
	"UEContextReleaseRequestIEValue":                           s43.UEContextReleaseRequestIEs().ID().Source().Assignment,
	"UEContextReleaseCommandIEValue":                           s37.UEContextReleaseCommandIEs().ID().Source().Assignment,
	"UEContextReleaseCompleteIEValue":                          s46.UEContextReleaseCompleteIEs().ID().Source().Assignment,
	"UEContextModificationRequestIEValue":                      s47.UEContextModificationRequestIEs().ID().Source().Assignment,
	"UEContextModificationResponseIEValue":                     s24.UEContextModificationResponseIEs().ID().Source().Assignment,
	"UEContextModificationFailureIEValue":                      s23.UEContextModificationFailureIEs().ID().Source().Assignment,
	"UERadioCapabilityMatchRequestIEValue":                     s12.UERadioCapabilityMatchRequestIEs().ID().Source().Assignment,
	"UERadioCapabilityMatchResponseIEValue":                    s24.UERadioCapabilityMatchResponseIEs().ID().Source().Assignment,
	"DownlinkNASTransportIEValue":                              s43.DownlinkNASTransportIEs().ID().Source().Assignment,
	"InitialUEMessageIEValue":                                  s36.InitialUEMessageIEs().ID().Source().Assignment,
	"UplinkNASTransportIEValue":                                s32.UplinkNASTransportIEs().ID().Source().Assignment,
	"NASNonDeliveryIndicationIEValue":                          s19.NASNonDeliveryIndicationIEs().ID().Source().Assignment,
	"RerouteNASRequestIEValue":                                 s20.RerouteNASRequestIEs().ID().Source().Assignment,
	"NASDeliveryIndicationIEValue":                             s10.NASDeliveryIndicationIEs().ID().Source().Assignment,
	"ResetIEValue":                                             s36.ResetIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemResIEValue":            s36.UEAssociatedLogicalS1ConnectionItemRes().ID().Source().Assignment,
	"ResetAcknowledgeIEValue":                                  s45.ResetAcknowledgeIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemResAckIEValue":         s36.UEAssociatedLogicalS1ConnectionItemResAck().ID().Source().Assignment,
	"ErrorIndicationIEValue":                                   s28.ErrorIndicationIEs().ID().Source().Assignment,
	"S1SetupRequestIEValue":                                    s44.S1SetupRequestIEs().ID().Source().Assignment,
	"S1SetupResponseIEValue":                                   s44.S1SetupResponseIEs().ID().Source().Assignment,
	"S1SetupFailureIEValue":                                    s23.S1SetupFailureIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateIEValue":                            s44.ENBConfigurationUpdateIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateAcknowledgeIEValue":                 s22.ENBConfigurationUpdateAcknowledgeIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateFailureIEValue":                     s22.ENBConfigurationUpdateFailureIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateIEValue":                            s44.MMEConfigurationUpdateIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateAcknowledgeIEValue":                 s23.MMEConfigurationUpdateAcknowledgeIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateFailureIEValue":                     s23.MMEConfigurationUpdateFailureIEs().ID().Source().Assignment,
	"DownlinkS1cdma2000tunnellingIEValue":                      s40.DownlinkS1cdma2000tunnellingIEs().ID().Source().Assignment,
	"UplinkS1cdma2000tunnellingIEValue":                        s21.UplinkS1cdma2000tunnellingIEs().ID().Source().Assignment,
	"UECapabilityInfoIndicationIEValue":                        s12.UECapabilityInfoIndicationIEs().ID().Source().Assignment,
	"ENBStatusTransferIEValue":                                 s22.ENBStatusTransferIEs().ID().Source().Assignment,
	"MMEStatusTransferIEValue":                                 s22.MMEStatusTransferIEs().ID().Source().Assignment,
	"TraceStartIEValue":                                        s49.TraceStartIEs().ID().Source().Assignment,
	"TraceFailureIndicationIEValue":                            s21.TraceFailureIndicationIEs().ID().Source().Assignment,
	"DeactivateTraceIEValue":                                   s08.DeactivateTraceIEs().ID().Source().Assignment,
	"CellTrafficTraceIEValue":                                  s18.CellTrafficTraceIEs().ID().Source().Assignment,
	"LocationReportingControlIEValue":                          s26.LocationReportingControlIEs().ID().Source().Assignment,
	"LocationReportingFailureIndicationIEValue":                s19.LocationReportingFailureIndicationIEs().ID().Source().Assignment,
	"LocationReportIEValue":                                    s32.LocationReportIEs().ID().Source().Assignment,
	"OverloadStartIEValue":                                     s42.OverloadStartIEs().ID().Source().Assignment,
	"OverloadStopIEValue":                                      s42.OverloadStopIEs().ID().Source().Assignment,
	"WriteReplaceWarningRequestIEValue":                        s33.WriteReplaceWarningRequestIEs().ID().Source().Assignment,
	"WriteReplaceWarningResponseIEValue":                       s33.WriteReplaceWarningResponseIEs().ID().Source().Assignment,
	"ENBDirectInformationTransferIEValue":                      s34.ENBDirectInformationTransferIEs().ID().Source().Assignment,
	"MMEDirectInformationTransferIEValue":                      s34.MMEDirectInformationTransferIEs().ID().Source().Assignment,
	"ENBConfigurationTransferIEValue":                          s52.ENBConfigurationTransferIEs().ID().Source().Assignment,
	"MMEConfigurationTransferIEValue":                          s52.MMEConfigurationTransferIEs().ID().Source().Assignment,
	"KillRequestIEValue":                                       s33.KillRequestIEs().ID().Source().Assignment,
	"KillResponseIEValue":                                      s33.KillResponseIEs().ID().Source().Assignment,
	"PWSRestartIndicationIEValue":                              s44.PWSRestartIndicationIEs().ID().Source().Assignment,
	"PWSFailureIndicationIEValue":                              s43.PWSFailureIndicationIEs().ID().Source().Assignment,
	"DownlinkUEAssociatedLPPaTransportIEValue":                 s08.DownlinkUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"UplinkUEAssociatedLPPaTransportIEValue":                   s12.UplinkUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"DownlinkNonUEAssociatedLPPaTransportIEValue":              s08.DownlinkNonUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"UplinkNonUEAssociatedLPPaTransportIEValue":                s12.UplinkNonUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"ERABModificationIndicationIEValue":                        s46.ERABModificationIndicationIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModIndIEValue":                  s17.ERABToBeModifiedItemBearerModIndIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModIndExtIEsValue":              s09.ERABToBeModifiedItemBearerModIndExtIEs().ID().Source().Assignment,
	"ERABNotToBeModifiedItemBearerModIndIEValue":               s16.ERABNotToBeModifiedItemBearerModIndIEs().ID().Source().Assignment,
	"ERABNotToBeModifiedItemBearerModIndExtIEsValue":           s08.ERABNotToBeModifiedItemBearerModIndExtIEs().ID().Source().Assignment,
	"CSGMembershipInfoExtIEsValue":                             s07.CSGMembershipInfoExtIEs().ID().Source().Assignment,
	"ERABModificationConfirmIEValue":                           s40.ERABModificationConfirmIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModConfIEValue":                       s16.ERABModifyItemBearerModConfIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModConfExtIEsValue":                   s08.ERABModifyItemBearerModConfExtIEs().ID().Source().Assignment,
	"UEContextModificationIndicationIEValue":                   s21.UEContextModificationIndicationIEs().ID().Source().Assignment,
	"UEContextModificationConfirmIEValue":                      s23.UEContextModificationConfirmIEs().ID().Source().Assignment,
	"UEContextSuspendRequestIEValue":                           s46.UEContextSuspendRequestIEs().ID().Source().Assignment,
	"UEContextSuspendResponseIEValue":                          s29.UEContextSuspendResponseIEs().ID().Source().Assignment,
	"UEContextResumeRequestIEValue":                            s39.UEContextResumeRequestIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeReqIEValue":                   s16.ERABFailedToResumeItemResumeReqIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeReqExtIEsValue":               s08.ERABFailedToResumeItemResumeReqExtIEs().ID().Source().Assignment,
	"UEContextResumeResponseIEValue":                           s39.UEContextResumeResponseIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeResIEValue":                   s16.ERABFailedToResumeItemResumeResIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeResExtIEsValue":               s08.ERABFailedToResumeItemResumeResExtIEs().ID().Source().Assignment,
	"UEContextResumeFailureIEValue":                            s24.UEContextResumeFailureIEs().ID().Source().Assignment,
	"ConnectionEstablishmentIndicationIEValue":                 s31.ConnectionEstablishmentIndicationIEs().ID().Source().Assignment,
	"RetrieveUEInformationIEValue":                             s28.RetrieveUEInformationIEs().ID().Source().Assignment,
	"UEInformationTransferIEValue":                             s31.UEInformationTransferIEs().ID().Source().Assignment,
	"ENBCPRelocationIndicationIEValue":                         s38.ENBCPRelocationIndicationIEs().ID().Source().Assignment,
	"MMECPRelocationIndicationIEValue":                         s10.MMECPRelocationIndicationIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportIEValue":                       s46.SecondaryRATDataUsageReportIEs().ID().Source().Assignment,
	"UERadioCapabilityIDMappingRequestIEValue":                 s12.UERadioCapabilityIDMappingRequestIEs().ID().Source().Assignment,
	"UERadioCapabilityIDMappingResponseIEValue":                s24.UERadioCapabilityIDMappingResponseIEs().ID().Source().Assignment,
	"S1RemovalRequestIEValue":                                  s20.S1RemovalRequestIEs().ID().Source().Assignment,
	"S1RemovalResponseIEValue":                                 s23.S1RemovalResponseIEs().ID().Source().Assignment,
	"S1RemovalFailureIEValue":                                  s23.S1RemovalFailureIEs().ID().Source().Assignment,
}

func asn1SelectedObserve(value reflect.Value) {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return
	}
	if value.Kind() == reflect.Struct {
		pointer := reflect.New(value.Type())
		pointer.Elem().Set(value)
		if selected, ok := pointer.Interface().(interface{ Selected() (any, bool) }); ok {
			var want any
			var row string
			for i := 0; i < pointer.NumMethod(); i++ {
				method := pointer.Type().Method(i)
				if !strings.HasPrefix(method.Name, "As") {
					continue
				}
				call := pointer.Method(i)
				if call.Type().NumIn() != 0 || call.Type().NumOut() != 2 || call.Type().Out(1).Kind() != reflect.Bool {
					continue
				}
				result := call.Call(nil)
				if result[1].Bool() {
					want = result[0].Interface()
					row = method.Name
					break
				}
			}
			got, active := selected.Selected()
			if active != (want != nil) || got != want {
				panic("Selected differs from As accessor")
			}
			if row != "" {
				fmt.Printf("selected decoded row %s.%s\n", value.Type().Name(), row)
				asn1SelectedObserve(reflect.ValueOf(got))
			}
			return
		}
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				asn1SelectedObserve(value.Field(i))
			}
		}
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < value.Len(); i++ {
			asn1SelectedObserve(value.Index(i))
		}
	}
}
func asn1TypedProjection(value reflect.Value, path string) any {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Struct {
		pointer := reflect.New(value.Type())
		pointer.Elem().Set(value)
		if _, ok := pointer.Interface().(json.Marshaler); ok {
			return pointer.Interface()
		}
		for i := 0; i < pointer.NumMethod(); i++ {
			method := pointer.Type().Method(i)
			if !strings.HasPrefix(method.Name, "As") {
				continue
			}
			call := pointer.Method(i)
			if call.Type().NumIn() != 0 || call.Type().NumOut() != 2 || call.Type().Out(1).Kind() != reflect.Bool {
				continue
			}
			results := call.Call(nil)
			if results[1].Bool() {
				return asn1TypedProjection(results[0], path)
			}
		}
		if method := pointer.MethodByName("Opaque"); method.IsValid() {
			results := method.Call(nil)
			if results[1].Bool() {
				contents := results[0].Interface().(interface{ Bytes() []byte }).Bytes()
				return map[string]any{"Bytes": contents}
			}
			return nil
		}
		result := map[string]any{}
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			result[field.Name] = asn1TypedProjection(value.Field(i), path+"."+field.Name)
		}
		selected := "Value"
		if _, ok := result["ExtensionValue"]; ok {
			selected = "ExtensionValue"
		}
		if field := value.FieldByName(selected); field.IsValid() {
			typ := field.Type()
			for typ.Kind() == reflect.Pointer {
				typ = typ.Elem()
			}
			if table, ok := asn1TypedTableNames[typ.Name()]; ok {
				original := map[string]any{}
				for k, v := range result {
					original[k] = v
				}
				result["Field"] = original
				result["ObjectSet"] = table
				result["Path"] = path
				inner := result[selected]
				if object, ok := inner.(map[string]any); ok {
					if _, opaque := object["Bytes"]; opaque && len(object) == 1 {
						result["Value"] = nil
					} else {
						result["Value"] = inner
						result["Extensions"] = object["IEExtensions"]
						result["Children"] = object["ProtocolIEs"]
					}
				}
				if list, ok := inner.([]any); ok {
					result["ProtocolIEs"] = list
					result["Children"] = list
				}
			}
		}
		return result
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return value.Interface()
		}
		list := make([]any, value.Len())
		for i := range list {
			list[i] = asn1TypedProjection(value.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
		return list
	}
	return value.Interface()
}

// TestVectorUeContextReleaseRequestCauseNas verifies 3GPP TS 36.413 V19.2.0 (2026-06), sections 9.1.4.5 and 9.3.4; CauseNas has four root values before the extension marker.
func TestVectorUeContextReleaseRequestCauseNas(t *testing.T) {
	input := asn1VectorHex(t, "001240140000030000000200010008000200020002400126")
	var decoded s53.S1APPDU
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	var body any
	switch decoded.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		body = &decoded.InitiatingMessage.Value
	case s00.S1APPDUChoiceSuccessfulOutcome:
		body = &decoded.SuccessfulOutcome.Value
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		body = &decoded.UnsuccessfulOutcome.Value
	default:
		t.Fatal("unknown PDU body")
	}
	subject := asn1TypedProjection(reflect.ValueOf(body), "S1APPDU")
	asn1VectorAssertPath(t, subject, "ProtocolIEs[2].Value.Choice", "3")
	asn1VectorAssertPath(t, subject, "ProtocolIEs[2].Value.Nas", "3")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorCauseNasRootExtensionBoundary verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4, Cause and CauseNas.
func TestVectorCauseNasRootExtensionBoundary(t *testing.T) {
	input := asn1VectorHex(t, "26")
	var decoded s14.Cause
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(&decoded), "Cause")
	asn1VectorAssertPath(t, subject, "Choice", "3")
	asn1VectorAssertPath(t, subject, "Nas", "3")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationDapsExtensionRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-06), sections 9.3.4 and 9.3.6; id-DAPSRequestInfo 317.
func TestVectorErabInformationDapsExtensionRecursive(t *testing.T) {
	input := asn1VectorHex(t, "250000013d400100")
	var decoded s29.ERABInformationListItem
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.IEExtensions), "ERABInformationListItem.IEExtensions")
	asn1VectorAssertPath(t, subject, "[0].Path", "\"ERABInformationListItem.IEExtensions[0]\"")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"E-RABInformationListItem-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Value.DAPSIndicator", "0")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationUnknownExtensionPreserved verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; unknown/private ProtocolExtensionField values remain raw.
func TestVectorErabInformationUnknownExtensionPreserved(t *testing.T) {
	input := asn1VectorHex(t, "250000fffc4004deadbeef")
	var decoded s29.ERABInformationListItem
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.IEExtensions), "ERABInformationListItem.IEExtensions")
	asn1VectorAssertPath(t, subject, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, subject, "[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorErabInformationMalformedDapsFullPath verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; malformed DAPS extension diagnostics retain the complete containing path.
func TestVectorErabInformationMalformedDapsFullPath(t *testing.T) {
	input := asn1VectorHex(t, "250000013d4001ff")
	var decoded s29.ERABInformationListItem
	_, err := decoded.UnmarshalAPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "non-zero APER alignment padding") {
		t.Fatalf("decode error = %v", err)
	}
	if !strings.Contains(err.Error(), "ERABInformationListItem.IEExtensions[0]") {
		t.Fatalf("decode path = %v", err)
	}
}

// TestVectorProtocolIeFieldConstrainedHeader verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.7; ProtocolIE-Field APER constrained header.
func TestVectorProtocolIeFieldConstrainedHeader(t *testing.T) {
	input := asn1VectorHex(t, "12344001aa")
	codec := s13.EventTriggerExtIEValueIEFieldTableCodec(s09.EventTriggerExtIEs().Table())
	complete, _, err := codec.DecodeAPER(input)
	decoded := complete.Value
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(&decoded), "ProtocolIEField")
	asn1VectorAssertPath(t, subject, "Field.Id", "4660")
	asn1VectorAssertPath(t, subject, "Field.Criticality", "1")
	asn1VectorAssertPath(t, subject, "Field.Value.Bytes", "\"qg==\"")
	wire, err := codec.EncodeAPER(complete)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorS1apPduConstrainedHeader verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.2; S1AP-PDU APER constrained header.
func TestVectorS1apPduConstrainedHeader(t *testing.T) {
	input := asn1VectorHex(t, "002e0002bbcc")
	var decoded s53.S1APPDU
	_, err := decoded.UnmarshalAPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "non-zero APER alignment padding") {
		t.Fatalf("decode error = %v", err)
	}
}

// TestVectorPagingTaiListRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-06), sections 9.1.6 and 9.3.3; Paging TAIList applies TAIItemIEs recursively.
func TestVectorPagingTaiListRecursive(t *testing.T) {
	input := asn1VectorHex(t, "000001002e400b00002f40060001f0101234")
	var decoded s50.Paging
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.ProtocolIEs), "Paging")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"PagingIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Children[0].ObjectSet", "\"TAIItemIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Children[0].Value.TAI.PLMNidentity", "\"AfAQ\"")
	asn1VectorAssertPath(t, subject, "[0].Children[0].Value.TAI.TAC", "\"EjQ=\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorPagingProcedureRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.1.6; initiating Paging procedure recursively resolves its argument and nested TAI items.
func TestVectorPagingProcedureRecursive(t *testing.T) {
	input := asn1VectorHex(t, "000a4012000001002e400b00002f40060001f0101234")
	var decoded s53.S1APPDU
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	var body any
	switch decoded.Choice {
	case s00.S1APPDUChoiceInitiatingMessage:
		body = &decoded.InitiatingMessage.Value
	case s00.S1APPDUChoiceSuccessfulOutcome:
		body = &decoded.SuccessfulOutcome.Value
	case s00.S1APPDUChoiceUnsuccessfulOutcome:
		body = &decoded.UnsuccessfulOutcome.Value
	default:
		t.Fatal("unknown PDU body")
	}
	subject := asn1TypedProjection(reflect.ValueOf(body), "S1APPDU")
	asn1VectorAssertPath(t, subject, "ProtocolIEs[0].ObjectSet", "\"PagingIEs\"")
	asn1VectorAssertPath(t, subject, "ProtocolIEs[0].Children[0].ObjectSet", "\"TAIItemIEs\"")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorResetAcknowledgeConnectionListRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.1.8.2; ResetAcknowledge recursively resolves UE-associated logical S1 connections.
func TestVectorResetAcknowledgeConnectionListRecursive(t *testing.T) {
	input := asn1VectorHex(t, "000001005d400900005b000460070009")
	var decoded s45.ResetAcknowledge
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.ProtocolIEs), "ResetAcknowledge")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"ResetAcknowledgeIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Children[0].ObjectSet", "\"UE-associatedLogicalS1-ConnectionItemResAck\"")
	asn1VectorAssertPath(t, subject, "[0].Children[0].Value.MMEUES1APID", "7")
	asn1VectorAssertPath(t, subject, "[0].Children[0].Value.ENBUES1APID", "9")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorEventTriggerEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; empty extensible EventTrigger-ExtIEs preserves private values.
func TestVectorEventTriggerEmptyChoiceExtensionSet(t *testing.T) {
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded s19.EventTrigger
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf([]any{decoded.ChoiceExtensions}), "EventTrigger.ChoiceExtensions")
	asn1VectorAssertPath(t, subject, "[0].Path", "\"EventTrigger.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"EventTrigger-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorMeasurementThresholdEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; empty extensible MeasurementThresholdL1LoggedMDT-ExtIEs preserves private values.
func TestVectorMeasurementThresholdEmptyChoiceExtensionSet(t *testing.T) {
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded s19.MeasurementThresholdL1LoggedMDT
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf([]any{decoded.ChoiceExtensions}), "MeasurementThresholdL1LoggedMDT.ChoiceExtensions")
	asn1VectorAssertPath(t, subject, "[0].Path", "\"MeasurementThresholdL1LoggedMDT.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"MeasurementThresholdL1LoggedMDT-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorSensorNameEmptyChoiceExtensionSet verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; empty extensible SensorNameConfig-ExtIEs preserves private values.
func TestVectorSensorNameEmptyChoiceExtensionSet(t *testing.T) {
	input := asn1VectorHex(t, "80fffc4004deadbeef")
	var decoded s30.SensorNameConfig
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf([]any{decoded.ChoiceExtensions}), "SensorNameConfig.ChoiceExtensions")
	asn1VectorAssertPath(t, subject, "[0].Path", "\"SensorNameConfig.ChoiceExtensions[0]\"")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"SensorNameConfig-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Field.Value.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerDapsRecursive verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; target transparent container DAPS response list and nested private extension.
func TestVectorTargetTransparentContainerDapsRecursive(t *testing.T) {
	input := asn1VectorHex(t, "4001010000013e401100013f400c4a000000fffc4004deadbeef")
	var decoded s40.TargeteNBToSourceeNBTransparentContainer
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.IEExtensions), "TargeteNBToSourceeNBTransparentContainer.IEExtensions")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].ObjectSet", "\"DAPSResponseInfoListIEs\"")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].Value.ERABID", "5")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].Value.DAPSResponseInfo.Dapsresponseindicator", "0")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].Extensions[0].ObjectSet", "\"DAPSResponseInfoItem-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].Extensions[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].Extensions[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerUnknownExtension verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; unknown target transparent container extension remains raw.
func TestVectorTargetTransparentContainerUnknownExtension(t *testing.T) {
	input := asn1VectorHex(t, "4001010000fffc4004deadbeef")
	var decoded s40.TargeteNBToSourceeNBTransparentContainer
	_, err := decoded.UnmarshalAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&decoded))
	subject := asn1TypedProjection(reflect.ValueOf(decoded.IEExtensions), "TargeteNBToSourceeNBTransparentContainer.IEExtensions")
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Field.Id", "65532")
	asn1VectorAssertPath(t, subject, "[0].Field.ExtensionValue.Bytes", "\"3q2+7w==\"")
	asn1VectorAssertPath(t, subject, "[0].Value", "null")
	wire, err := decoded.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, wire) {
		t.Fatalf("replay = %x, want %x", wire, input)
	}
}

// TestVectorTargetTransparentContainerMalformedDapsPath verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; malformed DAPS response list reports full containing path and identifier.
func TestVectorTargetTransparentContainerMalformedDapsPath(t *testing.T) {
	input := asn1VectorHex(t, "4001010000013e4000")
	var decoded s40.TargeteNBToSourceeNBTransparentContainer
	_, err := decoded.UnmarshalAPER(input)
	if err == nil {
		t.Fatal("decode succeeded, want error")
	}
	if !strings.Contains(err.Error(), "extension 318") {
		t.Fatalf("decode error = %v", err)
	}
	if !strings.Contains(err.Error(), "TargeteNBToSourceeNBTransparentContainer.IEExtensions[0]") {
		t.Fatalf("decode path = %v", err)
	}
}

// TestVectorTargetTransparentContainerDirectExtensionField verifies 3GPP TS 36.413 V19.2.0 (2026-06), section 9.3.4; direct recursive ProtocolExtensionField DAPS decoding and fuzz boundary.
func TestVectorTargetTransparentContainerDirectExtensionField(t *testing.T) {
	input := asn1VectorHex(t, "00013f400c4a000000fffc4004deadbeef")
	binding := s40.TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList()
	complete, _, err := binding.Codec().DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	field, err := binding.New(complete.Value)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&field))
	subject := []any{asn1TypedProjection(reflect.ValueOf(&field), "")}
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs\"")
	asn1VectorAssertPath(t, subject, "[0].ProtocolIEs[0].ObjectSet", "\"DAPSResponseInfoListIEs\"")
}

// TestVectorTaiItemDirectProtocolIeField verifies 3GPP TS 36.413 V19.2.0 (2026-06), sections 9.3.3 and 9.3.7; direct recursive TAIItem ProtocolIE-Field decoding and fuzz boundary.
func TestVectorTaiItemDirectProtocolIeField(t *testing.T) {
	input := asn1VectorHex(t, "0001f0101234")
	binding := s34.TAIItemIEs().TAIItem()
	complete, _, err := binding.Codec().DecodeAPER(input)
	if err != nil {
		t.Fatal(err)
	}
	field, err := binding.New(complete.Value)
	if err != nil {
		t.Fatal(err)
	}
	asn1SelectedObserve(reflect.ValueOf(&field))
	subject := []any{asn1TypedProjection(reflect.ValueOf(&field), "")}
	asn1VectorAssertPath(t, subject, "[0].ObjectSet", "\"TAIItemIEs\"")
	asn1VectorAssertPath(t, subject, "[0].Value.TAI.PLMNidentity", "\"AfAQ\"")
	asn1VectorAssertPath(t, subject, "[0].Value.TAI.TAC", "\"EjQ=\"")
}
func FuzzAPERS1APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
	f.Add(asn1VectorHexForFuzz("000a4012000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s53.S1APPDU
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERCause(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("26"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s14.Cause
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERERABInformationListItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("250000013d400100"))
	f.Add(asn1VectorHexForFuzz("250000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("250000013d4001ff"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s29.ERABInformationListItem
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERProtocolIEField(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12344001aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s13.EventTriggerExtIEValueIEFieldTableCodec(s09.EventTriggerExtIEs().Table()).DecodeAPER(input)
	})
}
func FuzzAPERS1APPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s53.S1APPDU
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERPagingProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s50.Paging
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERResetAcknowledgeProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001005d400900005b000460070009"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s45.ResetAcknowledge
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPEREventTriggerProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s19.EventTrigger
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERMeasurementThresholdL1LoggedMDTProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s19.MeasurementThresholdL1LoggedMDT
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERSensorNameConfigProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s30.SensorNameConfig
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERTargeteNBToSourceeNBTransparentContainerProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4001010000013e401100013f400c4a000000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000013e4000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s40.TargeteNBToSourceeNBTransparentContainer
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERDispatchProtocolExtensionRecursiveFieldTargeteNBToSourceeNBTransparentContainerExtIEsID318(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("00013f400c4a000000fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		bb := aper.NewBitBuffer()
		min, max := int64(0), int64(65535)
		if err := aper.EncodeIntegerAligned(bb, 318, &min, &max, false); err != nil {
			t.Fatal(err)
		}
		if err := aper.EncodeEnumeratedAligned(bb, 0, 3, false); err != nil {
			t.Fatal(err)
		}
		if err := aper.EncodeOpenTypeAligned(bb, input); err != nil {
			t.Fatal(err)
		}
		_, _, _ = s40.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec(s40.TargeteNBToSourceeNBTransparentContainerExtIEs().Table()).DecodeAPER(bb.CompleteBytes())
	})
}
func FuzzAPERDispatchProtocolIeRecursiveFieldTAIItemIEsID47(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("0001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		bb := aper.NewBitBuffer()
		min, max := int64(0), int64(65535)
		if err := aper.EncodeIntegerAligned(bb, 47, &min, &max, false); err != nil {
			t.Fatal(err)
		}
		if err := aper.EncodeEnumeratedAligned(bb, 0, 3, false); err != nil {
			t.Fatal(err)
		}
		if err := aper.EncodeOpenTypeAligned(bb, input); err != nil {
			t.Fatal(err)
		}
		_, _, _ = s34.TAIItemIEValueIEFieldTableCodec(s34.TAIItemIEs().Table()).DecodeAPER(bb.CompleteBytes())
	})
}
