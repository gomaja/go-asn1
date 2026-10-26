// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	json "encoding/json"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
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
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
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
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
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
func asn1VectorCheckPaddingReport(t *testing.T, report aper.DecodeReport, input []byte, fresh bool) {
	t.Helper()
	for _, observation := range report.Observations {
		switch observation.Kind {
		case aper.NonzeroTerminalPadding, aper.NonzeroEmptyEncoding:
			if fresh {
				t.Fatalf("fresh encoding has padding observation: %+v", observation)
			}
			count := observation.PaddingCount
			if count == 0 || count > 8 || (observation.Kind == aper.NonzeroTerminalPadding && count > 7) || (observation.Kind == aper.NonzeroEmptyEncoding && count != 8) {
				t.Fatalf("invalid padding width: %+v", observation)
			}
			if observation.PaddingBits == 0 || uint16(observation.PaddingBits) >= uint16(1)<<count {
				t.Fatalf("invalid padding bits: %+v", observation)
			}
		case aper.UnknownProcedure, aper.UnknownIE, aper.UnknownExtension:
			if observation.PaddingBits != 0 || observation.PaddingCount != 0 {
				t.Fatalf("non-padding observation carries padding: %+v", observation)
			}
		default:
			t.Fatalf("unknown observation kind: %+v", observation)
		}
		if observation.Location.Path == "" {
			t.Fatalf("observation has empty path: %+v", observation)
		}
		if observation.Location.HasWireLocation {
			if len(observation.Location.Spans) == 0 {
				t.Fatalf("located observation has no spans: %+v", observation)
			}
			for _, span := range observation.Location.Spans {
				if span.Start > span.End || span.End > uint64(len(input))*8 {
					t.Fatalf("observation span outside input: %+v", observation)
				}
			}
		}
	}
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
	"AdditionalGUTIExtIEsValue":                                s08.AdditionalGUTIExtIEs().ID().Source().Assignment,
	"AllocationAndRetentionPriorityExtIEsValue":                s08.AllocationAndRetentionPriorityExtIEs().ID().Source().Assignment,
	"InformationForCECapableUEsExtIEsValue":                    s11.InformationForCECapableUEsExtIEs().ID().Source().Assignment,
	"AssistanceDataForPagingExtIEsValue":                       s08.AssistanceDataForPagingExtIEs().ID().Source().Assignment,
	"AssistanceDataForRecommendedCellsExtIEsValue":             s08.AssistanceDataForRecommendedCellsExtIEs().ID().Source().Assignment,
	"BearersSubjectToStatusTransferItemIEValue":                s25.BearersSubjectToStatusTransferItemIEs().ID().Source().Assignment,
	"BearersSubjectToStatusTransferItemExtIEsValue":            s17.BearersSubjectToStatusTransferItemExtIEs().ID().Source().Assignment,
	"BearersSubjectToEarlyStatusTransferItemIEValue":           s17.BearersSubjectToEarlyStatusTransferItemIEs().ID().Source().Assignment,
	"BearersSubjectToEarlyStatusTransferItemExtIEsValue":       s08.BearersSubjectToEarlyStatusTransferItemExtIEs().ID().Source().Assignment,
	"BearersSubjectToDLDiscardingItemIEValue":                  s17.BearersSubjectToDLDiscardingItemIEs().ID().Source().Assignment,
	"BearersSubjectToDLDiscardingItemExtIEsValue":              s08.BearersSubjectToDLDiscardingItemExtIEs().ID().Source().Assignment,
	"BluetoothMeasurementConfigurationExtIEsValue":             s08.BluetoothMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"CancelledCellinEAIItemExtIEsValue":                        s08.CancelledCellinEAIItemExtIEs().ID().Source().Assignment,
	"CancelledCellinTAIItemExtIEsValue":                        s08.CancelledCellinTAIItemExtIEs().ID().Source().Assignment,
	"CellIdentifierAndCELevelForCECapableUEsExtIEsValue":       s09.CellIdentifierAndCELevelForCECapableUEsExtIEs().ID().Source().Assignment,
	"CellIDBroadcastItemExtIEsValue":                           s09.CellIDBroadcastItemExtIEs().ID().Source().Assignment,
	"CellIDCancelledItemExtIEsValue":                           s09.CellIDCancelledItemExtIEs().ID().Source().Assignment,
	"CellBasedMDTExtIEsValue":                                  s08.CellBasedMDTExtIEs().ID().Source().Assignment,
	"CellBasedQMCExtIEsValue":                                  s08.CellBasedQMCExtIEs().ID().Source().Assignment,
	"Cdma2000OneXSRVCCInfoExtIEsValue":                         s08.Cdma2000OneXSRVCCInfoExtIEs().ID().Source().Assignment,
	"CellTypeExtIEsValue":                                      s09.CellTypeExtIEs().ID().Source().Assignment,
	"CGIExtIEsValue":                                           s08.CGIExtIEs().ID().Source().Assignment,
	"CNTypeRestrictionsItemExtIEsValue":                        s08.CNTypeRestrictionsItemExtIEs().ID().Source().Assignment,
	"ConnectedengNBItemExtIEsValue":                            s09.ConnectedengNBItemExtIEs().ID().Source().Assignment,
	"ContextatSourceExtIEsValue":                               s09.ContextatSourceExtIEs().ID().Source().Assignment,
	"CSGIdListItemExtIEsValue":                                 s08.CSGIdListItemExtIEs().ID().Source().Assignment,
	"COUNTvalueExtIEsValue":                                    s08.COUNTvalueExtIEs().ID().Source().Assignment,
	"COUNTValueExtendedExtIEsValue":                            s08.COUNTValueExtendedExtIEs().ID().Source().Assignment,
	"COUNTvaluePDCPSNlength18ExtIEsValue":                      s08.COUNTvaluePDCPSNlength18ExtIEs().ID().Source().Assignment,
	"CriticalityDiagnosticsExtIEsValue":                        s09.CriticalityDiagnosticsExtIEs().ID().Source().Assignment,
	"CriticalityDiagnosticsIEItemExtIEsValue":                  s09.CriticalityDiagnosticsIEItemExtIEs().ID().Source().Assignment,
	"DAPSRequestInfoExtIEsValue":                               s09.DAPSRequestInfoExtIEs().ID().Source().Assignment,
	"DAPSResponseInfoListIEValue":                              s17.DAPSResponseInfoListIEs().ID().Source().Assignment,
	"DAPSResponseInfoItemExtIEsValue":                          s09.DAPSResponseInfoItemExtIEs().ID().Source().Assignment,
	"DAPSResponseInfoExtIEsValue":                              s09.DAPSResponseInfoExtIEs().ID().Source().Assignment,
	"ServedDCNsItemExtIEsValue":                                s13.ServedDCNsItemExtIEs().ID().Source().Assignment,
	"DLCPSecurityInformationExtIEsValue":                       s09.DLCPSecurityInformationExtIEs().ID().Source().Assignment,
	"EmergencyAreaIDBroadcastItemExtIEsValue":                  s10.EmergencyAreaIDBroadcastItemExtIEs().ID().Source().Assignment,
	"EmergencyAreaIDCancelledItemExtIEsValue":                  s10.EmergencyAreaIDCancelledItemExtIEs().ID().Source().Assignment,
	"CompletedCellinEAIItemExtIEsValue":                        s09.CompletedCellinEAIItemExtIEs().ID().Source().Assignment,
	"ENBEarlyStatusTransferTransparentContainerExtIEsValue":    s47.ENBEarlyStatusTransferTransparentContainerExtIEs().ID().Source().Assignment,
	"GERANCellIDExtIEsValue":                                   s11.GERANCellIDExtIEs().ID().Source().Assignment,
	"GlobalENBIDExtIEsValue":                                   s11.GlobalENBIDExtIEs().ID().Source().Assignment,
	"GlobalEnGNBIDExtIEsValue":                                 s11.GlobalEnGNBIDExtIEs().ID().Source().Assignment,
	"ENBStatusTransferTransparentContainerExtIEsValue":         s09.ENBStatusTransferTransparentContainerExtIEs().ID().Source().Assignment,
	"ENDCSONConfigurationTransferExtIEsValue":                  s09.ENDCSONConfigurationTransferExtIEs().ID().Source().Assignment,
	"ENDCTransferTypeRequestExtIEsValue":                       s10.ENDCTransferTypeRequestExtIEs().ID().Source().Assignment,
	"ENDCTransferTypeReplyExtIEsValue":                         s09.ENDCTransferTypeReplyExtIEs().ID().Source().Assignment,
	"ENDCSONeNBIdentificationExtIEsValue":                      s09.ENDCSONeNBIdentificationExtIEs().ID().Source().Assignment,
	"ENDCSONengNBIdentificationExtIEsValue":                    s09.ENDCSONengNBIdentificationExtIEs().ID().Source().Assignment,
	"ERABInformationListIEValue":                               s37.ERABInformationListIEs().ID().Source().Assignment,
	"ERABInformationListItemExtIEsValue":                       s37.ERABInformationListItemExtIEs().ID().Source().Assignment,
	"ERABItemIEValue":                                          s19.ERABItemIEs().ID().Source().Assignment,
	"ERABItemExtIEsValue":                                      s10.ERABItemExtIEs().ID().Source().Assignment,
	"ERABSecurityResultListIEValue":                            s38.ERABSecurityResultListIEs().ID().Source().Assignment,
	"ERABSecurityResultItemExtIEsValue":                        s10.ERABSecurityResultItemExtIEs().ID().Source().Assignment,
	"ERABUsageReportItemIEValue":                               s20.ERABUsageReportItemIEs().ID().Source().Assignment,
	"ERABUsageReportItemExtIEsValue":                           s10.ERABUsageReportItemExtIEs().ID().Source().Assignment,
	"ERABQoSParametersExtIEsValue":                             s10.ERABQoSParametersExtIEs().ID().Source().Assignment,
	"EUTRANCGIExtIEsValue":                                     s10.EUTRANCGIExtIEs().ID().Source().Assignment,
	"EventL1LoggedMDTConfigExtIEsValue":                        s10.EventL1LoggedMDTConfigExtIEs().ID().Source().Assignment,
	"EventTriggerExtIEValue":                                   s10.EventTriggerExtIEs().ID().Source().Assignment,
	"ExpectedUEBehaviourExtIEsValue":                           s10.ExpectedUEBehaviourExtIEs().ID().Source().Assignment,
	"ExpectedUEActivityBehaviourExtIEsValue":                   s10.ExpectedUEActivityBehaviourExtIEs().ID().Source().Assignment,
	"FiveGSTAIExtIEsValue":                                     s10.FiveGSTAIExtIEs().ID().Source().Assignment,
	"ForbiddenTAsItemExtIEsValue":                              s10.ForbiddenTAsItemExtIEs().ID().Source().Assignment,
	"ForbiddenLAsItemExtIEsValue":                              s10.ForbiddenLAsItemExtIEs().ID().Source().Assignment,
	"GBRQosInformationExtIEsValue":                             s11.GBRQosInformationExtIEs().ID().Source().Assignment,
	"GUMMEIExtIEsValue":                                        s11.GUMMEIExtIEs().ID().Source().Assignment,
	"HandoverRestrictionListExtIEsValue":                       s53.HandoverRestrictionListExtIEs().ID().Source().Assignment,
	"ImmediateMDTExtIEsValue":                                  s59.ImmediateMDTExtIEs().ID().Source().Assignment,
	"InformationOnRecommendedCellsAndENBsForPagingExtIEsValue": s11.InformationOnRecommendedCellsAndENBsForPagingExtIEs().ID().Source().Assignment,
	"IntersystemMeasurementConfigurationExtIEsValue":           s11.IntersystemMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"InterSystemMeasurementParametersExtIEsValue":              s11.InterSystemMeasurementParametersExtIEs().ID().Source().Assignment,
	"InterSystemMeasurementItemExtIEsValue":                    s11.InterSystemMeasurementItemExtIEs().ID().Source().Assignment,
	"LAIExtIEsValue":                                           s11.LAIExtIEs().ID().Source().Assignment,
	"LastVisitedEUTRANCellInformationExtIEsValue":              s52.LastVisitedEUTRANCellInformationExtIEs().ID().Source().Assignment,
	"LastVisitedPSCellInformationExtIEsValue":                  s11.LastVisitedPSCellInformationExtIEs().ID().Source().Assignment,
	"ListeningSubframePatternExtIEsValue":                      s11.ListeningSubframePatternExtIEs().ID().Source().Assignment,
	"LoggedMDTExtIEsValue":                                     s59.LoggedMDTExtIEs().ID().Source().Assignment,
	"LoggedMBSFNMDTExtIEsValue":                                s11.LoggedMBSFNMDTExtIEs().ID().Source().Assignment,
	"LTENTNTAIInformationExtIEsValue":                          s11.LTENTNTAIInformationExtIEs().ID().Source().Assignment,
	"M3ConfigurationExtIEsValue":                               s11.M3ConfigurationExtIEs().ID().Source().Assignment,
	"M4ConfigurationExtIEsValue":                               s11.M4ConfigurationExtIEs().ID().Source().Assignment,
	"M5ConfigurationExtIEsValue":                               s11.M5ConfigurationExtIEs().ID().Source().Assignment,
	"M6ConfigurationExtIEsValue":                               s11.M6ConfigurationExtIEs().ID().Source().Assignment,
	"M7ConfigurationExtIEsValue":                               s11.M7ConfigurationExtIEs().ID().Source().Assignment,
	"MDTConfigurationExtIEsValue":                              s52.MDTConfigurationExtIEs().ID().Source().Assignment,
	"MBSFNResultToLogInfoExtIEsValue":                          s11.MBSFNResultToLogInfoExtIEs().ID().Source().Assignment,
	"MDTModeExtensionIEIEValue":                                s28.MDTModeExtensionIE().ID().Source().Assignment,
	"MeasurementThresholdL1LoggedMDTExtIEValue":                s12.MeasurementThresholdL1LoggedMDTExtIEs().ID().Source().Assignment,
	"MutingPatternInformationExtIEsValue":                      s12.MutingPatternInformationExtIEs().ID().Source().Assignment,
	"NBIoTPagingEDRXInformationExtIEsValue":                    s12.NBIoTPagingEDRXInformationExtIEs().ID().Source().Assignment,
	"NRCGIExtIEsValue":                                         s12.NRCGIExtIEs().ID().Source().Assignment,
	"NRUESecurityCapabilitiesExtIEsValue":                      s12.NRUESecurityCapabilitiesExtIEs().ID().Source().Assignment,
	"NRV2XServicesAuthorizedExtIEsValue":                       s12.NRV2XServicesAuthorizedExtIEs().ID().Source().Assignment,
	"NRUESidelinkAggregateMaximumBitrateExtIEsValue":           s12.NRUESidelinkAggregateMaximumBitrateExtIEs().ID().Source().Assignment,
	"PagingAttemptInformationExtIEsValue":                      s12.PagingAttemptInformationExtIEs().ID().Source().Assignment,
	"PagingEDRXInformationExtIEsValue":                         s12.PagingEDRXInformationExtIEs().ID().Source().Assignment,
	"PC5QoSParametersExtIEsValue":                              s12.PC5QoSParametersExtIEs().ID().Source().Assignment,
	"PC5QoSFlowItemExtIEsValue":                                s12.PC5QoSFlowItemExtIEs().ID().Source().Assignment,
	"PC5FlowBitRatesExtIEsValue":                               s12.PC5FlowBitRatesExtIEs().ID().Source().Assignment,
	"M1PeriodicReportingExtIEsValue":                           s11.M1PeriodicReportingExtIEs().ID().Source().Assignment,
	"PLMNAreaBasedQMCExtIEsValue":                              s12.PLMNAreaBasedQMCExtIEs().ID().Source().Assignment,
	"ProSeAuthorizedExtIEsValue":                               s12.ProSeAuthorizedExtIEs().ID().Source().Assignment,
	"PSCellInformationExtIEsValue":                             s12.PSCellInformationExtIEs().ID().Source().Assignment,
	"RecommendedCellsForPagingExtIEsValue":                     s12.RecommendedCellsForPagingExtIEs().ID().Source().Assignment,
	"RecommendedCellItemIEValue":                               s30.RecommendedCellItemIEs().ID().Source().Assignment,
	"RecommendedCellsForPagingItemExtIEsValue":                 s12.RecommendedCellsForPagingItemExtIEs().ID().Source().Assignment,
	"RecommendedENBsForPagingExtIEsValue":                      s12.RecommendedENBsForPagingExtIEs().ID().Source().Assignment,
	"RecommendedENBItemIEValue":                                s40.RecommendedENBItemIEs().ID().Source().Assignment,
	"RecommendedENBItemExtIEsValue":                            s12.RecommendedENBItemExtIEs().ID().Source().Assignment,
	"RATRestrictionsItemExtIEsValue":                           s12.RATRestrictionsItemExtIEs().ID().Source().Assignment,
	"RequestedTNLInfoExtIEsValue":                              s13.RequestedTNLInfoExtIEs().ID().Source().Assignment,
	"RequestTypeExtIEsValue":                                   s12.RequestTypeExtIEs().ID().Source().Assignment,
	"RIMTransferExtIEsValue":                                   s12.RIMTransferExtIEs().ID().Source().Assignment,
	"RLFReportInformationExtIEsValue":                          s12.RLFReportInformationExtIEs().ID().Source().Assignment,
	"SecurityContextExtIEsValue":                               s13.SecurityContextExtIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportItemIEValue":                   s36.SecondaryRATDataUsageReportItemIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportItemExtIEsValue":               s13.SecondaryRATDataUsageReportItemExtIEs().ID().Source().Assignment,
	"SecurityIndicationExtIEsValue":                            s13.SecurityIndicationExtIEs().ID().Source().Assignment,
	"SecurityResultExtIEsValue":                                s13.SecurityResultExtIEs().ID().Source().Assignment,
	"SensorMeasConfigNameItemExtIEsValue":                      s13.SensorMeasConfigNameItemExtIEs().ID().Source().Assignment,
	"SensorMeasurementConfigurationExtIEsValue":                s13.SensorMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"SensorNameConfigExtIEValue":                               s13.SensorNameConfigExtIEs().ID().Source().Assignment,
	"SONInformationExtensionIEIEValue":                         s24.SONInformationExtensionIE().ID().Source().Assignment,
	"SONInformationReplyExtIEsValue":                           s44.SONInformationReplyExtIEs().ID().Source().Assignment,
	"SONConfigurationTransferExtIEsValue":                      s64.SONConfigurationTransferExtIEs().ID().Source().Assignment,
	"SynchronisationInformationExtIEsValue":                    s13.SynchronisationInformationExtIEs().ID().Source().Assignment,
	"SourceeNBIDExtIEsValue":                                   s13.SourceeNBIDExtIEs().ID().Source().Assignment,
	"SourceNodeIDExtensionIEIEValue":                           s13.SourceNodeIDExtensionIE().ID().Source().Assignment,
	"SourceeNBToTargeteNBTransparentContainerExtIEsValue":      s44.SourceeNBToTargeteNBTransparentContainerExtIEs().ID().Source().Assignment,
	"SourceNgRanNodeIDExtIEsValue":                             s13.SourceNgRanNodeIDExtIEs().ID().Source().Assignment,
	"ServedGUMMEIsItemExtIEsValue":                             s13.ServedGUMMEIsItemExtIEs().ID().Source().Assignment,
	"SubscriptionBasedUEDifferentiationInfoExtIEsValue":        s13.SubscriptionBasedUEDifferentiationInfoExtIEs().ID().Source().Assignment,
	"ScheduledCommunicationTimeExtIEsValue":                    s13.ScheduledCommunicationTimeExtIEs().ID().Source().Assignment,
	"SupportedTAsItemExtIEsValue":                              s13.SupportedTAsItemExtIEs().ID().Source().Assignment,
	"TimeSynchronisationInfoExtIEsValue":                       s14.TimeSynchronisationInfoExtIEs().ID().Source().Assignment,
	"STMSIExtIEsValue":                                         s13.STMSIExtIEs().ID().Source().Assignment,
	"TAIBasedMDTExtIEsValue":                                   s13.TAIBasedMDTExtIEs().ID().Source().Assignment,
	"TAIExtIEsValue":                                           s13.TAIExtIEs().ID().Source().Assignment,
	"TAIBroadcastItemExtIEsValue":                              s13.TAIBroadcastItemExtIEs().ID().Source().Assignment,
	"TAICancelledItemExtIEsValue":                              s13.TAICancelledItemExtIEs().ID().Source().Assignment,
	"TABasedMDTExtIEsValue":                                    s13.TABasedMDTExtIEs().ID().Source().Assignment,
	"TABasedQMCExtIEsValue":                                    s13.TABasedQMCExtIEs().ID().Source().Assignment,
	"TAIBasedQMCExtIEsValue":                                   s13.TAIBasedQMCExtIEs().ID().Source().Assignment,
	"CompletedCellinTAIItemExtIEsValue":                        s09.CompletedCellinTAIItemExtIEs().ID().Source().Assignment,
	"TargeteNBIDExtIEsValue":                                   s13.TargeteNBIDExtIEs().ID().Source().Assignment,
	"TargetRNCIDExtIEsValue":                                   s13.TargetRNCIDExtIEs().ID().Source().Assignment,
	"TargetNgRanNodeIDExtIEsValue":                             s13.TargetNgRanNodeIDExtIEs().ID().Source().Assignment,
	"GNBExtIEsValue":                                           s11.GNBExtIEs().ID().Source().Assignment,
	"GlobalGNBIDExtIEsValue":                                   s11.GlobalGNBIDExtIEs().ID().Source().Assignment,
	"NGENBExtIEsValue":                                         s12.NGENBExtIEs().ID().Source().Assignment,
	"TargeteNBToSourceeNBTransparentContainerExtIEsValue":      s50.TargeteNBToSourceeNBTransparentContainerExtIEs().ID().Source().Assignment,
	"M1ThresholdEventA2ExtIEsValue":                            s11.M1ThresholdEventA2ExtIEs().ID().Source().Assignment,
	"TimeBasedHandoverInformationExtIEsValue":                  s13.TimeBasedHandoverInformationExtIEs().ID().Source().Assignment,
	"TraceActivationExtIEsValue":                               s59.TraceActivationExtIEs().ID().Source().Assignment,
	"TunnelInformationExtIEsValue":                             s14.TunnelInformationExtIEs().ID().Source().Assignment,
	"UEAggregateMaximumBitratesExtIEsValue":                    s14.UEAggregateMaximumBitratesExtIEs().ID().Source().Assignment,
	"UEAppLayerMeasConfigExtIEsValue":                          s14.UEAppLayerMeasConfigExtIEs().ID().Source().Assignment,
	"UES1APIDPairExtIEsValue":                                  s14.UES1APIDPairExtIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemExtIEsValue":           s14.UEAssociatedLogicalS1ConnectionItemExtIEs().ID().Source().Assignment,
	"UESecurityCapabilitiesExtIEsValue":                        s14.UESecurityCapabilitiesExtIEs().ID().Source().Assignment,
	"UESidelinkAggregateMaximumBitratesExtIEsValue":            s14.UESidelinkAggregateMaximumBitratesExtIEs().ID().Source().Assignment,
	"ULCPSecurityInformationExtIEsValue":                       s14.ULCPSecurityInformationExtIEs().ID().Source().Assignment,
	"UserLocationInformationExtIEsValue":                       s25.UserLocationInformationExtIEs().ID().Source().Assignment,
	"V2XServicesAuthorizedExtIEsValue":                         s14.V2XServicesAuthorizedExtIEs().ID().Source().Assignment,
	"WLANMeasurementConfigurationExtIEsValue":                  s14.WLANMeasurementConfigurationExtIEs().ID().Source().Assignment,
	"WUSAssistanceInformationExtIEsValue":                      s15.WUSAssistanceInformationExtIEs().ID().Source().Assignment,
	"X2TNLConfigurationInfoExtIEsValue":                        s48.X2TNLConfigurationInfoExtIEs().ID().Source().Assignment,
	"ENBX2ExtTLAExtIEsValue":                                   s09.ENBX2ExtTLAExtIEs().ID().Source().Assignment,
	"HandoverRequiredIEValue":                                  s43.HandoverRequiredIEs().ID().Source().Assignment,
	"HandoverCommandIEValue":                                   s50.HandoverCommandIEs().ID().Source().Assignment,
	"ERABDataForwardingItemIEValue":                            s18.ERABDataForwardingItemIEs().ID().Source().Assignment,
	"ERABDataForwardingItemExtIEsValue":                        s10.ERABDataForwardingItemExtIEs().ID().Source().Assignment,
	"HandoverPreparationFailureIEValue":                        s26.HandoverPreparationFailureIEs().ID().Source().Assignment,
	"HandoverRequestIEValue":                                   s60.HandoverRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemHOReqIEValue":                            s38.ERABToBeSetupItemHOReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemHOReqExtIEsValue":                        s37.ERABToBeSetupItemHOReqExtIEs().ID().Source().Assignment,
	"HandoverRequestAcknowledgeIEValue":                        s49.HandoverRequestAcknowledgeIEs().ID().Source().Assignment,
	"ERABAdmittedItemIEValue":                                  s18.ERABAdmittedItemIEs().ID().Source().Assignment,
	"ERABAdmittedItemExtIEsValue":                              s10.ERABAdmittedItemExtIEs().ID().Source().Assignment,
	"ERABFailedtoSetupItemHOReqAckIEValue":                     s18.ERABFailedtoSetupItemHOReqAckIEs().ID().Source().Assignment,
	"ERABFailedToSetupItemHOReqAckExtIEsValue":                 s10.ERABFailedToSetupItemHOReqAckExtIEs().ID().Source().Assignment,
	"HandoverFailureIEValue":                                   s26.HandoverFailureIEs().ID().Source().Assignment,
	"HandoverNotifyIEValue":                                    s44.HandoverNotifyIEs().ID().Source().Assignment,
	"PathSwitchRequestIEValue":                                 s51.PathSwitchRequestIEs().ID().Source().Assignment,
	"ERABToBeSwitchedDLItemIEValue":                            s38.ERABToBeSwitchedDLItemIEs().ID().Source().Assignment,
	"ERABToBeSwitchedDLItemExtIEsValue":                        s37.ERABToBeSwitchedDLItemExtIEs().ID().Source().Assignment,
	"PathSwitchRequestAcknowledgeIEValue":                      s58.PathSwitchRequestAcknowledgeIEs().ID().Source().Assignment,
	"ERABToBeSwitchedULItemIEValue":                            s20.ERABToBeSwitchedULItemIEs().ID().Source().Assignment,
	"ERABToBeSwitchedULItemExtIEsValue":                        s10.ERABToBeSwitchedULItemExtIEs().ID().Source().Assignment,
	"ERABToBeUpdatedItemIEValue":                               s37.ERABToBeUpdatedItemIEs().ID().Source().Assignment,
	"ERABToBeUpdatedItemExtIEsValue":                           s10.ERABToBeUpdatedItemExtIEs().ID().Source().Assignment,
	"PathSwitchRequestFailureIEValue":                          s27.PathSwitchRequestFailureIEs().ID().Source().Assignment,
	"HandoverCancelIEValue":                                    s21.HandoverCancelIEs().ID().Source().Assignment,
	"HandoverCancelAcknowledgeIEValue":                         s26.HandoverCancelAcknowledgeIEs().ID().Source().Assignment,
	"HandoverSuccessIEValue":                                   s11.HandoverSuccessIEs().ID().Source().Assignment,
	"ENBEarlyStatusTransferIEValue":                            s47.ENBEarlyStatusTransferIEs().ID().Source().Assignment,
	"MMEEarlyStatusTransferIEValue":                            s47.MMEEarlyStatusTransferIEs().ID().Source().Assignment,
	"ERABSetupRequestIEValue":                                  s51.ERABSetupRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemBearerSUReqIEValue":                      s38.ERABToBeSetupItemBearerSUReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemBearerSUReqExtIEsValue":                  s37.ERABToBeSetupItemBearerSUReqExtIEs().ID().Source().Assignment,
	"ERABSetupResponseIEValue":                                 s57.ERABSetupResponseIEs().ID().Source().Assignment,
	"ERABSetupItemBearerSUResIEValue":                          s19.ERABSetupItemBearerSUResIEs().ID().Source().Assignment,
	"ERABSetupItemBearerSUResExtIEsValue":                      s10.ERABSetupItemBearerSUResExtIEs().ID().Source().Assignment,
	"ERABModifyRequestIEValue":                                 s51.ERABModifyRequestIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModReqIEValue":                  s29.ERABToBeModifiedItemBearerModReqIEs().ID().Source().Assignment,
	"ERABToBeModifyItemBearerModReqExtIEsValue":                s24.ERABToBeModifyItemBearerModReqExtIEs().ID().Source().Assignment,
	"ERABModifyResponseIEValue":                                s57.ERABModifyResponseIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModResIEValue":                        s19.ERABModifyItemBearerModResIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModResExtIEsValue":                    s10.ERABModifyItemBearerModResExtIEs().ID().Source().Assignment,
	"ERABReleaseCommandIEValue":                                s49.ERABReleaseCommandIEs().ID().Source().Assignment,
	"ERABReleaseResponseIEValue":                               s57.ERABReleaseResponseIEs().ID().Source().Assignment,
	"ERABReleaseItemBearerRelCompIEValue":                      s19.ERABReleaseItemBearerRelCompIEs().ID().Source().Assignment,
	"ERABReleaseItemBearerRelCompExtIEsValue":                  s10.ERABReleaseItemBearerRelCompExtIEs().ID().Source().Assignment,
	"ERABReleaseIndicationIEValue":                             s57.ERABReleaseIndicationIEs().ID().Source().Assignment,
	"InitialContextSetupRequestIEValue":                        s60.InitialContextSetupRequestIEs().ID().Source().Assignment,
	"ERABToBeSetupItemCtxtSUReqIEValue":                        s38.ERABToBeSetupItemCtxtSUReqIEs().ID().Source().Assignment,
	"ERABToBeSetupItemCtxtSUReqExtIEsValue":                    s37.ERABToBeSetupItemCtxtSUReqExtIEs().ID().Source().Assignment,
	"InitialContextSetupResponseIEValue":                       s50.InitialContextSetupResponseIEs().ID().Source().Assignment,
	"ERABSetupItemCtxtSUResIEValue":                            s20.ERABSetupItemCtxtSUResIEs().ID().Source().Assignment,
	"ERABSetupItemCtxtSUResExtIEsValue":                        s10.ERABSetupItemCtxtSUResExtIEs().ID().Source().Assignment,
	"InitialContextSetupFailureIEValue":                        s26.InitialContextSetupFailureIEs().ID().Source().Assignment,
	"PagingIEValue":                                            s61.PagingIEs().ID().Source().Assignment,
	"TAIItemIEValue":                                           s42.TAIItemIEs().ID().Source().Assignment,
	"TAIItemExtIEsValue":                                       s13.TAIItemExtIEs().ID().Source().Assignment,
	"UEContextReleaseRequestIEValue":                           s53.UEContextReleaseRequestIEs().ID().Source().Assignment,
	"UEContextReleaseCommandIEValue":                           s46.UEContextReleaseCommandIEs().ID().Source().Assignment,
	"UEContextReleaseCompleteIEValue":                          s57.UEContextReleaseCompleteIEs().ID().Source().Assignment,
	"UEContextModificationRequestIEValue":                      s58.UEContextModificationRequestIEs().ID().Source().Assignment,
	"UEContextModificationResponseIEValue":                     s27.UEContextModificationResponseIEs().ID().Source().Assignment,
	"UEContextModificationFailureIEValue":                      s27.UEContextModificationFailureIEs().ID().Source().Assignment,
	"UERadioCapabilityMatchRequestIEValue":                     s14.UERadioCapabilityMatchRequestIEs().ID().Source().Assignment,
	"UERadioCapabilityMatchResponseIEValue":                    s28.UERadioCapabilityMatchResponseIEs().ID().Source().Assignment,
	"DownlinkNASTransportIEValue":                              s53.DownlinkNASTransportIEs().ID().Source().Assignment,
	"InitialUEMessageIEValue":                                  s44.InitialUEMessageIEs().ID().Source().Assignment,
	"UplinkNASTransportIEValue":                                s41.UplinkNASTransportIEs().ID().Source().Assignment,
	"NASNonDeliveryIndicationIEValue":                          s23.NASNonDeliveryIndicationIEs().ID().Source().Assignment,
	"RerouteNASRequestIEValue":                                 s24.RerouteNASRequestIEs().ID().Source().Assignment,
	"NASDeliveryIndicationIEValue":                             s12.NASDeliveryIndicationIEs().ID().Source().Assignment,
	"ResetIEValue":                                             s45.ResetIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemResIEValue":            s45.UEAssociatedLogicalS1ConnectionItemRes().ID().Source().Assignment,
	"ResetAcknowledgeIEValue":                                  s55.ResetAcknowledgeIEs().ID().Source().Assignment,
	"UEAssociatedLogicalS1ConnectionItemResAckIEValue":         s45.UEAssociatedLogicalS1ConnectionItemResAck().ID().Source().Assignment,
	"ErrorIndicationIEValue":                                   s36.ErrorIndicationIEs().ID().Source().Assignment,
	"S1SetupRequestIEValue":                                    s54.S1SetupRequestIEs().ID().Source().Assignment,
	"S1SetupResponseIEValue":                                   s54.S1SetupResponseIEs().ID().Source().Assignment,
	"S1SetupFailureIEValue":                                    s27.S1SetupFailureIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateIEValue":                            s54.ENBConfigurationUpdateIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateAcknowledgeIEValue":                 s26.ENBConfigurationUpdateAcknowledgeIEs().ID().Source().Assignment,
	"ENBConfigurationUpdateFailureIEValue":                     s26.ENBConfigurationUpdateFailureIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateIEValue":                            s54.MMEConfigurationUpdateIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateAcknowledgeIEValue":                 s26.MMEConfigurationUpdateAcknowledgeIEs().ID().Source().Assignment,
	"MMEConfigurationUpdateFailureIEValue":                     s27.MMEConfigurationUpdateFailureIEs().ID().Source().Assignment,
	"DownlinkS1cdma2000tunnellingIEValue":                      s50.DownlinkS1cdma2000tunnellingIEs().ID().Source().Assignment,
	"UplinkS1cdma2000tunnellingIEValue":                        s25.UplinkS1cdma2000tunnellingIEs().ID().Source().Assignment,
	"UECapabilityInfoIndicationIEValue":                        s14.UECapabilityInfoIndicationIEs().ID().Source().Assignment,
	"ENBStatusTransferIEValue":                                 s25.ENBStatusTransferIEs().ID().Source().Assignment,
	"MMEStatusTransferIEValue":                                 s25.MMEStatusTransferIEs().ID().Source().Assignment,
	"TraceStartIEValue":                                        s60.TraceStartIEs().ID().Source().Assignment,
	"TraceFailureIndicationIEValue":                            s24.TraceFailureIndicationIEs().ID().Source().Assignment,
	"DeactivateTraceIEValue":                                   s09.DeactivateTraceIEs().ID().Source().Assignment,
	"CellTrafficTraceIEValue":                                  s21.CellTrafficTraceIEs().ID().Source().Assignment,
	"LocationReportingControlIEValue":                          s31.LocationReportingControlIEs().ID().Source().Assignment,
	"LocationReportingFailureIndicationIEValue":                s22.LocationReportingFailureIndicationIEs().ID().Source().Assignment,
	"LocationReportIEValue":                                    s41.LocationReportIEs().ID().Source().Assignment,
	"OverloadStartIEValue":                                     s52.OverloadStartIEs().ID().Source().Assignment,
	"OverloadStopIEValue":                                      s52.OverloadStopIEs().ID().Source().Assignment,
	"WriteReplaceWarningRequestIEValue":                        s42.WriteReplaceWarningRequestIEs().ID().Source().Assignment,
	"WriteReplaceWarningResponseIEValue":                       s41.WriteReplaceWarningResponseIEs().ID().Source().Assignment,
	"ENBDirectInformationTransferIEValue":                      s43.ENBDirectInformationTransferIEs().ID().Source().Assignment,
	"MMEDirectInformationTransferIEValue":                      s43.MMEDirectInformationTransferIEs().ID().Source().Assignment,
	"ENBConfigurationTransferIEValue":                          s65.ENBConfigurationTransferIEs().ID().Source().Assignment,
	"MMEConfigurationTransferIEValue":                          s65.MMEConfigurationTransferIEs().ID().Source().Assignment,
	"KillRequestIEValue":                                       s42.KillRequestIEs().ID().Source().Assignment,
	"KillResponseIEValue":                                      s41.KillResponseIEs().ID().Source().Assignment,
	"PWSRestartIndicationIEValue":                              s55.PWSRestartIndicationIEs().ID().Source().Assignment,
	"PWSFailureIndicationIEValue":                              s52.PWSFailureIndicationIEs().ID().Source().Assignment,
	"DownlinkUEAssociatedLPPaTransportIEValue":                 s09.DownlinkUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"UplinkUEAssociatedLPPaTransportIEValue":                   s14.UplinkUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"DownlinkNonUEAssociatedLPPaTransportIEValue":              s09.DownlinkNonUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"UplinkNonUEAssociatedLPPaTransportIEValue":                s14.UplinkNonUEAssociatedLPPaTransportIEs().ID().Source().Assignment,
	"ERABModificationIndicationIEValue":                        s57.ERABModificationIndicationIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModIndIEValue":                  s20.ERABToBeModifiedItemBearerModIndIEs().ID().Source().Assignment,
	"ERABToBeModifiedItemBearerModIndExtIEsValue":              s10.ERABToBeModifiedItemBearerModIndExtIEs().ID().Source().Assignment,
	"ERABNotToBeModifiedItemBearerModIndIEValue":               s19.ERABNotToBeModifiedItemBearerModIndIEs().ID().Source().Assignment,
	"ERABNotToBeModifiedItemBearerModIndExtIEsValue":           s10.ERABNotToBeModifiedItemBearerModIndExtIEs().ID().Source().Assignment,
	"CSGMembershipInfoExtIEsValue":                             s08.CSGMembershipInfoExtIEs().ID().Source().Assignment,
	"ERABModificationConfirmIEValue":                           s49.ERABModificationConfirmIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModConfIEValue":                       s19.ERABModifyItemBearerModConfIEs().ID().Source().Assignment,
	"ERABModifyItemBearerModConfExtIEsValue":                   s10.ERABModifyItemBearerModConfExtIEs().ID().Source().Assignment,
	"UEContextModificationIndicationIEValue":                   s24.UEContextModificationIndicationIEs().ID().Source().Assignment,
	"UEContextModificationConfirmIEValue":                      s27.UEContextModificationConfirmIEs().ID().Source().Assignment,
	"UEContextSuspendRequestIEValue":                           s57.UEContextSuspendRequestIEs().ID().Source().Assignment,
	"UEContextSuspendResponseIEValue":                          s37.UEContextSuspendResponseIEs().ID().Source().Assignment,
	"UEContextResumeRequestIEValue":                            s48.UEContextResumeRequestIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeReqIEValue":                   s18.ERABFailedToResumeItemResumeReqIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeReqExtIEsValue":               s10.ERABFailedToResumeItemResumeReqExtIEs().ID().Source().Assignment,
	"UEContextResumeResponseIEValue":                           s49.UEContextResumeResponseIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeResIEValue":                   s18.ERABFailedToResumeItemResumeResIEs().ID().Source().Assignment,
	"ERABFailedToResumeItemResumeResExtIEsValue":               s10.ERABFailedToResumeItemResumeResExtIEs().ID().Source().Assignment,
	"UEContextResumeFailureIEValue":                            s28.UEContextResumeFailureIEs().ID().Source().Assignment,
	"ConnectionEstablishmentIndicationIEValue":                 s39.ConnectionEstablishmentIndicationIEs().ID().Source().Assignment,
	"RetrieveUEInformationIEValue":                             s36.RetrieveUEInformationIEs().ID().Source().Assignment,
	"UEInformationTransferIEValue":                             s40.UEInformationTransferIEs().ID().Source().Assignment,
	"ENBCPRelocationIndicationIEValue":                         s47.ENBCPRelocationIndicationIEs().ID().Source().Assignment,
	"MMECPRelocationIndicationIEValue":                         s12.MMECPRelocationIndicationIEs().ID().Source().Assignment,
	"SecondaryRATDataUsageReportIEValue":                       s57.SecondaryRATDataUsageReportIEs().ID().Source().Assignment,
	"UERadioCapabilityIDMappingRequestIEValue":                 s14.UERadioCapabilityIDMappingRequestIEs().ID().Source().Assignment,
	"UERadioCapabilityIDMappingResponseIEValue":                s28.UERadioCapabilityIDMappingResponseIEs().ID().Source().Assignment,
	"S1RemovalRequestIEValue":                                  s24.S1RemovalRequestIEs().ID().Source().Assignment,
	"S1RemovalResponseIEValue":                                 s27.S1RemovalResponseIEs().ID().Source().Assignment,
	"S1RemovalFailureIEValue":                                  s27.S1RemovalFailureIEs().ID().Source().Assignment,
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
	var decoded s66.S1APPDU
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
	var decoded s17.Cause
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
	var decoded s37.ERABInformationListItem
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
	var decoded s37.ERABInformationListItem
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
	var decoded s37.ERABInformationListItem
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
	codec := s15.EventTriggerExtIEValueIEFieldTableCodec(s10.EventTriggerExtIEs().Table())
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
	var decoded s66.S1APPDU
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
	var decoded s61.Paging
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
	var decoded s66.S1APPDU
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
	var decoded s55.ResetAcknowledge
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
	var decoded s22.EventTrigger
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
	var decoded s22.MeasurementThresholdL1LoggedMDT
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
	var decoded s39.SensorNameConfig
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
	var decoded s50.TargeteNBToSourceeNBTransparentContainer
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
	var decoded s50.TargeteNBToSourceeNBTransparentContainer
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
	var decoded s50.TargeteNBToSourceeNBTransparentContainer
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
	binding := s50.TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList()
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
	binding := s42.TAIItemIEs().TAIItem()
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
func FuzzAPERS1APPDUProtocolValueNonzeroTerminalPadding(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
	f.Add(asn1VectorHexForFuzz("000a4012000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		report, err := decoded.UnmarshalAPER(input, aper.WithNonzeroTerminalPadding())
		asn1VectorCheckPaddingReport(t, report, input, false)
		if err != nil {
			return
		}
		replay, err := decoded.MarshalAPER()
		if err != nil {
			t.Fatalf("accepted input cannot replay: %v", err)
		}
		if !bytes.Equal(replay, input) {
			t.Fatalf("replay = %x, want %x", replay, input)
		}
		fresh, err := decoded.MarshalAPER(aper.WithoutReplay())
		if err != nil {
			t.Fatalf("fresh encode: %v", err)
		}
		var again s66.S1APPDU
		freshReport, err := again.UnmarshalAPER(fresh)
		asn1VectorCheckPaddingReport(t, freshReport, fresh, true)
		if err != nil {
			t.Fatalf("fresh decode: %v", err)
		}
	})
}
func FuzzAPERS1APPDUProtocolValueReceiverNonzeroTerminalPadding(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
	f.Add(asn1VectorHexForFuzz("000a4012000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		report, err := decoded.UnmarshalAPER(input, aper.WithNonzeroTerminalPadding(), aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, report, input, false)
		if err != nil {
			return
		}
		replay, err := decoded.MarshalAPER()
		if err != nil {
			t.Fatalf("accepted input cannot replay: %v", err)
		}
		if !bytes.Equal(replay, input) {
			t.Fatalf("replay = %x, want %x", replay, input)
		}
		fresh, err := decoded.MarshalAPER(aper.WithoutReplay())
		if err != nil {
			t.Fatalf("fresh encode: %v", err)
		}
		var again s66.S1APPDU
		freshReport, err := again.UnmarshalAPER(fresh, aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, freshReport, fresh, true)
		if err != nil {
			t.Fatalf("fresh decode: %v", err)
		}
	})
}
func FuzzAPERS1APPDUProtocolValue(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("001240140000030000000200010008000200020002400126"))
	f.Add(asn1VectorHexForFuzz("000a4012000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERCause(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("26"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s17.Cause
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERERABInformationListItemProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("250000013d400100"))
	f.Add(asn1VectorHexForFuzz("250000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("250000013d4001ff"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s37.ERABInformationListItem
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERProtocolIEField(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("12344001aa"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = s15.EventTriggerExtIEValueIEFieldTableCodec(s10.EventTriggerExtIEs().Table()).DecodeAPER(input)
	})
}
func FuzzAPERS1APPDUNonzeroTerminalPadding(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		report, err := decoded.UnmarshalAPER(input, aper.WithNonzeroTerminalPadding())
		asn1VectorCheckPaddingReport(t, report, input, false)
		if err != nil {
			return
		}
		replay, err := decoded.MarshalAPER()
		if err != nil {
			t.Fatalf("accepted input cannot replay: %v", err)
		}
		if !bytes.Equal(replay, input) {
			t.Fatalf("replay = %x, want %x", replay, input)
		}
		fresh, err := decoded.MarshalAPER(aper.WithoutReplay())
		if err != nil {
			t.Fatalf("fresh encode: %v", err)
		}
		var again s66.S1APPDU
		freshReport, err := again.UnmarshalAPER(fresh)
		asn1VectorCheckPaddingReport(t, freshReport, fresh, true)
		if err != nil {
			t.Fatalf("fresh decode: %v", err)
		}
	})
}
func FuzzAPERS1APPDUReceiverNonzeroTerminalPadding(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		report, err := decoded.UnmarshalAPER(input, aper.WithNonzeroTerminalPadding(), aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, report, input, false)
		if err != nil {
			return
		}
		replay, err := decoded.MarshalAPER()
		if err != nil {
			t.Fatalf("accepted input cannot replay: %v", err)
		}
		if !bytes.Equal(replay, input) {
			t.Fatalf("replay = %x, want %x", replay, input)
		}
		fresh, err := decoded.MarshalAPER(aper.WithoutReplay())
		if err != nil {
			t.Fatalf("fresh encode: %v", err)
		}
		var again s66.S1APPDU
		freshReport, err := again.UnmarshalAPER(fresh, aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, freshReport, fresh, true)
		if err != nil {
			t.Fatalf("fresh decode: %v", err)
		}
	})
}
func FuzzAPERS1APPDU(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s66.S1APPDU
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERPagingProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001002e400b00002f40060001f0101234"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s61.Paging
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERResetAcknowledgeProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("000001005d400900005b000460070009"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s55.ResetAcknowledge
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPEREventTriggerProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s22.EventTrigger
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERMeasurementThresholdL1LoggedMDTProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s22.MeasurementThresholdL1LoggedMDT
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERSensorNameConfigProtocolIes(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("80fffc4004deadbeef"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s39.SensorNameConfig
		_, _ = decoded.UnmarshalAPER(input)
	})
}
func FuzzAPERTargeteNBToSourceeNBTransparentContainerProtocolExtensions(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("4001010000013e401100013f400c4a000000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000fffc4004deadbeef"))
	f.Add(asn1VectorHexForFuzz("4001010000013e4000"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s50.TargeteNBToSourceeNBTransparentContainer
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
		_, _, _ = s50.TargeteNBToSourceeNBTransparentContainerExtIEsValueExtensionFieldTableCodec(s50.TargeteNBToSourceeNBTransparentContainerExtIEs().Table()).DecodeAPER(bb.CompleteBytes())
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
		_, _, _ = s42.TAIItemIEValueIEFieldTableCodec(s42.TAIItemIEs().Table()).DecodeAPER(bb.CompleteBytes())
	})
}
