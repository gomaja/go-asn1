// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
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
	s56 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s56"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

type selectedAccessor interface{ Selected() (any, bool) }

func selectedAssert(value any) string {
	selected, ok := value.(selectedAccessor)
	if !ok {
		panic("missing Selected")
	}
	got, active := selected.Selected()
	pointer := reflect.ValueOf(value)
	var want any
	var accessor string
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
			want = results[0].Interface()
			accessor = method.Name
			break
		}
	}
	if active != (want != nil) || got != want {
		panic(fmt.Sprintf("Selected %s differs from %s", pointer.Type(), accessor))
	}
	if allocations := testing.AllocsPerRun(100, func() { selected.Selected() }); allocations != 0 {
		panic(fmt.Sprintf("Selected %s allocations=%g", pointer.Type(), allocations))
	}
	if accessor != "" {
		return pointer.Type().Elem().Name() + "." + accessor
	}
	return ""
}
func selectedObserve(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	if value.Kind() == reflect.Interface {
		if !value.IsNil() {
			selectedObserve(value.Elem())
		}
		return
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}
		if value.CanInterface() {
			if _, ok := value.Interface().(selectedAccessor); ok {
				row := selectedAssert(value.Interface())
				if row != "" {
					fmt.Printf("selected decoded row %s\n", row)
					selected, _ := value.Interface().(selectedAccessor).Selected()
					selectedObserve(reflect.ValueOf(selected))
				}
				return
			}
		}
		selectedObserve(value.Elem())
		return
	}
	if value.Kind() == reflect.Struct {
		if value.CanAddr() && value.Addr().CanInterface() {
			if _, ok := value.Addr().Interface().(selectedAccessor); ok {
				selectedObserve(value.Addr())
				return
			}
		}
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				selectedObserve(value.Field(i))
			}
		}
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < value.Len(); i++ {
			selectedObserve(value.Index(i))
		}
	}
}
func selectedAssertOpaque(value any) {
	opaque, ok := value.(interface {
		Opaque() (aper.OpaqueOpenType, bool)
	}).Opaque()
	if !ok {
		panic("fixture does not contain an opaque value")
	}
	contents := opaque.Bytes()
	if len(contents) != 1 || contents[0] != 0x42 {
		panic("opaque fixture contents differ")
	}
	selectedAssert(value)
}
func TestSelectedEveryUnionAndRow(t *testing.T) {
	budget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaqueValue, err := aper.BuildOpaqueOpenType([]byte{0x42}, budget)
	if err != nil {
		t.Fatal(err)
	}
	var unions, rows int
	t.Run("AdditionalGUTIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.AdditionalGUTIExtIEsValue)(nil))
		selectedAssert(&s03.AdditionalGUTIExtIEsValue{})
		opaque := func() s03.AdditionalGUTIExtIEsValue {
			sealed := s03.AdditionalGUTIExtIEsValue{}
			*s03.BridgeAdditionalGUTIExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeAdditionalGUTIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AllocationAndRetentionPriorityExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.AllocationAndRetentionPriorityExtIEsValue)(nil))
		selectedAssert(&s03.AllocationAndRetentionPriorityExtIEsValue{})
		opaque := func() s03.AllocationAndRetentionPriorityExtIEsValue {
			sealed := s03.AllocationAndRetentionPriorityExtIEsValue{}
			*s03.BridgeAllocationAndRetentionPriorityExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeAllocationAndRetentionPriorityExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AssistanceDataForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.AssistanceDataForPagingExtIEsValue)(nil))
		selectedAssert(&s03.AssistanceDataForPagingExtIEsValue{})
		opaque := func() s03.AssistanceDataForPagingExtIEsValue {
			sealed := s03.AssistanceDataForPagingExtIEsValue{}
			*s03.BridgeAssistanceDataForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeAssistanceDataForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AssistanceDataForRecommendedCellsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.AssistanceDataForRecommendedCellsExtIEsValue)(nil))
		selectedAssert(&s03.AssistanceDataForRecommendedCellsExtIEsValue{})
		opaque := func() s03.AssistanceDataForRecommendedCellsExtIEsValue {
			sealed := s03.AssistanceDataForRecommendedCellsExtIEsValue{}
			*s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToDLDiscardingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.BearersSubjectToDLDiscardingItemExtIEsValue)(nil))
		selectedAssert(&s03.BearersSubjectToDLDiscardingItemExtIEsValue{})
		opaque := func() s03.BearersSubjectToDLDiscardingItemExtIEsValue {
			sealed := s03.BearersSubjectToDLDiscardingItemExtIEsValue{}
			*s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToDLDiscardingItemIEValue", func(t *testing.T) {
		selectedAssert((*s17.BearersSubjectToDLDiscardingItemIEValue)(nil))
		selectedAssert(&s17.BearersSubjectToDLDiscardingItemIEValue{})
		opaque := func() s17.BearersSubjectToDLDiscardingItemIEValue {
			sealed := s17.BearersSubjectToDLDiscardingItemIEValue{}
			*s17.BridgeBearersSubjectToDLDiscardingItemIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeBearersSubjectToDLDiscardingItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.BearersSubjectToDLDiscardingItemIEValue {
				sealed := s17.BearersSubjectToDLDiscardingItemIEValue{}
				*s17.BridgeBearersSubjectToDLDiscardingItemIEValueFieldId(&sealed) = s00.ProtocolIEID(351)
				*s17.BridgeBearersSubjectToDLDiscardingItemIEValueFieldRowBearersSubjectToDLDiscardingItem(&sealed) = new(s17.BearersSubjectToDLDiscardingItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToEarlyStatusTransferItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue)(nil))
		selectedAssert(&s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue{})
		opaque := func() s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue {
			sealed := s03.BearersSubjectToEarlyStatusTransferItemExtIEsValue{}
			*s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToEarlyStatusTransferItemIEValue", func(t *testing.T) {
		selectedAssert((*s17.BearersSubjectToEarlyStatusTransferItemIEValue)(nil))
		selectedAssert(&s17.BearersSubjectToEarlyStatusTransferItemIEValue{})
		opaque := func() s17.BearersSubjectToEarlyStatusTransferItemIEValue {
			sealed := s17.BearersSubjectToEarlyStatusTransferItemIEValue{}
			*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.BearersSubjectToEarlyStatusTransferItemIEValue {
				sealed := s17.BearersSubjectToEarlyStatusTransferItemIEValue{}
				*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldId(&sealed) = s00.ProtocolIEID(322)
				*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldRowBearersSubjectToEarlyStatusTransferItem(&sealed) = new(s17.BearersSubjectToEarlyStatusTransferItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToStatusTransferItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s16.BearersSubjectToStatusTransferItemExtIEsValue)(nil))
		selectedAssert(&s16.BearersSubjectToStatusTransferItemExtIEsValue{})
		opaque := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
			sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(179)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(&sealed) = new(s16.COUNTValueExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(180)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(&sealed) = new(s16.COUNTValueExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(181)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(&sealed) = new(s00.ReceiveStatusOfULPDCPSDUsExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(217)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(&sealed) = new(s16.COUNTvaluePDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(218)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(&sealed) = new(s16.COUNTvaluePDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(219)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(&sealed) = new(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToStatusTransferItemIEValue", func(t *testing.T) {
		selectedAssert((*s25.BearersSubjectToStatusTransferItemIEValue)(nil))
		selectedAssert(&s25.BearersSubjectToStatusTransferItemIEValue{})
		opaque := func() s25.BearersSubjectToStatusTransferItemIEValue {
			sealed := s25.BearersSubjectToStatusTransferItemIEValue{}
			*s25.BridgeBearersSubjectToStatusTransferItemIEValueFieldIsOpaque(&sealed) = true
			*s25.BridgeBearersSubjectToStatusTransferItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s25.BearersSubjectToStatusTransferItemIEValue {
				sealed := s25.BearersSubjectToStatusTransferItemIEValue{}
				*s25.BridgeBearersSubjectToStatusTransferItemIEValueFieldId(&sealed) = s00.ProtocolIEID(89)
				*s25.BridgeBearersSubjectToStatusTransferItemIEValueFieldRowBearersSubjectToStatusTransferItem(&sealed) = new(s25.BearersSubjectToStatusTransferItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BluetoothMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.BluetoothMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s03.BluetoothMeasurementConfigurationExtIEsValue{})
		opaque := func() s03.BluetoothMeasurementConfigurationExtIEsValue {
			sealed := s03.BluetoothMeasurementConfigurationExtIEsValue{}
			*s03.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CGIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CGIExtIEsValue)(nil))
		selectedAssert(&s03.CGIExtIEsValue{})
		opaque := func() s03.CGIExtIEsValue {
			sealed := s03.CGIExtIEsValue{}
			*s03.BridgeCGIExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCGIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CNTypeRestrictionsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CNTypeRestrictionsItemExtIEsValue)(nil))
		selectedAssert(&s03.CNTypeRestrictionsItemExtIEsValue{})
		opaque := func() s03.CNTypeRestrictionsItemExtIEsValue {
			sealed := s03.CNTypeRestrictionsItemExtIEsValue{}
			*s03.BridgeCNTypeRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCNTypeRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTValueExtendedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.COUNTValueExtendedExtIEsValue)(nil))
		selectedAssert(&s03.COUNTValueExtendedExtIEsValue{})
		opaque := func() s03.COUNTValueExtendedExtIEsValue {
			sealed := s03.COUNTValueExtendedExtIEsValue{}
			*s03.BridgeCOUNTValueExtendedExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCOUNTValueExtendedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTvalueExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.COUNTvalueExtIEsValue)(nil))
		selectedAssert(&s03.COUNTvalueExtIEsValue{})
		opaque := func() s03.COUNTvalueExtIEsValue {
			sealed := s03.COUNTvalueExtIEsValue{}
			*s03.BridgeCOUNTvalueExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCOUNTvalueExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTvaluePDCPSNlength18ExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.COUNTvaluePDCPSNlength18ExtIEsValue)(nil))
		selectedAssert(&s03.COUNTvaluePDCPSNlength18ExtIEsValue{})
		opaque := func() s03.COUNTvaluePDCPSNlength18ExtIEsValue {
			sealed := s03.COUNTvaluePDCPSNlength18ExtIEsValue{}
			*s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CSGIdListItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CSGIdListItemExtIEsValue)(nil))
		selectedAssert(&s03.CSGIdListItemExtIEsValue{})
		opaque := func() s03.CSGIdListItemExtIEsValue {
			sealed := s03.CSGIdListItemExtIEsValue{}
			*s03.BridgeCSGIdListItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCSGIdListItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CSGMembershipInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CSGMembershipInfoExtIEsValue)(nil))
		selectedAssert(&s03.CSGMembershipInfoExtIEsValue{})
		opaque := func() s03.CSGMembershipInfoExtIEsValue {
			sealed := s03.CSGMembershipInfoExtIEsValue{}
			*s03.BridgeCSGMembershipInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCSGMembershipInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CancelledCellinEAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CancelledCellinEAIItemExtIEsValue)(nil))
		selectedAssert(&s03.CancelledCellinEAIItemExtIEsValue{})
		opaque := func() s03.CancelledCellinEAIItemExtIEsValue {
			sealed := s03.CancelledCellinEAIItemExtIEsValue{}
			*s03.BridgeCancelledCellinEAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCancelledCellinEAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CancelledCellinTAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CancelledCellinTAIItemExtIEsValue)(nil))
		selectedAssert(&s03.CancelledCellinTAIItemExtIEsValue{})
		opaque := func() s03.CancelledCellinTAIItemExtIEsValue {
			sealed := s03.CancelledCellinTAIItemExtIEsValue{}
			*s03.BridgeCancelledCellinTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCancelledCellinTAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("Cdma2000OneXSRVCCInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.Cdma2000OneXSRVCCInfoExtIEsValue)(nil))
		selectedAssert(&s03.Cdma2000OneXSRVCCInfoExtIEsValue{})
		opaque := func() s03.Cdma2000OneXSRVCCInfoExtIEsValue {
			sealed := s03.Cdma2000OneXSRVCCInfoExtIEsValue{}
			*s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCdma2000OneXSRVCCInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellBasedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellBasedMDTExtIEsValue)(nil))
		selectedAssert(&s03.CellBasedMDTExtIEsValue{})
		opaque := func() s03.CellBasedMDTExtIEsValue {
			sealed := s03.CellBasedMDTExtIEsValue{}
			*s03.BridgeCellBasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellBasedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellBasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellBasedQMCExtIEsValue)(nil))
		selectedAssert(&s03.CellBasedQMCExtIEsValue{})
		opaque := func() s03.CellBasedQMCExtIEsValue {
			sealed := s03.CellBasedQMCExtIEsValue{}
			*s03.BridgeCellBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellBasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellIDBroadcastItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellIDBroadcastItemExtIEsValue)(nil))
		selectedAssert(&s03.CellIDBroadcastItemExtIEsValue{})
		opaque := func() s03.CellIDBroadcastItemExtIEsValue {
			sealed := s03.CellIDBroadcastItemExtIEsValue{}
			*s03.BridgeCellIDBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellIDBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellIDCancelledItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellIDCancelledItemExtIEsValue)(nil))
		selectedAssert(&s03.CellIDCancelledItemExtIEsValue{})
		opaque := func() s03.CellIDCancelledItemExtIEsValue {
			sealed := s03.CellIDCancelledItemExtIEsValue{}
			*s03.BridgeCellIDCancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellIDCancelledItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellIdentifierAndCELevelForCECapableUEsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue)(nil))
		selectedAssert(&s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue{})
		opaque := func() s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue {
			sealed := s03.CellIdentifierAndCELevelForCECapableUEsExtIEsValue{}
			*s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CellTrafficTraceIEValue", func(t *testing.T) {
		selectedAssert((*s20.CellTrafficTraceIEValue)(nil))
		selectedAssert(&s20.CellTrafficTraceIEValue{})
		opaque := func() s20.CellTrafficTraceIEValue {
			sealed := s20.CellTrafficTraceIEValue{}
			*s20.BridgeCellTrafficTraceIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeCellTrafficTraceIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s20.BridgeCellTrafficTraceIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s20.BridgeCellTrafficTraceIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s20.BridgeCellTrafficTraceIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s20.BridgeCellTrafficTraceIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(131)
				*s20.BridgeCellTrafficTraceIEValueFieldRowTraceCollectionEntityIPAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.CellTrafficTraceIEValue {
				sealed := s20.CellTrafficTraceIEValue{}
				*s20.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(166)
				*s20.BridgeCellTrafficTraceIEValueFieldRowPrivacyIndicator(&sealed) = new(s00.PrivacyIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("CellTypeExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CellTypeExtIEsValue)(nil))
		selectedAssert(&s03.CellTypeExtIEsValue{})
		opaque := func() s03.CellTypeExtIEsValue {
			sealed := s03.CellTypeExtIEsValue{}
			*s03.BridgeCellTypeExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCellTypeExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CompletedCellinEAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CompletedCellinEAIItemExtIEsValue)(nil))
		selectedAssert(&s03.CompletedCellinEAIItemExtIEsValue{})
		opaque := func() s03.CompletedCellinEAIItemExtIEsValue {
			sealed := s03.CompletedCellinEAIItemExtIEsValue{}
			*s03.BridgeCompletedCellinEAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCompletedCellinEAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CompletedCellinTAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CompletedCellinTAIItemExtIEsValue)(nil))
		selectedAssert(&s03.CompletedCellinTAIItemExtIEsValue{})
		opaque := func() s03.CompletedCellinTAIItemExtIEsValue {
			sealed := s03.CompletedCellinTAIItemExtIEsValue{}
			*s03.BridgeCompletedCellinTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCompletedCellinTAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ConnectedengNBItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ConnectedengNBItemExtIEsValue)(nil))
		selectedAssert(&s03.ConnectedengNBItemExtIEsValue{})
		opaque := func() s03.ConnectedengNBItemExtIEsValue {
			sealed := s03.ConnectedengNBItemExtIEsValue{}
			*s03.BridgeConnectedengNBItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeConnectedengNBItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ConnectionEstablishmentIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s39.ConnectionEstablishmentIndicationIEValue)(nil))
		selectedAssert(&s39.ConnectionEstablishmentIndicationIEValue{})
		opaque := func() s39.ConnectionEstablishmentIndicationIEValue {
			sealed := s39.ConnectionEstablishmentIndicationIEValue{}
			*s39.BridgeConnectionEstablishmentIndicationIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeConnectionEstablishmentIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(253)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(&sealed) = new(s17.DLCPSecurityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowEndIndication(&sealed) = new(s00.EndIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(&sealed) = new(s21.ERABLevelQoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ConnectionEstablishmentIndicationIEValue {
				sealed := s39.ConnectionEstablishmentIndicationIEValue{}
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s39.BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ContextatSourceExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ContextatSourceExtIEsValue)(nil))
		selectedAssert(&s03.ContextatSourceExtIEsValue{})
		opaque := func() s03.ContextatSourceExtIEsValue {
			sealed := s03.ContextatSourceExtIEsValue{}
			*s03.BridgeContextatSourceExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeContextatSourceExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CriticalityDiagnosticsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CriticalityDiagnosticsExtIEsValue)(nil))
		selectedAssert(&s03.CriticalityDiagnosticsExtIEsValue{})
		opaque := func() s03.CriticalityDiagnosticsExtIEsValue {
			sealed := s03.CriticalityDiagnosticsExtIEsValue{}
			*s03.BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CriticalityDiagnosticsIEItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.CriticalityDiagnosticsIEItemExtIEsValue)(nil))
		selectedAssert(&s03.CriticalityDiagnosticsIEItemExtIEsValue{})
		opaque := func() s03.CriticalityDiagnosticsIEItemExtIEsValue {
			sealed := s03.CriticalityDiagnosticsIEItemExtIEsValue{}
			*s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeCriticalityDiagnosticsIEItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DAPSRequestInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.DAPSRequestInfoExtIEsValue)(nil))
		selectedAssert(&s03.DAPSRequestInfoExtIEsValue{})
		opaque := func() s03.DAPSRequestInfoExtIEsValue {
			sealed := s03.DAPSRequestInfoExtIEsValue{}
			*s03.BridgeDAPSRequestInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeDAPSRequestInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DAPSResponseInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.DAPSResponseInfoExtIEsValue)(nil))
		selectedAssert(&s03.DAPSResponseInfoExtIEsValue{})
		opaque := func() s03.DAPSResponseInfoExtIEsValue {
			sealed := s03.DAPSResponseInfoExtIEsValue{}
			*s03.BridgeDAPSResponseInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeDAPSResponseInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DAPSResponseInfoItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.DAPSResponseInfoItemExtIEsValue)(nil))
		selectedAssert(&s04.DAPSResponseInfoItemExtIEsValue{})
		opaque := func() s04.DAPSResponseInfoItemExtIEsValue {
			sealed := s04.DAPSResponseInfoItemExtIEsValue{}
			*s04.BridgeDAPSResponseInfoItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeDAPSResponseInfoItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DAPSResponseInfoListIEValue", func(t *testing.T) {
		selectedAssert((*s17.DAPSResponseInfoListIEValue)(nil))
		selectedAssert(&s17.DAPSResponseInfoListIEValue{})
		opaque := func() s17.DAPSResponseInfoListIEValue {
			sealed := s17.DAPSResponseInfoListIEValue{}
			*s17.BridgeDAPSResponseInfoListIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeDAPSResponseInfoListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.DAPSResponseInfoListIEValue {
				sealed := s17.DAPSResponseInfoListIEValue{}
				*s17.BridgeDAPSResponseInfoListIEValueFieldId(&sealed) = s00.ProtocolIEID(319)
				*s17.BridgeDAPSResponseInfoListIEValueFieldRowDAPSResponseInfoItem(&sealed) = new(s17.DAPSResponseInfoItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DLCPSecurityInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.DLCPSecurityInformationExtIEsValue)(nil))
		selectedAssert(&s04.DLCPSecurityInformationExtIEsValue{})
		opaque := func() s04.DLCPSecurityInformationExtIEsValue {
			sealed := s04.DLCPSecurityInformationExtIEsValue{}
			*s04.BridgeDLCPSecurityInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeDLCPSecurityInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DeactivateTraceIEValue", func(t *testing.T) {
		selectedAssert((*s09.DeactivateTraceIEValue)(nil))
		selectedAssert(&s09.DeactivateTraceIEValue{})
		opaque := func() s09.DeactivateTraceIEValue {
			sealed := s09.DeactivateTraceIEValue{}
			*s09.BridgeDeactivateTraceIEValueFieldIsOpaque(&sealed) = true
			*s09.BridgeDeactivateTraceIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s09.DeactivateTraceIEValue {
				sealed := s09.DeactivateTraceIEValue{}
				*s09.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s09.BridgeDeactivateTraceIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DeactivateTraceIEValue {
				sealed := s09.DeactivateTraceIEValue{}
				*s09.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s09.BridgeDeactivateTraceIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DeactivateTraceIEValue {
				sealed := s09.DeactivateTraceIEValue{}
				*s09.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s09.BridgeDeactivateTraceIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkNASTransportIEValue", func(t *testing.T) {
		selectedAssert((*s53.DownlinkNASTransportIEValue)(nil))
		selectedAssert(&s53.DownlinkNASTransportIEValue{})
		opaque := func() s53.DownlinkNASTransportIEValue {
			sealed := s53.DownlinkNASTransportIEValue{}
			*s53.BridgeDownlinkNASTransportIEValueFieldIsOpaque(&sealed) = true
			*s53.BridgeDownlinkNASTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowHandoverRestrictionList(&sealed) = new(s53.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(249)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowDLNASPDUDeliveryAckRequest(&sealed) = new(s00.DLNASPDUDeliveryAckRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(275)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowUECapabilityInfoRequest(&sealed) = new(s00.UECapabilityInfoRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowEndIndication(&sealed) = new(s00.EndIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.DownlinkNASTransportIEValue {
				sealed := s53.DownlinkNASTransportIEValue{}
				*s53.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s53.BridgeDownlinkNASTransportIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkNonUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s09.DownlinkNonUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s09.DownlinkNonUEAssociatedLPPaTransportIEValue{})
		opaque := func() s09.DownlinkNonUEAssociatedLPPaTransportIEValue {
			sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValue{}
			*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s09.DownlinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DownlinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkNonUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s09.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkS1cdma2000tunnellingIEValue", func(t *testing.T) {
		selectedAssert((*s50.DownlinkS1cdma2000tunnellingIEValue)(nil))
		selectedAssert(&s50.DownlinkS1cdma2000tunnellingIEValue{})
		opaque := func() s50.DownlinkS1cdma2000tunnellingIEValue {
			sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
			*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldIsOpaque(&sealed) = true
			*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(12)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowERABSubjecttoDataForwardingList(&sealed) = new(s20.ERABSubjecttoDataForwardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(83)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000HOStatus(&sealed) = new(s00.Cdma2000HOStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = new(s00.Cdma2000RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s50.DownlinkS1cdma2000tunnellingIEValue{}
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
				*s50.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = new(s00.Cdma2000PDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s09.DownlinkUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s09.DownlinkUEAssociatedLPPaTransportIEValue{})
		opaque := func() s09.DownlinkUEAssociatedLPPaTransportIEValue {
			sealed := s09.DownlinkUEAssociatedLPPaTransportIEValue{}
			*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s09.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s09.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBCPRelocationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s47.ENBCPRelocationIndicationIEValue)(nil))
		selectedAssert(&s47.ENBCPRelocationIndicationIEValue{})
		opaque := func() s47.ENBCPRelocationIndicationIEValue {
			sealed := s47.ENBCPRelocationIndicationIEValue{}
			*s47.BridgeENBCPRelocationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s47.BridgeENBCPRelocationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowSTMSI(&sealed) = new(s36.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(254)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowULCPSecurityInformation(&sealed) = new(s47.ULCPSecurityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBCPRelocationIndicationIEValue {
				sealed := s47.ENBCPRelocationIndicationIEValue{}
				*s47.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s47.BridgeENBCPRelocationIndicationIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s64.ENBConfigurationTransferIEValue)(nil))
		selectedAssert(&s64.ENBConfigurationTransferIEValue{})
		opaque := func() s64.ENBConfigurationTransferIEValue {
			sealed := s64.ENBConfigurationTransferIEValue{}
			*s64.BridgeENBConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			*s64.BridgeENBConfigurationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(129)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowSONConfigurationTransferECT(&sealed) = new(s64.SONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(294)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferECT(&sealed) = new(s64.ENDCSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.ENBConfigurationTransferIEValue {
				sealed := s64.ENBConfigurationTransferIEValue{}
				*s64.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(310)
				*s64.BridgeENBConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferECT(&sealed) = new(s00.IntersystemSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s26.ENBConfigurationUpdateAcknowledgeIEValue)(nil))
		selectedAssert(&s26.ENBConfigurationUpdateAcknowledgeIEValue{})
		opaque := func() s26.ENBConfigurationUpdateAcknowledgeIEValue {
			sealed := s26.ENBConfigurationUpdateAcknowledgeIEValue{}
			*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.ENBConfigurationUpdateAcknowledgeIEValue {
				sealed := s26.ENBConfigurationUpdateAcknowledgeIEValue{}
				*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateFailureIEValue", func(t *testing.T) {
		selectedAssert((*s26.ENBConfigurationUpdateFailureIEValue)(nil))
		selectedAssert(&s26.ENBConfigurationUpdateFailureIEValue{})
		opaque := func() s26.ENBConfigurationUpdateFailureIEValue {
			sealed := s26.ENBConfigurationUpdateFailureIEValue{}
			*s26.BridgeENBConfigurationUpdateFailureIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeENBConfigurationUpdateFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.ENBConfigurationUpdateFailureIEValue {
				sealed := s26.ENBConfigurationUpdateFailureIEValue{}
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.ENBConfigurationUpdateFailureIEValue {
				sealed := s26.ENBConfigurationUpdateFailureIEValue{}
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.ENBConfigurationUpdateFailureIEValue {
				sealed := s26.ENBConfigurationUpdateFailureIEValue{}
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeENBConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateIEValue", func(t *testing.T) {
		selectedAssert((*s54.ENBConfigurationUpdateIEValue)(nil))
		selectedAssert(&s54.ENBConfigurationUpdateIEValue{})
		opaque := func() s54.ENBConfigurationUpdateIEValue {
			sealed := s54.ENBConfigurationUpdateIEValue{}
			*s54.BridgeENBConfigurationUpdateIEValueFieldIsOpaque(&sealed) = true
			*s54.BridgeENBConfigurationUpdateIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(60)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowENBname(&sealed) = new(s00.ENBname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(64)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowSupportedTAs(&sealed) = new(s40.SupportedTAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowCSGIdList(&sealed) = new(s17.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(137)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowDefaultPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(234)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowNBIoTDefaultPagingDRX(&sealed) = new(s00.NBIoTDefaultPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(292)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToAddList(&sealed) = new(s40.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.ENBConfigurationUpdateIEValue {
				sealed := s54.ENBConfigurationUpdateIEValue{}
				*s54.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(293)
				*s54.BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToRemoveList(&sealed) = new(s40.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBDirectInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s43.ENBDirectInformationTransferIEValue)(nil))
		selectedAssert(&s43.ENBDirectInformationTransferIEValue{})
		opaque := func() s43.ENBDirectInformationTransferIEValue {
			sealed := s43.ENBDirectInformationTransferIEValue{}
			*s43.BridgeENBDirectInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeENBDirectInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.ENBDirectInformationTransferIEValue {
				sealed := s43.ENBDirectInformationTransferIEValue{}
				*s43.BridgeENBDirectInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(121)
				*s43.BridgeENBDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeEDT(&sealed) = new(s43.InterSystemInformationTransferType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBEarlyStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s47.ENBEarlyStatusTransferIEValue)(nil))
		selectedAssert(&s47.ENBEarlyStatusTransferIEValue{})
		opaque := func() s47.ENBEarlyStatusTransferIEValue {
			sealed := s47.ENBEarlyStatusTransferIEValue{}
			*s47.BridgeENBEarlyStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s47.BridgeENBEarlyStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.ENBEarlyStatusTransferIEValue {
				sealed := s47.ENBEarlyStatusTransferIEValue{}
				*s47.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s47.BridgeENBEarlyStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBEarlyStatusTransferIEValue {
				sealed := s47.ENBEarlyStatusTransferIEValue{}
				*s47.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s47.BridgeENBEarlyStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ENBEarlyStatusTransferIEValue {
				sealed := s47.ENBEarlyStatusTransferIEValue{}
				*s47.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(321)
				*s47.BridgeENBEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(&sealed) = new(s47.ENBEarlyStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBEarlyStatusTransferTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue{})
		opaque := func() s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue {
			sealed := s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue{}
			*s47.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s47.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue {
				sealed := s47.ENBEarlyStatusTransferTransparentContainerExtIEsValue{}
				*s47.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(352)
				*s47.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldRowBearersSubjectToDLDiscardingList(&sealed) = new(s17.BearersSubjectToDLDiscardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s25.ENBStatusTransferIEValue)(nil))
		selectedAssert(&s25.ENBStatusTransferIEValue{})
		opaque := func() s25.ENBStatusTransferIEValue {
			sealed := s25.ENBStatusTransferIEValue{}
			*s25.BridgeENBStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s25.BridgeENBStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s25.ENBStatusTransferIEValue {
				sealed := s25.ENBStatusTransferIEValue{}
				*s25.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s25.BridgeENBStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s25.ENBStatusTransferIEValue {
				sealed := s25.ENBStatusTransferIEValue{}
				*s25.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s25.BridgeENBStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s25.ENBStatusTransferIEValue {
				sealed := s25.ENBStatusTransferIEValue{}
				*s25.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(90)
				*s25.BridgeENBStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(&sealed) = new(s25.ENBStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBStatusTransferTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENBStatusTransferTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s04.ENBStatusTransferTransparentContainerExtIEsValue{})
		opaque := func() s04.ENBStatusTransferTransparentContainerExtIEsValue {
			sealed := s04.ENBStatusTransferTransparentContainerExtIEsValue{}
			*s04.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENBX2ExtTLAExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENBX2ExtTLAExtIEsValue)(nil))
		selectedAssert(&s04.ENBX2ExtTLAExtIEsValue{})
		opaque := func() s04.ENBX2ExtTLAExtIEsValue {
			sealed := s04.ENBX2ExtTLAExtIEsValue{}
			*s04.BridgeENBX2ExtTLAExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENBX2ExtTLAExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONConfigurationTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENDCSONConfigurationTransferExtIEsValue)(nil))
		selectedAssert(&s04.ENDCSONConfigurationTransferExtIEsValue{})
		opaque := func() s04.ENDCSONConfigurationTransferExtIEsValue {
			sealed := s04.ENDCSONConfigurationTransferExtIEsValue{}
			*s04.BridgeENDCSONConfigurationTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENDCSONConfigurationTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONeNBIdentificationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENDCSONeNBIdentificationExtIEsValue)(nil))
		selectedAssert(&s04.ENDCSONeNBIdentificationExtIEsValue{})
		opaque := func() s04.ENDCSONeNBIdentificationExtIEsValue {
			sealed := s04.ENDCSONeNBIdentificationExtIEsValue{}
			*s04.BridgeENDCSONeNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENDCSONeNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONengNBIdentificationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENDCSONengNBIdentificationExtIEsValue)(nil))
		selectedAssert(&s04.ENDCSONengNBIdentificationExtIEsValue{})
		opaque := func() s04.ENDCSONengNBIdentificationExtIEsValue {
			sealed := s04.ENDCSONengNBIdentificationExtIEsValue{}
			*s04.BridgeENDCSONengNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENDCSONengNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCTransferTypeReplyExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENDCTransferTypeReplyExtIEsValue)(nil))
		selectedAssert(&s04.ENDCTransferTypeReplyExtIEsValue{})
		opaque := func() s04.ENDCTransferTypeReplyExtIEsValue {
			sealed := s04.ENDCTransferTypeReplyExtIEsValue{}
			*s04.BridgeENDCTransferTypeReplyExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENDCTransferTypeReplyExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCTransferTypeRequestExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ENDCTransferTypeRequestExtIEsValue)(nil))
		selectedAssert(&s04.ENDCTransferTypeRequestExtIEsValue{})
		opaque := func() s04.ENDCTransferTypeRequestExtIEsValue {
			sealed := s04.ENDCTransferTypeRequestExtIEsValue{}
			*s04.BridgeENDCTransferTypeRequestExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeENDCTransferTypeRequestExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABAdmittedItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABAdmittedItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABAdmittedItemExtIEsValue{})
		opaque := func() s04.ERABAdmittedItemExtIEsValue {
			sealed := s04.ERABAdmittedItemExtIEsValue{}
			*s04.BridgeERABAdmittedItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABAdmittedItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABAdmittedItemIEValue", func(t *testing.T) {
		selectedAssert((*s18.ERABAdmittedItemIEValue)(nil))
		selectedAssert(&s18.ERABAdmittedItemIEValue{})
		opaque := func() s18.ERABAdmittedItemIEValue {
			sealed := s18.ERABAdmittedItemIEValue{}
			*s18.BridgeERABAdmittedItemIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeERABAdmittedItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.ERABAdmittedItemIEValue {
				sealed := s18.ERABAdmittedItemIEValue{}
				*s18.BridgeERABAdmittedItemIEValueFieldId(&sealed) = s00.ProtocolIEID(20)
				*s18.BridgeERABAdmittedItemIEValueFieldRowERABAdmittedItem(&sealed) = new(s18.ERABAdmittedItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABDataForwardingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABDataForwardingItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABDataForwardingItemExtIEsValue{})
		opaque := func() s04.ERABDataForwardingItemExtIEsValue {
			sealed := s04.ERABDataForwardingItemExtIEsValue{}
			*s04.BridgeERABDataForwardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABDataForwardingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABDataForwardingItemIEValue", func(t *testing.T) {
		selectedAssert((*s18.ERABDataForwardingItemIEValue)(nil))
		selectedAssert(&s18.ERABDataForwardingItemIEValue{})
		opaque := func() s18.ERABDataForwardingItemIEValue {
			sealed := s18.ERABDataForwardingItemIEValue{}
			*s18.BridgeERABDataForwardingItemIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeERABDataForwardingItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.ERABDataForwardingItemIEValue {
				sealed := s18.ERABDataForwardingItemIEValue{}
				*s18.BridgeERABDataForwardingItemIEValueFieldId(&sealed) = s00.ProtocolIEID(14)
				*s18.BridgeERABDataForwardingItemIEValueFieldRowERABDataForwardingItem(&sealed) = new(s18.ERABDataForwardingItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToResumeItemResumeReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABFailedToResumeItemResumeReqExtIEsValue)(nil))
		selectedAssert(&s04.ERABFailedToResumeItemResumeReqExtIEsValue{})
		opaque := func() s04.ERABFailedToResumeItemResumeReqExtIEsValue {
			sealed := s04.ERABFailedToResumeItemResumeReqExtIEsValue{}
			*s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedToResumeItemResumeReqIEValue", func(t *testing.T) {
		selectedAssert((*s18.ERABFailedToResumeItemResumeReqIEValue)(nil))
		selectedAssert(&s18.ERABFailedToResumeItemResumeReqIEValue{})
		opaque := func() s18.ERABFailedToResumeItemResumeReqIEValue {
			sealed := s18.ERABFailedToResumeItemResumeReqIEValue{}
			*s18.BridgeERABFailedToResumeItemResumeReqIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeERABFailedToResumeItemResumeReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.ERABFailedToResumeItemResumeReqIEValue {
				sealed := s18.ERABFailedToResumeItemResumeReqIEValue{}
				*s18.BridgeERABFailedToResumeItemResumeReqIEValueFieldId(&sealed) = s00.ProtocolIEID(236)
				*s18.BridgeERABFailedToResumeItemResumeReqIEValueFieldRowERABFailedToResumeItemResumeReq(&sealed) = new(s18.ERABFailedToResumeItemResumeReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToResumeItemResumeResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABFailedToResumeItemResumeResExtIEsValue)(nil))
		selectedAssert(&s04.ERABFailedToResumeItemResumeResExtIEsValue{})
		opaque := func() s04.ERABFailedToResumeItemResumeResExtIEsValue {
			sealed := s04.ERABFailedToResumeItemResumeResExtIEsValue{}
			*s04.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedToResumeItemResumeResIEValue", func(t *testing.T) {
		selectedAssert((*s18.ERABFailedToResumeItemResumeResIEValue)(nil))
		selectedAssert(&s18.ERABFailedToResumeItemResumeResIEValue{})
		opaque := func() s18.ERABFailedToResumeItemResumeResIEValue {
			sealed := s18.ERABFailedToResumeItemResumeResIEValue{}
			*s18.BridgeERABFailedToResumeItemResumeResIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeERABFailedToResumeItemResumeResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.ERABFailedToResumeItemResumeResIEValue {
				sealed := s18.ERABFailedToResumeItemResumeResIEValue{}
				*s18.BridgeERABFailedToResumeItemResumeResIEValueFieldId(&sealed) = s00.ProtocolIEID(238)
				*s18.BridgeERABFailedToResumeItemResumeResIEValueFieldRowERABFailedToResumeItemResumeRes(&sealed) = new(s18.ERABFailedToResumeItemResumeRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToSetupItemHOReqAckExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABFailedToSetupItemHOReqAckExtIEsValue)(nil))
		selectedAssert(&s04.ERABFailedToSetupItemHOReqAckExtIEsValue{})
		opaque := func() s04.ERABFailedToSetupItemHOReqAckExtIEsValue {
			sealed := s04.ERABFailedToSetupItemHOReqAckExtIEsValue{}
			*s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedtoSetupItemHOReqAckIEValue", func(t *testing.T) {
		selectedAssert((*s18.ERABFailedtoSetupItemHOReqAckIEValue)(nil))
		selectedAssert(&s18.ERABFailedtoSetupItemHOReqAckIEValue{})
		opaque := func() s18.ERABFailedtoSetupItemHOReqAckIEValue {
			sealed := s18.ERABFailedtoSetupItemHOReqAckIEValue{}
			*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.ERABFailedtoSetupItemHOReqAckIEValue {
				sealed := s18.ERABFailedtoSetupItemHOReqAckIEValue{}
				*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldId(&sealed) = s00.ProtocolIEID(21)
				*s18.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldRowERABFailedtoSetupItemHOReqAck(&sealed) = new(s18.ERABFailedToSetupItemHOReqAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABInformationListIEValue", func(t *testing.T) {
		selectedAssert((*s37.ERABInformationListIEValue)(nil))
		selectedAssert(&s37.ERABInformationListIEValue{})
		opaque := func() s37.ERABInformationListIEValue {
			sealed := s37.ERABInformationListIEValue{}
			*s37.BridgeERABInformationListIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABInformationListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABInformationListIEValue {
				sealed := s37.ERABInformationListIEValue{}
				*s37.BridgeERABInformationListIEValueFieldId(&sealed) = s00.ProtocolIEID(78)
				*s37.BridgeERABInformationListIEValueFieldRowERABInformationListItem(&sealed) = new(s37.ERABInformationListItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABInformationListItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ERABInformationListItemExtIEsValue)(nil))
		selectedAssert(&s37.ERABInformationListItemExtIEsValue{})
		opaque := func() s37.ERABInformationListItemExtIEsValue {
			sealed := s37.ERABInformationListItemExtIEsValue{}
			*s37.BridgeERABInformationListItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABInformationListItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABInformationListItemExtIEsValue {
				sealed := s37.ERABInformationListItemExtIEsValue{}
				*s37.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(317)
				*s37.BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(&sealed) = new(s17.DAPSRequestInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABInformationListItemExtIEsValue {
				sealed := s37.ERABInformationListItemExtIEsValue{}
				*s37.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(328)
				*s37.BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABInformationListItemExtIEsValue {
				sealed := s37.ERABInformationListItemExtIEsValue{}
				*s37.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s37.BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(&sealed) = new(s37.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABInformationListItemExtIEsValue {
				sealed := s37.ERABInformationListItemExtIEsValue{}
				*s37.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(340)
				*s37.BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABItemExtIEsValue{})
		opaque := func() s04.ERABItemExtIEsValue {
			sealed := s04.ERABItemExtIEsValue{}
			*s04.BridgeERABItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABItemIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABItemIEValue)(nil))
		selectedAssert(&s19.ERABItemIEValue{})
		opaque := func() s19.ERABItemIEValue {
			sealed := s19.ERABItemIEValue{}
			*s19.BridgeERABItemIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABItemIEValue {
				sealed := s19.ERABItemIEValue{}
				*s19.BridgeERABItemIEValueFieldId(&sealed) = s00.ProtocolIEID(35)
				*s19.BridgeERABItemIEValueFieldRowERABItem(&sealed) = new(s19.ERABItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModificationConfirmIEValue", func(t *testing.T) {
		selectedAssert((*s49.ERABModificationConfirmIEValue)(nil))
		selectedAssert(&s49.ERABModificationConfirmIEValue{})
		opaque := func() s49.ERABModificationConfirmIEValue {
			sealed := s49.ERABModificationConfirmIEValue{}
			*s49.BridgeERABModificationConfirmIEValueFieldIsOpaque(&sealed) = true
			*s49.BridgeERABModificationConfirmIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s49.BridgeERABModificationConfirmIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s49.BridgeERABModificationConfirmIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(203)
				*s49.BridgeERABModificationConfirmIEValueFieldRowERABModifyListBearerModConf(&sealed) = new(s19.ERABModifyListBearerModConf)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(205)
				*s49.BridgeERABModificationConfirmIEValueFieldRowERABFailedToModifyListBearerModConf(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(210)
				*s49.BridgeERABModificationConfirmIEValueFieldRowERABToBeReleasedListBearerModConf(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s49.BridgeERABModificationConfirmIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABModificationConfirmIEValue {
				sealed := s49.ERABModificationConfirmIEValue{}
				*s49.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s49.BridgeERABModificationConfirmIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModificationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s56.ERABModificationIndicationIEValue)(nil))
		selectedAssert(&s56.ERABModificationIndicationIEValue{})
		opaque := func() s56.ERABModificationIndicationIEValue {
			sealed := s56.ERABModificationIndicationIEValue{}
			*s56.BridgeERABModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeERABModificationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
				*s56.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = new(s20.ERABToBeModifiedListBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
				*s56.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = new(s19.ERABNotToBeModifiedListBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s56.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = new(s17.CSGMembershipInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s56.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s44.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModificationIndicationIEValue {
				sealed := s56.ERABModificationIndicationIEValue{}
				*s56.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyItemBearerModConfExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABModifyItemBearerModConfExtIEsValue)(nil))
		selectedAssert(&s04.ERABModifyItemBearerModConfExtIEsValue{})
		opaque := func() s04.ERABModifyItemBearerModConfExtIEsValue {
			sealed := s04.ERABModifyItemBearerModConfExtIEsValue{}
			*s04.BridgeERABModifyItemBearerModConfExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABModifyItemBearerModConfExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABModifyItemBearerModConfIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABModifyItemBearerModConfIEValue)(nil))
		selectedAssert(&s19.ERABModifyItemBearerModConfIEValue{})
		opaque := func() s19.ERABModifyItemBearerModConfIEValue {
			sealed := s19.ERABModifyItemBearerModConfIEValue{}
			*s19.BridgeERABModifyItemBearerModConfIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABModifyItemBearerModConfIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABModifyItemBearerModConfIEValue {
				sealed := s19.ERABModifyItemBearerModConfIEValue{}
				*s19.BridgeERABModifyItemBearerModConfIEValueFieldId(&sealed) = s00.ProtocolIEID(204)
				*s19.BridgeERABModifyItemBearerModConfIEValueFieldRowERABModifyItemBearerModConf(&sealed) = new(s19.ERABModifyItemBearerModConf)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyItemBearerModResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABModifyItemBearerModResExtIEsValue)(nil))
		selectedAssert(&s04.ERABModifyItemBearerModResExtIEsValue{})
		opaque := func() s04.ERABModifyItemBearerModResExtIEsValue {
			sealed := s04.ERABModifyItemBearerModResExtIEsValue{}
			*s04.BridgeERABModifyItemBearerModResExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABModifyItemBearerModResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABModifyItemBearerModResIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABModifyItemBearerModResIEValue)(nil))
		selectedAssert(&s19.ERABModifyItemBearerModResIEValue{})
		opaque := func() s19.ERABModifyItemBearerModResIEValue {
			sealed := s19.ERABModifyItemBearerModResIEValue{}
			*s19.BridgeERABModifyItemBearerModResIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABModifyItemBearerModResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABModifyItemBearerModResIEValue {
				sealed := s19.ERABModifyItemBearerModResIEValue{}
				*s19.BridgeERABModifyItemBearerModResIEValueFieldId(&sealed) = s00.ProtocolIEID(37)
				*s19.BridgeERABModifyItemBearerModResIEValueFieldRowERABModifyItemBearerModRes(&sealed) = new(s19.ERABModifyItemBearerModRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyRequestIEValue", func(t *testing.T) {
		selectedAssert((*s50.ERABModifyRequestIEValue)(nil))
		selectedAssert(&s50.ERABModifyRequestIEValue{})
		opaque := func() s50.ERABModifyRequestIEValue {
			sealed := s50.ERABModifyRequestIEValue{}
			*s50.BridgeERABModifyRequestIEValueFieldIsOpaque(&sealed) = true
			*s50.BridgeERABModifyRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.ERABModifyRequestIEValue {
				sealed := s50.ERABModifyRequestIEValue{}
				*s50.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s50.BridgeERABModifyRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.ERABModifyRequestIEValue {
				sealed := s50.ERABModifyRequestIEValue{}
				*s50.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s50.BridgeERABModifyRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.ERABModifyRequestIEValue {
				sealed := s50.ERABModifyRequestIEValue{}
				*s50.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s50.BridgeERABModifyRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.ERABModifyRequestIEValue {
				sealed := s50.ERABModifyRequestIEValue{}
				*s50.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(30)
				*s50.BridgeERABModifyRequestIEValueFieldRowERABToBeModifiedListBearerModReq(&sealed) = new(s29.ERABToBeModifiedListBearerModReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.ERABModifyRequestIEValue {
				sealed := s50.ERABModifyRequestIEValue{}
				*s50.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(268)
				*s50.BridgeERABModifyRequestIEValueFieldRowSecondaryRATDataUsageRequest(&sealed) = new(s00.SecondaryRATDataUsageRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyResponseIEValue", func(t *testing.T) {
		selectedAssert((*s56.ERABModifyResponseIEValue)(nil))
		selectedAssert(&s56.ERABModifyResponseIEValue{})
		opaque := func() s56.ERABModifyResponseIEValue {
			sealed := s56.ERABModifyResponseIEValue{}
			*s56.BridgeERABModifyResponseIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeERABModifyResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABModifyResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABModifyResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(31)
				*s56.BridgeERABModifyResponseIEValueFieldRowERABModifyListBearerModRes(&sealed) = new(s19.ERABModifyListBearerModRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(32)
				*s56.BridgeERABModifyResponseIEValueFieldRowERABFailedToModifyList(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABModifyResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABModifyResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABModifyResponseIEValue {
				sealed := s56.ERABModifyResponseIEValue{}
				*s56.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABModifyResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABNotToBeModifiedItemBearerModIndExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue)(nil))
		selectedAssert(&s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue{})
		opaque := func() s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue {
			sealed := s04.ERABNotToBeModifiedItemBearerModIndExtIEsValue{}
			*s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABNotToBeModifiedItemBearerModIndIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABNotToBeModifiedItemBearerModIndIEValue)(nil))
		selectedAssert(&s19.ERABNotToBeModifiedItemBearerModIndIEValue{})
		opaque := func() s19.ERABNotToBeModifiedItemBearerModIndIEValue {
			sealed := s19.ERABNotToBeModifiedItemBearerModIndIEValue{}
			*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABNotToBeModifiedItemBearerModIndIEValue {
				sealed := s19.ERABNotToBeModifiedItemBearerModIndIEValue{}
				*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldId(&sealed) = s00.ProtocolIEID(202)
				*s19.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldRowERABNotToBeModifiedItemBearerModInd(&sealed) = new(s19.ERABNotToBeModifiedItemBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABQoSParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s10.ERABQoSParametersExtIEsValue)(nil))
		selectedAssert(&s10.ERABQoSParametersExtIEsValue{})
		opaque := func() s10.ERABQoSParametersExtIEsValue {
			sealed := s10.ERABQoSParametersExtIEsValue{}
			*s10.BridgeERABQoSParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s10.BridgeERABQoSParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s10.ERABQoSParametersExtIEsValue {
				sealed := s10.ERABQoSParametersExtIEsValue{}
				*s10.BridgeERABQoSParametersExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(273)
				*s10.BridgeERABQoSParametersExtIEsValueFieldRowDownlinkPacketLossRate(&sealed) = new(s00.PacketLossRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s10.ERABQoSParametersExtIEsValue {
				sealed := s10.ERABQoSParametersExtIEsValue{}
				*s10.BridgeERABQoSParametersExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(274)
				*s10.BridgeERABQoSParametersExtIEsValueFieldRowUplinkPacketLossRate(&sealed) = new(s00.PacketLossRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseCommandIEValue", func(t *testing.T) {
		selectedAssert((*s49.ERABReleaseCommandIEValue)(nil))
		selectedAssert(&s49.ERABReleaseCommandIEValue{})
		opaque := func() s49.ERABReleaseCommandIEValue {
			sealed := s49.ERABReleaseCommandIEValue{}
			*s49.BridgeERABReleaseCommandIEValueFieldIsOpaque(&sealed) = true
			*s49.BridgeERABReleaseCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s49.ERABReleaseCommandIEValue {
				sealed := s49.ERABReleaseCommandIEValue{}
				*s49.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s49.BridgeERABReleaseCommandIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABReleaseCommandIEValue {
				sealed := s49.ERABReleaseCommandIEValue{}
				*s49.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s49.BridgeERABReleaseCommandIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABReleaseCommandIEValue {
				sealed := s49.ERABReleaseCommandIEValue{}
				*s49.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s49.BridgeERABReleaseCommandIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABReleaseCommandIEValue {
				sealed := s49.ERABReleaseCommandIEValue{}
				*s49.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
				*s49.BridgeERABReleaseCommandIEValueFieldRowERABToBeReleasedList(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.ERABReleaseCommandIEValue {
				sealed := s49.ERABReleaseCommandIEValue{}
				*s49.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s49.BridgeERABReleaseCommandIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s56.ERABReleaseIndicationIEValue)(nil))
		selectedAssert(&s56.ERABReleaseIndicationIEValue{})
		opaque := func() s56.ERABReleaseIndicationIEValue {
			sealed := s56.ERABReleaseIndicationIEValue{}
			*s56.BridgeERABReleaseIndicationIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeERABReleaseIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(110)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowERABReleasedList(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseIndicationIEValue {
				sealed := s56.ERABReleaseIndicationIEValue{}
				*s56.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABReleaseIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseItemBearerRelCompExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABReleaseItemBearerRelCompExtIEsValue)(nil))
		selectedAssert(&s04.ERABReleaseItemBearerRelCompExtIEsValue{})
		opaque := func() s04.ERABReleaseItemBearerRelCompExtIEsValue {
			sealed := s04.ERABReleaseItemBearerRelCompExtIEsValue{}
			*s04.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABReleaseItemBearerRelCompIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABReleaseItemBearerRelCompIEValue)(nil))
		selectedAssert(&s19.ERABReleaseItemBearerRelCompIEValue{})
		opaque := func() s19.ERABReleaseItemBearerRelCompIEValue {
			sealed := s19.ERABReleaseItemBearerRelCompIEValue{}
			*s19.BridgeERABReleaseItemBearerRelCompIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABReleaseItemBearerRelCompIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABReleaseItemBearerRelCompIEValue {
				sealed := s19.ERABReleaseItemBearerRelCompIEValue{}
				*s19.BridgeERABReleaseItemBearerRelCompIEValueFieldId(&sealed) = s00.ProtocolIEID(15)
				*s19.BridgeERABReleaseItemBearerRelCompIEValueFieldRowERABReleaseItemBearerRelComp(&sealed) = new(s19.ERABReleaseItemBearerRelComp)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseResponseIEValue", func(t *testing.T) {
		selectedAssert((*s56.ERABReleaseResponseIEValue)(nil))
		selectedAssert(&s56.ERABReleaseResponseIEValue{})
		opaque := func() s56.ERABReleaseResponseIEValue {
			sealed := s56.ERABReleaseResponseIEValue{}
			*s56.BridgeERABReleaseResponseIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeERABReleaseResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABReleaseResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABReleaseResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(69)
				*s56.BridgeERABReleaseResponseIEValueFieldRowERABReleaseListBearerRelComp(&sealed) = new(s19.ERABReleaseListBearerRelComp)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(34)
				*s56.BridgeERABReleaseResponseIEValueFieldRowERABFailedToReleaseList(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABReleaseResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABReleaseResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABReleaseResponseIEValue {
				sealed := s56.ERABReleaseResponseIEValue{}
				*s56.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeERABReleaseResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSecurityResultItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABSecurityResultItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABSecurityResultItemExtIEsValue{})
		opaque := func() s04.ERABSecurityResultItemExtIEsValue {
			sealed := s04.ERABSecurityResultItemExtIEsValue{}
			*s04.BridgeERABSecurityResultItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABSecurityResultItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABSecurityResultListIEValue", func(t *testing.T) {
		selectedAssert((*s38.ERABSecurityResultListIEValue)(nil))
		selectedAssert(&s38.ERABSecurityResultListIEValue{})
		opaque := func() s38.ERABSecurityResultListIEValue {
			sealed := s38.ERABSecurityResultListIEValue{}
			*s38.BridgeERABSecurityResultListIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeERABSecurityResultListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.ERABSecurityResultListIEValue {
				sealed := s38.ERABSecurityResultListIEValue{}
				*s38.BridgeERABSecurityResultListIEValueFieldId(&sealed) = s00.ProtocolIEID(334)
				*s38.BridgeERABSecurityResultListIEValueFieldRowERABSecurityResultItem(&sealed) = new(s38.ERABSecurityResultItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupItemBearerSUResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABSetupItemBearerSUResExtIEsValue)(nil))
		selectedAssert(&s04.ERABSetupItemBearerSUResExtIEsValue{})
		opaque := func() s04.ERABSetupItemBearerSUResExtIEsValue {
			sealed := s04.ERABSetupItemBearerSUResExtIEsValue{}
			*s04.BridgeERABSetupItemBearerSUResExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABSetupItemBearerSUResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABSetupItemBearerSUResIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABSetupItemBearerSUResIEValue)(nil))
		selectedAssert(&s19.ERABSetupItemBearerSUResIEValue{})
		opaque := func() s19.ERABSetupItemBearerSUResIEValue {
			sealed := s19.ERABSetupItemBearerSUResIEValue{}
			*s19.BridgeERABSetupItemBearerSUResIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABSetupItemBearerSUResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABSetupItemBearerSUResIEValue {
				sealed := s19.ERABSetupItemBearerSUResIEValue{}
				*s19.BridgeERABSetupItemBearerSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(39)
				*s19.BridgeERABSetupItemBearerSUResIEValueFieldRowERABSetupItemBearerSURes(&sealed) = new(s19.ERABSetupItemBearerSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupItemCtxtSUResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABSetupItemCtxtSUResExtIEsValue)(nil))
		selectedAssert(&s04.ERABSetupItemCtxtSUResExtIEsValue{})
		opaque := func() s04.ERABSetupItemCtxtSUResExtIEsValue {
			sealed := s04.ERABSetupItemCtxtSUResExtIEsValue{}
			*s04.BridgeERABSetupItemCtxtSUResExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABSetupItemCtxtSUResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABSetupItemCtxtSUResIEValue", func(t *testing.T) {
		selectedAssert((*s19.ERABSetupItemCtxtSUResIEValue)(nil))
		selectedAssert(&s19.ERABSetupItemCtxtSUResIEValue{})
		opaque := func() s19.ERABSetupItemCtxtSUResIEValue {
			sealed := s19.ERABSetupItemCtxtSUResIEValue{}
			*s19.BridgeERABSetupItemCtxtSUResIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeERABSetupItemCtxtSUResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.ERABSetupItemCtxtSUResIEValue {
				sealed := s19.ERABSetupItemCtxtSUResIEValue{}
				*s19.BridgeERABSetupItemCtxtSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(50)
				*s19.BridgeERABSetupItemCtxtSUResIEValueFieldRowERABSetupItemCtxtSURes(&sealed) = new(s19.ERABSetupItemCtxtSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s51.ERABSetupRequestIEValue)(nil))
		selectedAssert(&s51.ERABSetupRequestIEValue{})
		opaque := func() s51.ERABSetupRequestIEValue {
			sealed := s51.ERABSetupRequestIEValue{}
			*s51.BridgeERABSetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s51.BridgeERABSetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.ERABSetupRequestIEValue {
				sealed := s51.ERABSetupRequestIEValue{}
				*s51.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s51.BridgeERABSetupRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.ERABSetupRequestIEValue {
				sealed := s51.ERABSetupRequestIEValue{}
				*s51.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s51.BridgeERABSetupRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.ERABSetupRequestIEValue {
				sealed := s51.ERABSetupRequestIEValue{}
				*s51.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s51.BridgeERABSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.ERABSetupRequestIEValue {
				sealed := s51.ERABSetupRequestIEValue{}
				*s51.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(16)
				*s51.BridgeERABSetupRequestIEValueFieldRowERABToBeSetupListBearerSUReq(&sealed) = new(s38.ERABToBeSetupListBearerSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s56.ERABSetupResponseIEValue)(nil))
		selectedAssert(&s56.ERABSetupResponseIEValue{})
		opaque := func() s56.ERABSetupResponseIEValue {
			sealed := s56.ERABSetupResponseIEValue{}
			*s56.BridgeERABSetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeERABSetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeERABSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeERABSetupResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(28)
				*s56.BridgeERABSetupResponseIEValueFieldRowERABSetupListBearerSURes(&sealed) = new(s20.ERABSetupListBearerSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(29)
				*s56.BridgeERABSetupResponseIEValueFieldRowERABFailedToSetupListBearerSURes(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeERABSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.ERABSetupResponseIEValue {
				sealed := s56.ERABSetupResponseIEValue{}
				*s56.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeERABSetupResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeModifiedItemBearerModIndExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABToBeModifiedItemBearerModIndExtIEsValue)(nil))
		selectedAssert(&s04.ERABToBeModifiedItemBearerModIndExtIEsValue{})
		opaque := func() s04.ERABToBeModifiedItemBearerModIndExtIEsValue {
			sealed := s04.ERABToBeModifiedItemBearerModIndExtIEsValue{}
			*s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABToBeModifiedItemBearerModIndExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABToBeModifiedItemBearerModIndIEValue", func(t *testing.T) {
		selectedAssert((*s20.ERABToBeModifiedItemBearerModIndIEValue)(nil))
		selectedAssert(&s20.ERABToBeModifiedItemBearerModIndIEValue{})
		opaque := func() s20.ERABToBeModifiedItemBearerModIndIEValue {
			sealed := s20.ERABToBeModifiedItemBearerModIndIEValue{}
			*s20.BridgeERABToBeModifiedItemBearerModIndIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeERABToBeModifiedItemBearerModIndIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.ERABToBeModifiedItemBearerModIndIEValue {
				sealed := s20.ERABToBeModifiedItemBearerModIndIEValue{}
				*s20.BridgeERABToBeModifiedItemBearerModIndIEValueFieldId(&sealed) = s00.ProtocolIEID(200)
				*s20.BridgeERABToBeModifiedItemBearerModIndIEValueFieldRowERABToBeModifiedItemBearerModInd(&sealed) = new(s20.ERABToBeModifiedItemBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeModifiedItemBearerModReqIEValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeModifiedItemBearerModReqIEValue)(nil))
		selectedAssert(&s29.ERABToBeModifiedItemBearerModReqIEValue{})
		opaque := func() s29.ERABToBeModifiedItemBearerModReqIEValue {
			sealed := s29.ERABToBeModifiedItemBearerModReqIEValue{}
			*s29.BridgeERABToBeModifiedItemBearerModReqIEValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeModifiedItemBearerModReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeModifiedItemBearerModReqIEValue {
				sealed := s29.ERABToBeModifiedItemBearerModReqIEValue{}
				*s29.BridgeERABToBeModifiedItemBearerModReqIEValueFieldId(&sealed) = s00.ProtocolIEID(36)
				*s29.BridgeERABToBeModifiedItemBearerModReqIEValueFieldRowERABToBeModifiedItemBearerModReq(&sealed) = new(s29.ERABToBeModifiedItemBearerModReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeModifyItemBearerModReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s24.ERABToBeModifyItemBearerModReqExtIEsValue)(nil))
		selectedAssert(&s24.ERABToBeModifyItemBearerModReqExtIEsValue{})
		opaque := func() s24.ERABToBeModifyItemBearerModReqExtIEsValue {
			sealed := s24.ERABToBeModifyItemBearerModReqExtIEsValue{}
			*s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.ERABToBeModifyItemBearerModReqExtIEsValue {
				sealed := s24.ERABToBeModifyItemBearerModReqExtIEsValue{}
				*s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(185)
				*s24.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldRowTransportInformation(&sealed) = new(s24.TransportInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemBearerSUReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ERABToBeSetupItemBearerSUReqExtIEsValue)(nil))
		selectedAssert(&s37.ERABToBeSetupItemBearerSUReqExtIEsValue{})
		opaque := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
			sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
			*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s37.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s37.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemBearerSUReqIEValue", func(t *testing.T) {
		selectedAssert((*s38.ERABToBeSetupItemBearerSUReqIEValue)(nil))
		selectedAssert(&s38.ERABToBeSetupItemBearerSUReqIEValue{})
		opaque := func() s38.ERABToBeSetupItemBearerSUReqIEValue {
			sealed := s38.ERABToBeSetupItemBearerSUReqIEValue{}
			*s38.BridgeERABToBeSetupItemBearerSUReqIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeERABToBeSetupItemBearerSUReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.ERABToBeSetupItemBearerSUReqIEValue {
				sealed := s38.ERABToBeSetupItemBearerSUReqIEValue{}
				*s38.BridgeERABToBeSetupItemBearerSUReqIEValueFieldId(&sealed) = s00.ProtocolIEID(17)
				*s38.BridgeERABToBeSetupItemBearerSUReqIEValueFieldRowERABToBeSetupItemBearerSUReq(&sealed) = new(s37.ERABToBeSetupItemBearerSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemCtxtSUReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ERABToBeSetupItemCtxtSUReqExtIEsValue)(nil))
		selectedAssert(&s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{})
		opaque := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
			*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s37.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s37.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemCtxtSUReqIEValue", func(t *testing.T) {
		selectedAssert((*s38.ERABToBeSetupItemCtxtSUReqIEValue)(nil))
		selectedAssert(&s38.ERABToBeSetupItemCtxtSUReqIEValue{})
		opaque := func() s38.ERABToBeSetupItemCtxtSUReqIEValue {
			sealed := s38.ERABToBeSetupItemCtxtSUReqIEValue{}
			*s38.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.ERABToBeSetupItemCtxtSUReqIEValue {
				sealed := s38.ERABToBeSetupItemCtxtSUReqIEValue{}
				*s38.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldId(&sealed) = s00.ProtocolIEID(52)
				*s38.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldRowERABToBeSetupItemCtxtSUReq(&sealed) = new(s38.ERABToBeSetupItemCtxtSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemHOReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ERABToBeSetupItemHOReqExtIEsValue)(nil))
		selectedAssert(&s37.ERABToBeSetupItemHOReqExtIEsValue{})
		opaque := func() s37.ERABToBeSetupItemHOReqExtIEsValue {
			sealed := s37.ERABToBeSetupItemHOReqExtIEsValue{}
			*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemHOReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(143)
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowDataForwardingNotPossible(&sealed) = new(s00.DataForwardingNotPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemHOReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemHOReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s37.ERABToBeSetupItemHOReqExtIEsValue{}
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s37.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s37.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemHOReqIEValue", func(t *testing.T) {
		selectedAssert((*s38.ERABToBeSetupItemHOReqIEValue)(nil))
		selectedAssert(&s38.ERABToBeSetupItemHOReqIEValue{})
		opaque := func() s38.ERABToBeSetupItemHOReqIEValue {
			sealed := s38.ERABToBeSetupItemHOReqIEValue{}
			*s38.BridgeERABToBeSetupItemHOReqIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeERABToBeSetupItemHOReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.ERABToBeSetupItemHOReqIEValue {
				sealed := s38.ERABToBeSetupItemHOReqIEValue{}
				*s38.BridgeERABToBeSetupItemHOReqIEValueFieldId(&sealed) = s00.ProtocolIEID(27)
				*s38.BridgeERABToBeSetupItemHOReqIEValueFieldRowERABToBeSetupItemHOReq(&sealed) = new(s38.ERABToBeSetupItemHOReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSwitchedDLItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ERABToBeSwitchedDLItemExtIEsValue)(nil))
		selectedAssert(&s37.ERABToBeSwitchedDLItemExtIEsValue{})
		opaque := func() s37.ERABToBeSwitchedDLItemExtIEsValue {
			sealed := s37.ERABToBeSwitchedDLItemExtIEsValue{}
			*s37.BridgeERABToBeSwitchedDLItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABToBeSwitchedDLItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABToBeSwitchedDLItemExtIEsValue {
				sealed := s37.ERABToBeSwitchedDLItemExtIEsValue{}
				*s37.BridgeERABToBeSwitchedDLItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s37.BridgeERABToBeSwitchedDLItemExtIEsValueFieldRowSecurityIndication(&sealed) = new(s37.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSwitchedDLItemIEValue", func(t *testing.T) {
		selectedAssert((*s38.ERABToBeSwitchedDLItemIEValue)(nil))
		selectedAssert(&s38.ERABToBeSwitchedDLItemIEValue{})
		opaque := func() s38.ERABToBeSwitchedDLItemIEValue {
			sealed := s38.ERABToBeSwitchedDLItemIEValue{}
			*s38.BridgeERABToBeSwitchedDLItemIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeERABToBeSwitchedDLItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.ERABToBeSwitchedDLItemIEValue {
				sealed := s38.ERABToBeSwitchedDLItemIEValue{}
				*s38.BridgeERABToBeSwitchedDLItemIEValueFieldId(&sealed) = s00.ProtocolIEID(23)
				*s38.BridgeERABToBeSwitchedDLItemIEValueFieldRowERABToBeSwitchedDLItem(&sealed) = new(s38.ERABToBeSwitchedDLItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSwitchedULItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABToBeSwitchedULItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABToBeSwitchedULItemExtIEsValue{})
		opaque := func() s04.ERABToBeSwitchedULItemExtIEsValue {
			sealed := s04.ERABToBeSwitchedULItemExtIEsValue{}
			*s04.BridgeERABToBeSwitchedULItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABToBeSwitchedULItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABToBeSwitchedULItemIEValue", func(t *testing.T) {
		selectedAssert((*s20.ERABToBeSwitchedULItemIEValue)(nil))
		selectedAssert(&s20.ERABToBeSwitchedULItemIEValue{})
		opaque := func() s20.ERABToBeSwitchedULItemIEValue {
			sealed := s20.ERABToBeSwitchedULItemIEValue{}
			*s20.BridgeERABToBeSwitchedULItemIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeERABToBeSwitchedULItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.ERABToBeSwitchedULItemIEValue {
				sealed := s20.ERABToBeSwitchedULItemIEValue{}
				*s20.BridgeERABToBeSwitchedULItemIEValueFieldId(&sealed) = s00.ProtocolIEID(94)
				*s20.BridgeERABToBeSwitchedULItemIEValueFieldRowERABToBeSwitchedULItem(&sealed) = new(s20.ERABToBeSwitchedULItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeUpdatedItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABToBeUpdatedItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABToBeUpdatedItemExtIEsValue{})
		opaque := func() s04.ERABToBeUpdatedItemExtIEsValue {
			sealed := s04.ERABToBeUpdatedItemExtIEsValue{}
			*s04.BridgeERABToBeUpdatedItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABToBeUpdatedItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABToBeUpdatedItemIEValue", func(t *testing.T) {
		selectedAssert((*s37.ERABToBeUpdatedItemIEValue)(nil))
		selectedAssert(&s37.ERABToBeUpdatedItemIEValue{})
		opaque := func() s37.ERABToBeUpdatedItemIEValue {
			sealed := s37.ERABToBeUpdatedItemIEValue{}
			*s37.BridgeERABToBeUpdatedItemIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeERABToBeUpdatedItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ERABToBeUpdatedItemIEValue {
				sealed := s37.ERABToBeUpdatedItemIEValue{}
				*s37.BridgeERABToBeUpdatedItemIEValueFieldId(&sealed) = s00.ProtocolIEID(342)
				*s37.BridgeERABToBeUpdatedItemIEValueFieldRowERABToBeUpdatedItem(&sealed) = new(s37.ERABToBeUpdatedItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABUsageReportItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ERABUsageReportItemExtIEsValue)(nil))
		selectedAssert(&s04.ERABUsageReportItemExtIEsValue{})
		opaque := func() s04.ERABUsageReportItemExtIEsValue {
			sealed := s04.ERABUsageReportItemExtIEsValue{}
			*s04.BridgeERABUsageReportItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeERABUsageReportItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABUsageReportItemIEValue", func(t *testing.T) {
		selectedAssert((*s20.ERABUsageReportItemIEValue)(nil))
		selectedAssert(&s20.ERABUsageReportItemIEValue{})
		opaque := func() s20.ERABUsageReportItemIEValue {
			sealed := s20.ERABUsageReportItemIEValue{}
			*s20.BridgeERABUsageReportItemIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeERABUsageReportItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.ERABUsageReportItemIEValue {
				sealed := s20.ERABUsageReportItemIEValue{}
				*s20.BridgeERABUsageReportItemIEValueFieldId(&sealed) = s00.ProtocolIEID(267)
				*s20.BridgeERABUsageReportItemIEValueFieldRowERABUsageReportItem(&sealed) = new(s20.ERABUsageReportItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("EUTRANCGIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.EUTRANCGIExtIEsValue)(nil))
		selectedAssert(&s04.EUTRANCGIExtIEsValue{})
		opaque := func() s04.EUTRANCGIExtIEsValue {
			sealed := s04.EUTRANCGIExtIEsValue{}
			*s04.BridgeEUTRANCGIExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeEUTRANCGIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("EmergencyAreaIDBroadcastItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.EmergencyAreaIDBroadcastItemExtIEsValue)(nil))
		selectedAssert(&s04.EmergencyAreaIDBroadcastItemExtIEsValue{})
		opaque := func() s04.EmergencyAreaIDBroadcastItemExtIEsValue {
			sealed := s04.EmergencyAreaIDBroadcastItemExtIEsValue{}
			*s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeEmergencyAreaIDBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("EmergencyAreaIDCancelledItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.EmergencyAreaIDCancelledItemExtIEsValue)(nil))
		selectedAssert(&s04.EmergencyAreaIDCancelledItemExtIEsValue{})
		opaque := func() s04.EmergencyAreaIDCancelledItemExtIEsValue {
			sealed := s04.EmergencyAreaIDCancelledItemExtIEsValue{}
			*s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeEmergencyAreaIDCancelledItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ErrorIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s36.ErrorIndicationIEValue)(nil))
		selectedAssert(&s36.ErrorIndicationIEValue{})
		opaque := func() s36.ErrorIndicationIEValue {
			sealed := s36.ErrorIndicationIEValue{}
			*s36.BridgeErrorIndicationIEValueFieldIsOpaque(&sealed) = true
			*s36.BridgeErrorIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.ErrorIndicationIEValue {
				sealed := s36.ErrorIndicationIEValue{}
				*s36.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s36.BridgeErrorIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.ErrorIndicationIEValue {
				sealed := s36.ErrorIndicationIEValue{}
				*s36.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s36.BridgeErrorIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.ErrorIndicationIEValue {
				sealed := s36.ErrorIndicationIEValue{}
				*s36.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s36.BridgeErrorIndicationIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.ErrorIndicationIEValue {
				sealed := s36.ErrorIndicationIEValue{}
				*s36.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s36.BridgeErrorIndicationIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.ErrorIndicationIEValue {
				sealed := s36.ErrorIndicationIEValue{}
				*s36.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s36.BridgeErrorIndicationIEValueFieldRowSTMSI(&sealed) = new(s36.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("EventL1LoggedMDTConfigExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.EventL1LoggedMDTConfigExtIEsValue)(nil))
		selectedAssert(&s04.EventL1LoggedMDTConfigExtIEsValue{})
		opaque := func() s04.EventL1LoggedMDTConfigExtIEsValue {
			sealed := s04.EventL1LoggedMDTConfigExtIEsValue{}
			*s04.BridgeEventL1LoggedMDTConfigExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeEventL1LoggedMDTConfigExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("EventTriggerExtIEValue", func(t *testing.T) {
		selectedAssert((*s04.EventTriggerExtIEValue)(nil))
		selectedAssert(&s04.EventTriggerExtIEValue{})
		opaque := func() s04.EventTriggerExtIEValue {
			sealed := s04.EventTriggerExtIEValue{}
			*s04.BridgeEventTriggerExtIEValueFieldIsOpaque(&sealed) = true
			*s04.BridgeEventTriggerExtIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ExpectedUEActivityBehaviourExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ExpectedUEActivityBehaviourExtIEsValue)(nil))
		selectedAssert(&s05.ExpectedUEActivityBehaviourExtIEsValue{})
		opaque := func() s05.ExpectedUEActivityBehaviourExtIEsValue {
			sealed := s05.ExpectedUEActivityBehaviourExtIEsValue{}
			*s05.BridgeExpectedUEActivityBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeExpectedUEActivityBehaviourExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ExpectedUEBehaviourExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ExpectedUEBehaviourExtIEsValue)(nil))
		selectedAssert(&s05.ExpectedUEBehaviourExtIEsValue{})
		opaque := func() s05.ExpectedUEBehaviourExtIEsValue {
			sealed := s05.ExpectedUEBehaviourExtIEsValue{}
			*s05.BridgeExpectedUEBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeExpectedUEBehaviourExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("FiveGSTAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.FiveGSTAIExtIEsValue)(nil))
		selectedAssert(&s05.FiveGSTAIExtIEsValue{})
		opaque := func() s05.FiveGSTAIExtIEsValue {
			sealed := s05.FiveGSTAIExtIEsValue{}
			*s05.BridgeFiveGSTAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeFiveGSTAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ForbiddenLAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ForbiddenLAsItemExtIEsValue)(nil))
		selectedAssert(&s05.ForbiddenLAsItemExtIEsValue{})
		opaque := func() s05.ForbiddenLAsItemExtIEsValue {
			sealed := s05.ForbiddenLAsItemExtIEsValue{}
			*s05.BridgeForbiddenLAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeForbiddenLAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ForbiddenTAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ForbiddenTAsItemExtIEsValue)(nil))
		selectedAssert(&s05.ForbiddenTAsItemExtIEsValue{})
		opaque := func() s05.ForbiddenTAsItemExtIEsValue {
			sealed := s05.ForbiddenTAsItemExtIEsValue{}
			*s05.BridgeForbiddenTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeForbiddenTAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GBRQosInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GBRQosInformationExtIEsValue)(nil))
		selectedAssert(&s05.GBRQosInformationExtIEsValue{})
		opaque := func() s05.GBRQosInformationExtIEsValue {
			sealed := s05.GBRQosInformationExtIEsValue{}
			*s05.BridgeGBRQosInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGBRQosInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(255)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(256)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(257)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s05.GBRQosInformationExtIEsValue {
				sealed := s05.GBRQosInformationExtIEsValue{}
				*s05.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(258)
				*s05.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("GERANCellIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GERANCellIDExtIEsValue)(nil))
		selectedAssert(&s05.GERANCellIDExtIEsValue{})
		opaque := func() s05.GERANCellIDExtIEsValue {
			sealed := s05.GERANCellIDExtIEsValue{}
			*s05.BridgeGERANCellIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGERANCellIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GNBExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GNBExtIEsValue)(nil))
		selectedAssert(&s05.GNBExtIEsValue{})
		opaque := func() s05.GNBExtIEsValue {
			sealed := s05.GNBExtIEsValue{}
			*s05.BridgeGNBExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGNBExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GUMMEIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GUMMEIExtIEsValue)(nil))
		selectedAssert(&s05.GUMMEIExtIEsValue{})
		opaque := func() s05.GUMMEIExtIEsValue {
			sealed := s05.GUMMEIExtIEsValue{}
			*s05.BridgeGUMMEIExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGUMMEIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalENBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GlobalENBIDExtIEsValue)(nil))
		selectedAssert(&s05.GlobalENBIDExtIEsValue{})
		opaque := func() s05.GlobalENBIDExtIEsValue {
			sealed := s05.GlobalENBIDExtIEsValue{}
			*s05.BridgeGlobalENBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGlobalENBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalEnGNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GlobalEnGNBIDExtIEsValue)(nil))
		selectedAssert(&s05.GlobalEnGNBIDExtIEsValue{})
		opaque := func() s05.GlobalEnGNBIDExtIEsValue {
			sealed := s05.GlobalEnGNBIDExtIEsValue{}
			*s05.BridgeGlobalEnGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGlobalEnGNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalGNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.GlobalGNBIDExtIEsValue)(nil))
		selectedAssert(&s05.GlobalGNBIDExtIEsValue{})
		opaque := func() s05.GlobalGNBIDExtIEsValue {
			sealed := s05.GlobalGNBIDExtIEsValue{}
			*s05.BridgeGlobalGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeGlobalGNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("HandoverCancelAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s26.HandoverCancelAcknowledgeIEValue)(nil))
		selectedAssert(&s26.HandoverCancelAcknowledgeIEValue{})
		opaque := func() s26.HandoverCancelAcknowledgeIEValue {
			sealed := s26.HandoverCancelAcknowledgeIEValue{}
			*s26.BridgeHandoverCancelAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeHandoverCancelAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.HandoverCancelAcknowledgeIEValue {
				sealed := s26.HandoverCancelAcknowledgeIEValue{}
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverCancelAcknowledgeIEValue {
				sealed := s26.HandoverCancelAcknowledgeIEValue{}
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverCancelAcknowledgeIEValue {
				sealed := s26.HandoverCancelAcknowledgeIEValue{}
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeHandoverCancelAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverCancelIEValue", func(t *testing.T) {
		selectedAssert((*s21.HandoverCancelIEValue)(nil))
		selectedAssert(&s21.HandoverCancelIEValue{})
		opaque := func() s21.HandoverCancelIEValue {
			sealed := s21.HandoverCancelIEValue{}
			*s21.BridgeHandoverCancelIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeHandoverCancelIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.HandoverCancelIEValue {
				sealed := s21.HandoverCancelIEValue{}
				*s21.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s21.BridgeHandoverCancelIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.HandoverCancelIEValue {
				sealed := s21.HandoverCancelIEValue{}
				*s21.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s21.BridgeHandoverCancelIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.HandoverCancelIEValue {
				sealed := s21.HandoverCancelIEValue{}
				*s21.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s21.BridgeHandoverCancelIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverCommandIEValue", func(t *testing.T) {
		selectedAssert((*s50.HandoverCommandIEValue)(nil))
		selectedAssert(&s50.HandoverCommandIEValue{})
		opaque := func() s50.HandoverCommandIEValue {
			sealed := s50.HandoverCommandIEValue{}
			*s50.BridgeHandoverCommandIEValueFieldIsOpaque(&sealed) = true
			*s50.BridgeHandoverCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s50.BridgeHandoverCommandIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s50.BridgeHandoverCommandIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s50.BridgeHandoverCommandIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(135)
				*s50.BridgeHandoverCommandIEValueFieldRowNASSecurityParametersfromEUTRAN(&sealed) = new(s00.NASSecurityParametersfromEUTRAN)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(12)
				*s50.BridgeHandoverCommandIEValueFieldRowERABSubjecttoDataForwardingList(&sealed) = new(s20.ERABSubjecttoDataForwardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(13)
				*s50.BridgeHandoverCommandIEValueFieldRowERABtoReleaseListHOCmd(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(123)
				*s50.BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainer(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(139)
				*s50.BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainerSecondary(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.HandoverCommandIEValue {
				sealed := s50.HandoverCommandIEValue{}
				*s50.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s50.BridgeHandoverCommandIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverFailureIEValue", func(t *testing.T) {
		selectedAssert((*s26.HandoverFailureIEValue)(nil))
		selectedAssert(&s26.HandoverFailureIEValue{})
		opaque := func() s26.HandoverFailureIEValue {
			sealed := s26.HandoverFailureIEValue{}
			*s26.BridgeHandoverFailureIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeHandoverFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.HandoverFailureIEValue {
				sealed := s26.HandoverFailureIEValue{}
				*s26.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s26.BridgeHandoverFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverFailureIEValue {
				sealed := s26.HandoverFailureIEValue{}
				*s26.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s26.BridgeHandoverFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverFailureIEValue {
				sealed := s26.HandoverFailureIEValue{}
				*s26.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeHandoverFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverNotifyIEValue", func(t *testing.T) {
		selectedAssert((*s44.HandoverNotifyIEValue)(nil))
		selectedAssert(&s44.HandoverNotifyIEValue{})
		opaque := func() s44.HandoverNotifyIEValue {
			sealed := s44.HandoverNotifyIEValue{}
			*s44.BridgeHandoverNotifyIEValueFieldIsOpaque(&sealed) = true
			*s44.BridgeHandoverNotifyIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s44.BridgeHandoverNotifyIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s44.BridgeHandoverNotifyIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s44.BridgeHandoverNotifyIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s44.BridgeHandoverNotifyIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s44.BridgeHandoverNotifyIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s44.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s44.BridgeHandoverNotifyIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s44.BridgeHandoverNotifyIEValueFieldRowPSCellInformation(&sealed) = new(s23.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(320)
				*s44.BridgeHandoverNotifyIEValueFieldRowNotifySourceeNB(&sealed) = new(s00.NotifySourceeNB)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.HandoverNotifyIEValue {
				sealed := s44.HandoverNotifyIEValue{}
				*s44.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s44.BridgeHandoverNotifyIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverPreparationFailureIEValue", func(t *testing.T) {
		selectedAssert((*s26.HandoverPreparationFailureIEValue)(nil))
		selectedAssert(&s26.HandoverPreparationFailureIEValue{})
		opaque := func() s26.HandoverPreparationFailureIEValue {
			sealed := s26.HandoverPreparationFailureIEValue{}
			*s26.BridgeHandoverPreparationFailureIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeHandoverPreparationFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.HandoverPreparationFailureIEValue {
				sealed := s26.HandoverPreparationFailureIEValue{}
				*s26.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s26.BridgeHandoverPreparationFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverPreparationFailureIEValue {
				sealed := s26.HandoverPreparationFailureIEValue{}
				*s26.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s26.BridgeHandoverPreparationFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverPreparationFailureIEValue {
				sealed := s26.HandoverPreparationFailureIEValue{}
				*s26.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s26.BridgeHandoverPreparationFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.HandoverPreparationFailureIEValue {
				sealed := s26.HandoverPreparationFailureIEValue{}
				*s26.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeHandoverPreparationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequestAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s49.HandoverRequestAcknowledgeIEValue)(nil))
		selectedAssert(&s49.HandoverRequestAcknowledgeIEValue{})
		opaque := func() s49.HandoverRequestAcknowledgeIEValue {
			sealed := s49.HandoverRequestAcknowledgeIEValue{}
			*s49.BridgeHandoverRequestAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s49.BridgeHandoverRequestAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(18)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowERABAdmittedList(&sealed) = new(s18.ERABAdmittedList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(19)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowERABFailedToSetupListHOReqAck(&sealed) = new(s19.ERABFailedtoSetupListHOReqAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(123)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowTargetToSourceTransparentContainer(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.HandoverRequestAcknowledgeIEValue {
				sealed := s49.HandoverRequestAcknowledgeIEValue{}
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
				*s49.BridgeHandoverRequestAcknowledgeIEValueFieldRowCEModeBSupportIndicator(&sealed) = new(s00.CEModeBSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequestIEValue", func(t *testing.T) {
		selectedAssert((*s59.HandoverRequestIEValue)(nil))
		selectedAssert(&s59.HandoverRequestIEValue{})
		opaque := func() s59.HandoverRequestIEValue {
			sealed := s59.HandoverRequestIEValue{}
			*s59.BridgeHandoverRequestIEValueFieldIsOpaque(&sealed) = true
			*s59.BridgeHandoverRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s59.BridgeHandoverRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s59.BridgeHandoverRequestIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s59.BridgeHandoverRequestIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s59.BridgeHandoverRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(53)
				*s59.BridgeHandoverRequestIEValueFieldRowERABToBeSetupListHOReq(&sealed) = new(s38.ERABToBeSetupListHOReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
				*s59.BridgeHandoverRequestIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s59.BridgeHandoverRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s47.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s59.BridgeHandoverRequestIEValueFieldRowHandoverRestrictionList(&sealed) = new(s53.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s59.BridgeHandoverRequestIEValueFieldRowTraceActivation(&sealed) = new(s59.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s59.BridgeHandoverRequestIEValueFieldRowRequestType(&sealed) = new(s31.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s59.BridgeHandoverRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s59.BridgeHandoverRequestIEValueFieldRowSecurityContext(&sealed) = new(s36.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(136)
				*s59.BridgeHandoverRequestIEValueFieldRowNASSecurityParameterstoEUTRAN(&sealed) = new(s00.NASSecurityParameterstoEUTRAN)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s59.BridgeHandoverRequestIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s59.BridgeHandoverRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s59.BridgeHandoverRequestIEValueFieldRowGUMMEIID(&sealed) = new(s21.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s59.BridgeHandoverRequestIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
				*s59.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = new(s00.ManagementBasedMDTAllowed)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
				*s59.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s59.BridgeHandoverRequestIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
				*s59.BridgeHandoverRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = new(s21.ExpectedUEBehaviour)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s59.BridgeHandoverRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s23.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s59.BridgeHandoverRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s59.BridgeHandoverRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s57.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s59.BridgeHandoverRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s47.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s59.BridgeHandoverRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s59.BridgeHandoverRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s59.BridgeHandoverRequestIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s59.BridgeHandoverRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s59.BridgeHandoverRequestIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s59.BridgeHandoverRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s59.BridgeHandoverRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s59.BridgeHandoverRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s59.BridgeHandoverRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s23.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s59.BridgeHandoverRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s23.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s59.BridgeHandoverRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s28.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s59.BridgeHandoverRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.HandoverRequestIEValue {
				sealed := s59.HandoverRequestIEValue{}
				*s59.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s59.BridgeHandoverRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequiredIEValue", func(t *testing.T) {
		selectedAssert((*s43.HandoverRequiredIEValue)(nil))
		selectedAssert(&s43.HandoverRequiredIEValue{})
		opaque := func() s43.HandoverRequiredIEValue {
			sealed := s43.HandoverRequiredIEValue{}
			*s43.BridgeHandoverRequiredIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeHandoverRequiredIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s43.BridgeHandoverRequiredIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s43.BridgeHandoverRequiredIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s43.BridgeHandoverRequiredIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s43.BridgeHandoverRequiredIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(4)
				*s43.BridgeHandoverRequiredIEValueFieldRowTargetID(&sealed) = new(s43.TargetID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s43.BridgeHandoverRequiredIEValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(125)
				*s43.BridgeHandoverRequiredIEValueFieldRowSRVCCHOIndication(&sealed) = new(s00.SRVCCHOIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
				*s43.BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(138)
				*s43.BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainerSecondary(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(132)
				*s43.BridgeHandoverRequiredIEValueFieldRowMSClassmark2(&sealed) = new(s00.MSClassmark2)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(133)
				*s43.BridgeHandoverRequiredIEValueFieldRowMSClassmark3(&sealed) = new(s00.MSClassmark3)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s43.BridgeHandoverRequiredIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s43.BridgeHandoverRequiredIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.HandoverRequiredIEValue {
				sealed := s43.HandoverRequiredIEValue{}
				*s43.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(150)
				*s43.BridgeHandoverRequiredIEValueFieldRowPSServiceNotAvailable(&sealed) = new(s00.PSServiceNotAvailable)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRestrictionListExtIEsValue", func(t *testing.T) {
		selectedAssert((*s53.HandoverRestrictionListExtIEsValue)(nil))
		selectedAssert(&s53.HandoverRestrictionListExtIEsValue{})
		opaque := func() s53.HandoverRestrictionListExtIEsValue {
			sealed := s53.HandoverRestrictionListExtIEsValue{}
			*s53.BridgeHandoverRestrictionListExtIEsValueFieldIsOpaque(&sealed) = true
			*s53.BridgeHandoverRestrictionListExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(261)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictioninEPSasSecondaryRAT(&sealed) = new(s00.NRrestrictioninEPSasSecondaryRAT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(270)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowUnlicensedSpectrumRestriction(&sealed) = new(s00.UnlicensedSpectrumRestriction)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(282)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowCNTypeRestrictions(&sealed) = new(s16.CNTypeRestrictions)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(287)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictionin5GS(&sealed) = new(s00.NRrestrictionin5GS)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(290)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowLastNGRANPLMNIdentity(&sealed) = new(s00.PLMNidentity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.HandoverRestrictionListExtIEsValue {
				sealed := s53.HandoverRestrictionListExtIEsValue{}
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(336)
				*s53.BridgeHandoverRestrictionListExtIEsValueFieldRowRATRestrictions(&sealed) = new(s23.RATRestrictions)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverSuccessIEValue", func(t *testing.T) {
		selectedAssert((*s11.HandoverSuccessIEValue)(nil))
		selectedAssert(&s11.HandoverSuccessIEValue{})
		opaque := func() s11.HandoverSuccessIEValue {
			sealed := s11.HandoverSuccessIEValue{}
			*s11.BridgeHandoverSuccessIEValueFieldIsOpaque(&sealed) = true
			*s11.BridgeHandoverSuccessIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s11.HandoverSuccessIEValue {
				sealed := s11.HandoverSuccessIEValue{}
				*s11.BridgeHandoverSuccessIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s11.BridgeHandoverSuccessIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s11.HandoverSuccessIEValue {
				sealed := s11.HandoverSuccessIEValue{}
				*s11.BridgeHandoverSuccessIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s11.BridgeHandoverSuccessIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ImmediateMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s59.ImmediateMDTExtIEsValue)(nil))
		selectedAssert(&s59.ImmediateMDTExtIEsValue{})
		opaque := func() s59.ImmediateMDTExtIEsValue {
			sealed := s59.ImmediateMDTExtIEsValue{}
			*s59.BridgeImmediateMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s59.BridgeImmediateMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(171)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowM3Configuration(&sealed) = new(s22.M3Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(172)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowM4Configuration(&sealed) = new(s22.M4Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(173)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowM5Configuration(&sealed) = new(s22.M5Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(174)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowMDTLocationInfo(&sealed) = new(s00.MDTLocationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(220)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowM6Configuration(&sealed) = new(s22.M6Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(221)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowM7Configuration(&sealed) = new(s22.M7Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(284)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(&sealed) = new(s16.BluetoothMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(285)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowWLANMeasurementConfiguration(&sealed) = new(s59.WLANMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.ImmediateMDTExtIEsValue {
				sealed := s59.ImmediateMDTExtIEsValue{}
				*s59.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(345)
				*s59.BridgeImmediateMDTExtIEsValueFieldRowSensorMeasurementConfiguration(&sealed) = new(s39.SensorMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InformationForCECapableUEsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.InformationForCECapableUEsExtIEsValue)(nil))
		selectedAssert(&s05.InformationForCECapableUEsExtIEsValue{})
		opaque := func() s05.InformationForCECapableUEsExtIEsValue {
			sealed := s05.InformationForCECapableUEsExtIEsValue{}
			*s05.BridgeInformationForCECapableUEsExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeInformationForCECapableUEsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InformationOnRecommendedCellsAndENBsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue)(nil))
		selectedAssert(&s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue{})
		opaque := func() s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue {
			sealed := s05.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue{}
			*s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InitialContextSetupFailureIEValue", func(t *testing.T) {
		selectedAssert((*s26.InitialContextSetupFailureIEValue)(nil))
		selectedAssert(&s26.InitialContextSetupFailureIEValue{})
		opaque := func() s26.InitialContextSetupFailureIEValue {
			sealed := s26.InitialContextSetupFailureIEValue{}
			*s26.BridgeInitialContextSetupFailureIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeInitialContextSetupFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.InitialContextSetupFailureIEValue {
				sealed := s26.InitialContextSetupFailureIEValue{}
				*s26.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s26.BridgeInitialContextSetupFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.InitialContextSetupFailureIEValue {
				sealed := s26.InitialContextSetupFailureIEValue{}
				*s26.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s26.BridgeInitialContextSetupFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.InitialContextSetupFailureIEValue {
				sealed := s26.InitialContextSetupFailureIEValue{}
				*s26.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s26.BridgeInitialContextSetupFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.InitialContextSetupFailureIEValue {
				sealed := s26.InitialContextSetupFailureIEValue{}
				*s26.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeInitialContextSetupFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialContextSetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s60.InitialContextSetupRequestIEValue)(nil))
		selectedAssert(&s60.InitialContextSetupRequestIEValue{})
		opaque := func() s60.InitialContextSetupRequestIEValue {
			sealed := s60.InitialContextSetupRequestIEValue{}
			*s60.BridgeInitialContextSetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s60.BridgeInitialContextSetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(24)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowERABToBeSetupListCtxtSUReq(&sealed) = new(s38.ERABToBeSetupListCtxtSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s47.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowSecurityKey(&sealed) = new(s00.SecurityKey)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowTraceActivation(&sealed) = new(s59.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowHandoverRestrictionList(&sealed) = new(s53.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowCSFallbackIndicator(&sealed) = new(s00.CSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowRegisteredLAI(&sealed) = new(s22.LAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowGUMMEIID(&sealed) = new(s21.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = new(s00.ManagementBasedMDTAllowed)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = new(s00.AdditionalCSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = new(s21.ExpectedUEBehaviour)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s23.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s57.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s47.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s23.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s23.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s28.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.InitialContextSetupRequestIEValue {
				sealed := s60.InitialContextSetupRequestIEValue{}
				*s60.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s60.BridgeInitialContextSetupRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialContextSetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s50.InitialContextSetupResponseIEValue)(nil))
		selectedAssert(&s50.InitialContextSetupResponseIEValue{})
		opaque := func() s50.InitialContextSetupResponseIEValue {
			sealed := s50.InitialContextSetupResponseIEValue{}
			*s50.BridgeInitialContextSetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s50.BridgeInitialContextSetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.InitialContextSetupResponseIEValue {
				sealed := s50.InitialContextSetupResponseIEValue{}
				*s50.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s50.BridgeInitialContextSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.InitialContextSetupResponseIEValue {
				sealed := s50.InitialContextSetupResponseIEValue{}
				*s50.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s50.BridgeInitialContextSetupResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.InitialContextSetupResponseIEValue {
				sealed := s50.InitialContextSetupResponseIEValue{}
				*s50.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(51)
				*s50.BridgeInitialContextSetupResponseIEValueFieldRowERABSetupListCtxtSURes(&sealed) = new(s20.ERABSetupListCtxtSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.InitialContextSetupResponseIEValue {
				sealed := s50.InitialContextSetupResponseIEValue{}
				*s50.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(48)
				*s50.BridgeInitialContextSetupResponseIEValueFieldRowERABFailedToSetupListCtxtSURes(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.InitialContextSetupResponseIEValue {
				sealed := s50.InitialContextSetupResponseIEValue{}
				*s50.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s50.BridgeInitialContextSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialUEMessageIEValue", func(t *testing.T) {
		selectedAssert((*s44.InitialUEMessageIEValue)(nil))
		selectedAssert(&s44.InitialUEMessageIEValue{})
		opaque := func() s44.InitialUEMessageIEValue {
			sealed := s44.InitialUEMessageIEValue{}
			*s44.BridgeInitialUEMessageIEValueFieldIsOpaque(&sealed) = true
			*s44.BridgeInitialUEMessageIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s44.BridgeInitialUEMessageIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s44.BridgeInitialUEMessageIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s44.BridgeInitialUEMessageIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s44.BridgeInitialUEMessageIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(134)
				*s44.BridgeInitialUEMessageIEValueFieldRowRRCEstablishmentCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s44.BridgeInitialUEMessageIEValueFieldRowSTMSI(&sealed) = new(s36.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s44.BridgeInitialUEMessageIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s44.BridgeInitialUEMessageIEValueFieldRowGUMMEIID(&sealed) = new(s21.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s44.BridgeInitialUEMessageIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
				*s44.BridgeInitialUEMessageIEValueFieldRowGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(160)
				*s44.BridgeInitialUEMessageIEValueFieldRowRelayNodeIndicator(&sealed) = new(s00.RelayNodeIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s44.BridgeInitialUEMessageIEValueFieldRowGUMMEIType(&sealed) = new(s00.GUMMEIType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s44.BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s44.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
				*s44.BridgeInitialUEMessageIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s44.BridgeInitialUEMessageIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s44.BridgeInitialUEMessageIEValueFieldRowMMEGroupID(&sealed) = new(s00.MMEGroupID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s44.BridgeInitialUEMessageIEValueFieldRowUEUsageType(&sealed) = new(s00.UEUsageType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
				*s44.BridgeInitialUEMessageIEValueFieldRowCEModeBSupportIndicator(&sealed) = new(s00.CEModeBSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(246)
				*s44.BridgeInitialUEMessageIEValueFieldRowDCNID(&sealed) = new(s00.DCNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(250)
				*s44.BridgeInitialUEMessageIEValueFieldRowCoverageLevel(&sealed) = new(s00.CoverageLevel)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
				*s44.BridgeInitialUEMessageIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = new(s00.UEApplicationLayerMeasurementCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(281)
				*s44.BridgeInitialUEMessageIEValueFieldRowEDTSession(&sealed) = new(s00.EDTSession)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(302)
				*s44.BridgeInitialUEMessageIEValueFieldRowIABNodeIndication(&sealed) = new(s00.IABNodeIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s44.BridgeInitialUEMessageIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.InitialUEMessageIEValue {
				sealed := s44.InitialUEMessageIEValue{}
				*s44.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(353)
				*s44.BridgeInitialUEMessageIEValueFieldRowCoarseUELocationRequested(&sealed) = new(s00.CoarseUELocationRequested)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitiatingValue", func(t *testing.T) {
		selectedAssert((*s65.InitiatingValue)(nil))
		selectedAssert(&s65.InitiatingValue{})
		opaque := func() s65.InitiatingValue {
			sealed := s65.InitiatingValue{}
			*s65.BridgeInitiatingValueFieldIsOpaque(&sealed) = true
			*s65.BridgeInitiatingValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s65.BridgeInitiatingValueFieldBodyHandoverRequired(&sealed) = new(s43.HandoverRequired)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s65.BridgeInitiatingValueFieldBodyHandoverRequest(&sealed) = new(s60.HandoverRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(2)
				*s65.BridgeInitiatingValueFieldBodyHandoverNotify(&sealed) = new(s44.HandoverNotify)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s65.BridgeInitiatingValueFieldBodyPathSwitchRequest(&sealed) = new(s51.PathSwitchRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s65.BridgeInitiatingValueFieldBodyHandoverCancel(&sealed) = new(s29.HandoverCancel)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s65.BridgeInitiatingValueFieldBodyERABSetupRequest(&sealed) = new(s51.ERABSetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s65.BridgeInitiatingValueFieldBodyERABModifyRequest(&sealed) = new(s51.ERABModifyRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s65.BridgeInitiatingValueFieldBodyERABReleaseCommand(&sealed) = new(s49.ERABReleaseCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(8)
				*s65.BridgeInitiatingValueFieldBodyERABReleaseIndication(&sealed) = new(s57.ERABReleaseIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s65.BridgeInitiatingValueFieldBodyInitialContextSetupRequest(&sealed) = new(s60.InitialContextSetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(10)
				*s65.BridgeInitiatingValueFieldBodyPaging(&sealed) = new(s61.Paging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(11)
				*s65.BridgeInitiatingValueFieldBodyDownlinkNASTransport(&sealed) = new(s53.DownlinkNASTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(12)
				*s65.BridgeInitiatingValueFieldBodyInitialUEMessage(&sealed) = new(s45.InitialUEMessage)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(13)
				*s65.BridgeInitiatingValueFieldBodyUplinkNASTransport(&sealed) = new(s55.UplinkNASTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s65.BridgeInitiatingValueFieldBodyReset(&sealed) = new(s45.Reset)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(15)
				*s65.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = new(s36.ErrorIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(16)
				*s65.BridgeInitiatingValueFieldBodyNASNonDeliveryIndication(&sealed) = new(s30.NASNonDeliveryIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s65.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = new(s54.S1SetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(18)
				*s65.BridgeInitiatingValueFieldBodyUEContextReleaseRequest(&sealed) = new(s53.UEContextReleaseRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(19)
				*s65.BridgeInitiatingValueFieldBodyDownlinkS1cdma2000tunnelling(&sealed) = new(s50.DownlinkS1cdma2000tunnelling)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(20)
				*s65.BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(&sealed) = new(s55.UplinkS1cdma2000tunnelling)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s65.BridgeInitiatingValueFieldBodyUEContextModificationRequest(&sealed) = new(s58.UEContextModificationRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(22)
				*s65.BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(&sealed) = new(s45.UECapabilityInfoIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s65.BridgeInitiatingValueFieldBodyUEContextReleaseCommand(&sealed) = new(s47.UEContextReleaseCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(24)
				*s65.BridgeInitiatingValueFieldBodyENBStatusTransfer(&sealed) = new(s28.ENBStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(25)
				*s65.BridgeInitiatingValueFieldBodyMMEStatusTransfer(&sealed) = new(s30.MMEStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(26)
				*s65.BridgeInitiatingValueFieldBodyDeactivateTrace(&sealed) = new(s18.DeactivateTrace)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(27)
				*s65.BridgeInitiatingValueFieldBodyTraceStart(&sealed) = new(s61.TraceStart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(28)
				*s65.BridgeInitiatingValueFieldBodyTraceFailureIndication(&sealed) = new(s44.TraceFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s65.BridgeInitiatingValueFieldBodyENBConfigurationUpdate(&sealed) = new(s54.ENBConfigurationUpdate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s65.BridgeInitiatingValueFieldBodyMMEConfigurationUpdate(&sealed) = new(s54.MMEConfigurationUpdate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(31)
				*s65.BridgeInitiatingValueFieldBodyLocationReportingControl(&sealed) = new(s31.LocationReportingControl)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(32)
				*s65.BridgeInitiatingValueFieldBodyLocationReportingFailureIndication(&sealed) = new(s30.LocationReportingFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(33)
				*s65.BridgeInitiatingValueFieldBodyLocationReport(&sealed) = new(s42.LocationReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(34)
				*s65.BridgeInitiatingValueFieldBodyOverloadStart(&sealed) = new(s52.OverloadStart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(35)
				*s65.BridgeInitiatingValueFieldBodyOverloadStop(&sealed) = new(s52.OverloadStop)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s65.BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(&sealed) = new(s64.WriteReplaceWarningRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(37)
				*s65.BridgeInitiatingValueFieldBodyENBDirectInformationTransfer(&sealed) = new(s43.ENBDirectInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(38)
				*s65.BridgeInitiatingValueFieldBodyMMEDirectInformationTransfer(&sealed) = new(s43.MMEDirectInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(39)
				*s65.BridgeInitiatingValueFieldBodyPrivateMessage(&sealed) = new(s30.PrivateMessage)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(40)
				*s65.BridgeInitiatingValueFieldBodyENBConfigurationTransfer(&sealed) = new(s65.ENBConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(41)
				*s65.BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(&sealed) = new(s65.MMEConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(42)
				*s65.BridgeInitiatingValueFieldBodyCellTrafficTrace(&sealed) = new(s25.CellTrafficTrace)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(43)
				*s65.BridgeInitiatingValueFieldBodyKillRequest(&sealed) = new(s42.KillRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(44)
				*s65.BridgeInitiatingValueFieldBodyDownlinkUEAssociatedLPPaTransport(&sealed) = new(s18.DownlinkUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(45)
				*s65.BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(&sealed) = new(s55.UplinkUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(46)
				*s65.BridgeInitiatingValueFieldBodyDownlinkNonUEAssociatedLPPaTransport(&sealed) = new(s18.DownlinkNonUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(47)
				*s65.BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(&sealed) = new(s55.UplinkNonUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s65.BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(&sealed) = new(s46.UERadioCapabilityMatchRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(49)
				*s65.BridgeInitiatingValueFieldBodyPWSRestartIndication(&sealed) = new(s55.PWSRestartIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(50)
				*s65.BridgeInitiatingValueFieldBodyERABModificationIndication(&sealed) = new(s57.ERABModificationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(51)
				*s65.BridgeInitiatingValueFieldBodyPWSFailureIndication(&sealed) = new(s52.PWSFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(52)
				*s65.BridgeInitiatingValueFieldBodyRerouteNASRequest(&sealed) = new(s31.RerouteNASRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s65.BridgeInitiatingValueFieldBodyUEContextModificationIndication(&sealed) = new(s46.UEContextModificationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(54)
				*s65.BridgeInitiatingValueFieldBodyConnectionEstablishmentIndication(&sealed) = new(s40.ConnectionEstablishmentIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s65.BridgeInitiatingValueFieldBodyUEContextSuspendRequest(&sealed) = new(s57.UEContextSuspendRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s65.BridgeInitiatingValueFieldBodyUEContextResumeRequest(&sealed) = new(s48.UEContextResumeRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(57)
				*s65.BridgeInitiatingValueFieldBodyNASDeliveryIndication(&sealed) = new(s22.NASDeliveryIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(58)
				*s65.BridgeInitiatingValueFieldBodyRetrieveUEInformation(&sealed) = new(s36.RetrieveUEInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(59)
				*s65.BridgeInitiatingValueFieldBodyUEInformationTransfer(&sealed) = new(s46.UEInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(60)
				*s65.BridgeInitiatingValueFieldBodyENBCPRelocationIndication(&sealed) = new(s47.ENBCPRelocationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(61)
				*s65.BridgeInitiatingValueFieldBodyMMECPRelocationIndication(&sealed) = new(s22.MMECPRelocationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(62)
				*s65.BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(&sealed) = new(s57.SecondaryRATDataUsageReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s65.BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(&sealed) = new(s46.UERadioCapabilityIDMappingRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(64)
				*s65.BridgeInitiatingValueFieldBodyHandoverSuccess(&sealed) = new(s21.HandoverSuccess)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(65)
				*s65.BridgeInitiatingValueFieldBodyENBEarlyStatusTransfer(&sealed) = new(s47.ENBEarlyStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(66)
				*s65.BridgeInitiatingValueFieldBodyMMEEarlyStatusTransfer(&sealed) = new(s48.MMEEarlyStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s65.InitiatingValue {
				sealed := s65.InitiatingValue{}
				*s65.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s65.BridgeInitiatingValueFieldBodyS1RemovalRequest(&sealed) = new(s31.S1RemovalRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InterSystemMeasurementItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.InterSystemMeasurementItemExtIEsValue)(nil))
		selectedAssert(&s05.InterSystemMeasurementItemExtIEsValue{})
		opaque := func() s05.InterSystemMeasurementItemExtIEsValue {
			sealed := s05.InterSystemMeasurementItemExtIEsValue{}
			*s05.BridgeInterSystemMeasurementItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeInterSystemMeasurementItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InterSystemMeasurementParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.InterSystemMeasurementParametersExtIEsValue)(nil))
		selectedAssert(&s05.InterSystemMeasurementParametersExtIEsValue{})
		opaque := func() s05.InterSystemMeasurementParametersExtIEsValue {
			sealed := s05.InterSystemMeasurementParametersExtIEsValue{}
			*s05.BridgeInterSystemMeasurementParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeInterSystemMeasurementParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("IntersystemMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.IntersystemMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.IntersystemMeasurementConfigurationExtIEsValue{})
		opaque := func() s05.IntersystemMeasurementConfigurationExtIEsValue {
			sealed := s05.IntersystemMeasurementConfigurationExtIEsValue{}
			*s05.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("KillRequestIEValue", func(t *testing.T) {
		selectedAssert((*s41.KillRequestIEValue)(nil))
		selectedAssert(&s41.KillRequestIEValue{})
		opaque := func() s41.KillRequestIEValue {
			sealed := s41.KillRequestIEValue{}
			*s41.BridgeKillRequestIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeKillRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.KillRequestIEValue {
				sealed := s41.KillRequestIEValue{}
				*s41.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s41.BridgeKillRequestIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillRequestIEValue {
				sealed := s41.KillRequestIEValue{}
				*s41.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s41.BridgeKillRequestIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillRequestIEValue {
				sealed := s41.KillRequestIEValue{}
				*s41.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(113)
				*s41.BridgeKillRequestIEValueFieldRowWarningAreaList(&sealed) = new(s41.WarningAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillRequestIEValue {
				sealed := s41.KillRequestIEValue{}
				*s41.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(191)
				*s41.BridgeKillRequestIEValueFieldRowKillAllWarningMessages(&sealed) = new(s00.KillAllWarningMessages)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("KillResponseIEValue", func(t *testing.T) {
		selectedAssert((*s41.KillResponseIEValue)(nil))
		selectedAssert(&s41.KillResponseIEValue{})
		opaque := func() s41.KillResponseIEValue {
			sealed := s41.KillResponseIEValue{}
			*s41.BridgeKillResponseIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeKillResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.KillResponseIEValue {
				sealed := s41.KillResponseIEValue{}
				*s41.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s41.BridgeKillResponseIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillResponseIEValue {
				sealed := s41.KillResponseIEValue{}
				*s41.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s41.BridgeKillResponseIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillResponseIEValue {
				sealed := s41.KillResponseIEValue{}
				*s41.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(141)
				*s41.BridgeKillResponseIEValueFieldRowBroadcastCancelledAreaList(&sealed) = new(s41.BroadcastCancelledAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.KillResponseIEValue {
				sealed := s41.KillResponseIEValue{}
				*s41.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s41.BridgeKillResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.LAIExtIEsValue)(nil))
		selectedAssert(&s05.LAIExtIEsValue{})
		opaque := func() s05.LAIExtIEsValue {
			sealed := s05.LAIExtIEsValue{}
			*s05.BridgeLAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeLAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LTENTNTAIInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.LTENTNTAIInformationExtIEsValue)(nil))
		selectedAssert(&s05.LTENTNTAIInformationExtIEsValue{})
		opaque := func() s05.LTENTNTAIInformationExtIEsValue {
			sealed := s05.LTENTNTAIInformationExtIEsValue{}
			*s05.BridgeLTENTNTAIInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeLTENTNTAIInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LastVisitedEUTRANCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s52.LastVisitedEUTRANCellInformationExtIEsValue)(nil))
		selectedAssert(&s52.LastVisitedEUTRANCellInformationExtIEsValue{})
		opaque := func() s52.LastVisitedEUTRANCellInformationExtIEsValue {
			sealed := s52.LastVisitedEUTRANCellInformationExtIEsValue{}
			*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s52.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s52.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(167)
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowTimeUEStayedInCellEnhancedGranularity(&sealed) = new(s00.TimeUEStayedInCellEnhancedGranularity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s52.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s52.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(168)
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowHOCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s52.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s52.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(329)
				*s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowLastVisitedPSCellList(&sealed) = new(s23.LastVisitedPSCellList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LastVisitedPSCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.LastVisitedPSCellInformationExtIEsValue)(nil))
		selectedAssert(&s05.LastVisitedPSCellInformationExtIEsValue{})
		opaque := func() s05.LastVisitedPSCellInformationExtIEsValue {
			sealed := s05.LastVisitedPSCellInformationExtIEsValue{}
			*s05.BridgeLastVisitedPSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeLastVisitedPSCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ListeningSubframePatternExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ListeningSubframePatternExtIEsValue)(nil))
		selectedAssert(&s05.ListeningSubframePatternExtIEsValue{})
		opaque := func() s05.ListeningSubframePatternExtIEsValue {
			sealed := s05.ListeningSubframePatternExtIEsValue{}
			*s05.BridgeListeningSubframePatternExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeListeningSubframePatternExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LocationReportIEValue", func(t *testing.T) {
		selectedAssert((*s40.LocationReportIEValue)(nil))
		selectedAssert(&s40.LocationReportIEValue{})
		opaque := func() s40.LocationReportIEValue {
			sealed := s40.LocationReportIEValue{}
			*s40.BridgeLocationReportIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeLocationReportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeLocationReportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeLocationReportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s40.BridgeLocationReportIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s40.BridgeLocationReportIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s40.BridgeLocationReportIEValueFieldRowRequestType(&sealed) = new(s31.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s40.BridgeLocationReportIEValueFieldRowPSCellInformation(&sealed) = new(s23.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.LocationReportIEValue {
				sealed := s40.LocationReportIEValue{}
				*s40.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s40.BridgeLocationReportIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LocationReportingControlIEValue", func(t *testing.T) {
		selectedAssert((*s31.LocationReportingControlIEValue)(nil))
		selectedAssert(&s31.LocationReportingControlIEValue{})
		opaque := func() s31.LocationReportingControlIEValue {
			sealed := s31.LocationReportingControlIEValue{}
			*s31.BridgeLocationReportingControlIEValueFieldIsOpaque(&sealed) = true
			*s31.BridgeLocationReportingControlIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s31.LocationReportingControlIEValue {
				sealed := s31.LocationReportingControlIEValue{}
				*s31.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s31.BridgeLocationReportingControlIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportingControlIEValue {
				sealed := s31.LocationReportingControlIEValue{}
				*s31.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s31.BridgeLocationReportingControlIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportingControlIEValue {
				sealed := s31.LocationReportingControlIEValue{}
				*s31.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s31.BridgeLocationReportingControlIEValueFieldRowRequestType(&sealed) = new(s31.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LocationReportingFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s22.LocationReportingFailureIndicationIEValue)(nil))
		selectedAssert(&s22.LocationReportingFailureIndicationIEValue{})
		opaque := func() s22.LocationReportingFailureIndicationIEValue {
			sealed := s22.LocationReportingFailureIndicationIEValue{}
			*s22.BridgeLocationReportingFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeLocationReportingFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.LocationReportingFailureIndicationIEValue {
				sealed := s22.LocationReportingFailureIndicationIEValue{}
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.LocationReportingFailureIndicationIEValue {
				sealed := s22.LocationReportingFailureIndicationIEValue{}
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.LocationReportingFailureIndicationIEValue {
				sealed := s22.LocationReportingFailureIndicationIEValue{}
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeLocationReportingFailureIndicationIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LoggedMBSFNMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.LoggedMBSFNMDTExtIEsValue)(nil))
		selectedAssert(&s05.LoggedMBSFNMDTExtIEsValue{})
		opaque := func() s05.LoggedMBSFNMDTExtIEsValue {
			sealed := s05.LoggedMBSFNMDTExtIEsValue{}
			*s05.BridgeLoggedMBSFNMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeLoggedMBSFNMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LoggedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s59.LoggedMDTExtIEsValue)(nil))
		selectedAssert(&s59.LoggedMDTExtIEsValue{})
		opaque := func() s59.LoggedMDTExtIEsValue {
			sealed := s59.LoggedMDTExtIEsValue{}
			*s59.BridgeLoggedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s59.BridgeLoggedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s59.LoggedMDTExtIEsValue {
				sealed := s59.LoggedMDTExtIEsValue{}
				*s59.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(284)
				*s59.BridgeLoggedMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(&sealed) = new(s16.BluetoothMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.LoggedMDTExtIEsValue {
				sealed := s59.LoggedMDTExtIEsValue{}
				*s59.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(285)
				*s59.BridgeLoggedMDTExtIEsValueFieldRowWLANMeasurementConfiguration(&sealed) = new(s59.WLANMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.LoggedMDTExtIEsValue {
				sealed := s59.LoggedMDTExtIEsValue{}
				*s59.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(344)
				*s59.BridgeLoggedMDTExtIEsValueFieldRowLoggedMDTTrigger(&sealed) = new(s22.LoggedMDTTrigger)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.LoggedMDTExtIEsValue {
				sealed := s59.LoggedMDTExtIEsValue{}
				*s59.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(345)
				*s59.BridgeLoggedMDTExtIEsValueFieldRowSensorMeasurementConfiguration(&sealed) = new(s39.SensorMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("M1PeriodicReportingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M1PeriodicReportingExtIEsValue)(nil))
		selectedAssert(&s05.M1PeriodicReportingExtIEsValue{})
		opaque := func() s05.M1PeriodicReportingExtIEsValue {
			sealed := s05.M1PeriodicReportingExtIEsValue{}
			*s05.BridgeM1PeriodicReportingExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM1PeriodicReportingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("M1ThresholdEventA2ExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M1ThresholdEventA2ExtIEsValue)(nil))
		selectedAssert(&s05.M1ThresholdEventA2ExtIEsValue{})
		opaque := func() s05.M1ThresholdEventA2ExtIEsValue {
			sealed := s05.M1ThresholdEventA2ExtIEsValue{}
			*s05.BridgeM1ThresholdEventA2ExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM1ThresholdEventA2ExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("M3ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M3ConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.M3ConfigurationExtIEsValue{})
		opaque := func() s05.M3ConfigurationExtIEsValue {
			sealed := s05.M3ConfigurationExtIEsValue{}
			*s05.BridgeM3ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM3ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("M4ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M4ConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.M4ConfigurationExtIEsValue{})
		opaque := func() s05.M4ConfigurationExtIEsValue {
			sealed := s05.M4ConfigurationExtIEsValue{}
			*s05.BridgeM4ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM4ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.M4ConfigurationExtIEsValue {
				sealed := s05.M4ConfigurationExtIEsValue{}
				*s05.BridgeM4ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(346)
				*s05.BridgeM4ConfigurationExtIEsValueFieldRowM4ReportAmount(&sealed) = new(s00.M4ReportAmountMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("M5ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M5ConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.M5ConfigurationExtIEsValue{})
		opaque := func() s05.M5ConfigurationExtIEsValue {
			sealed := s05.M5ConfigurationExtIEsValue{}
			*s05.BridgeM5ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM5ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.M5ConfigurationExtIEsValue {
				sealed := s05.M5ConfigurationExtIEsValue{}
				*s05.BridgeM5ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(347)
				*s05.BridgeM5ConfigurationExtIEsValueFieldRowM5ReportAmount(&sealed) = new(s00.M5ReportAmountMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("M6ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M6ConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.M6ConfigurationExtIEsValue{})
		opaque := func() s05.M6ConfigurationExtIEsValue {
			sealed := s05.M6ConfigurationExtIEsValue{}
			*s05.BridgeM6ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM6ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.M6ConfigurationExtIEsValue {
				sealed := s05.M6ConfigurationExtIEsValue{}
				*s05.BridgeM6ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(348)
				*s05.BridgeM6ConfigurationExtIEsValueFieldRowM6ReportAmount(&sealed) = new(s00.M6ReportAmountMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("M7ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.M7ConfigurationExtIEsValue)(nil))
		selectedAssert(&s05.M7ConfigurationExtIEsValue{})
		opaque := func() s05.M7ConfigurationExtIEsValue {
			sealed := s05.M7ConfigurationExtIEsValue{}
			*s05.BridgeM7ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeM7ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.M7ConfigurationExtIEsValue {
				sealed := s05.M7ConfigurationExtIEsValue{}
				*s05.BridgeM7ConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(349)
				*s05.BridgeM7ConfigurationExtIEsValueFieldRowM7ReportAmount(&sealed) = new(s00.M7ReportAmountMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MBSFNResultToLogInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.MBSFNResultToLogInfoExtIEsValue)(nil))
		selectedAssert(&s05.MBSFNResultToLogInfoExtIEsValue{})
		opaque := func() s05.MBSFNResultToLogInfoExtIEsValue {
			sealed := s05.MBSFNResultToLogInfoExtIEsValue{}
			*s05.BridgeMBSFNResultToLogInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeMBSFNResultToLogInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("MDTConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s52.MDTConfigurationExtIEsValue)(nil))
		selectedAssert(&s52.MDTConfigurationExtIEsValue{})
		opaque := func() s52.MDTConfigurationExtIEsValue {
			sealed := s52.MDTConfigurationExtIEsValue{}
			*s52.BridgeMDTConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s52.BridgeMDTConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s52.MDTConfigurationExtIEsValue {
				sealed := s52.MDTConfigurationExtIEsValue{}
				*s52.BridgeMDTConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(178)
				*s52.BridgeMDTConfigurationExtIEsValueFieldRowSignallingBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MDTModeExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s28.MDTModeExtensionIEIEValue)(nil))
		selectedAssert(&s28.MDTModeExtensionIEIEValue{})
		opaque := func() s28.MDTModeExtensionIEIEValue {
			sealed := s28.MDTModeExtensionIEIEValue{}
			*s28.BridgeMDTModeExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeMDTModeExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.MDTModeExtensionIEIEValue {
				sealed := s28.MDTModeExtensionIEIEValue{}
				*s28.BridgeMDTModeExtensionIEIEValueFieldId(&sealed) = s00.ProtocolIEID(197)
				*s28.BridgeMDTModeExtensionIEIEValueFieldRowLoggedMBSFNMDT(&sealed) = new(s28.LoggedMBSFNMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMECPRelocationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s11.MMECPRelocationIndicationIEValue)(nil))
		selectedAssert(&s11.MMECPRelocationIndicationIEValue{})
		opaque := func() s11.MMECPRelocationIndicationIEValue {
			sealed := s11.MMECPRelocationIndicationIEValue{}
			*s11.BridgeMMECPRelocationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s11.BridgeMMECPRelocationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s11.MMECPRelocationIndicationIEValue {
				sealed := s11.MMECPRelocationIndicationIEValue{}
				*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s11.BridgeMMECPRelocationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s11.MMECPRelocationIndicationIEValue {
				sealed := s11.MMECPRelocationIndicationIEValue{}
				*s11.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s11.BridgeMMECPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s64.MMEConfigurationTransferIEValue)(nil))
		selectedAssert(&s64.MMEConfigurationTransferIEValue{})
		opaque := func() s64.MMEConfigurationTransferIEValue {
			sealed := s64.MMEConfigurationTransferIEValue{}
			*s64.BridgeMMEConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			*s64.BridgeMMEConfigurationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(130)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowSONConfigurationTransferMCT(&sealed) = new(s64.SONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(295)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferMCT(&sealed) = new(s64.ENDCSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.MMEConfigurationTransferIEValue {
				sealed := s64.MMEConfigurationTransferIEValue{}
				*s64.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(309)
				*s64.BridgeMMEConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferMCT(&sealed) = new(s00.IntersystemSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s26.MMEConfigurationUpdateAcknowledgeIEValue)(nil))
		selectedAssert(&s26.MMEConfigurationUpdateAcknowledgeIEValue{})
		opaque := func() s26.MMEConfigurationUpdateAcknowledgeIEValue {
			sealed := s26.MMEConfigurationUpdateAcknowledgeIEValue{}
			*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.MMEConfigurationUpdateAcknowledgeIEValue {
				sealed := s26.MMEConfigurationUpdateAcknowledgeIEValue{}
				*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateFailureIEValue", func(t *testing.T) {
		selectedAssert((*s26.MMEConfigurationUpdateFailureIEValue)(nil))
		selectedAssert(&s26.MMEConfigurationUpdateFailureIEValue{})
		opaque := func() s26.MMEConfigurationUpdateFailureIEValue {
			sealed := s26.MMEConfigurationUpdateFailureIEValue{}
			*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.MMEConfigurationUpdateFailureIEValue {
				sealed := s26.MMEConfigurationUpdateFailureIEValue{}
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.MMEConfigurationUpdateFailureIEValue {
				sealed := s26.MMEConfigurationUpdateFailureIEValue{}
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.MMEConfigurationUpdateFailureIEValue {
				sealed := s26.MMEConfigurationUpdateFailureIEValue{}
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s26.BridgeMMEConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateIEValue", func(t *testing.T) {
		selectedAssert((*s54.MMEConfigurationUpdateIEValue)(nil))
		selectedAssert(&s54.MMEConfigurationUpdateIEValue{})
		opaque := func() s54.MMEConfigurationUpdateIEValue {
			sealed := s54.MMEConfigurationUpdateIEValue{}
			*s54.BridgeMMEConfigurationUpdateIEValueFieldIsOpaque(&sealed) = true
			*s54.BridgeMMEConfigurationUpdateIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s54.MMEConfigurationUpdateIEValue {
				sealed := s54.MMEConfigurationUpdateIEValue{}
				*s54.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s54.BridgeMMEConfigurationUpdateIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.MMEConfigurationUpdateIEValue {
				sealed := s54.MMEConfigurationUpdateIEValue{}
				*s54.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s54.BridgeMMEConfigurationUpdateIEValueFieldRowServedGUMMEIs(&sealed) = new(s39.ServedGUMMEIs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.MMEConfigurationUpdateIEValue {
				sealed := s54.MMEConfigurationUpdateIEValue{}
				*s54.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s54.BridgeMMEConfigurationUpdateIEValueFieldRowRelativeMMECapacity(&sealed) = new(s00.RelativeMMECapacity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.MMEConfigurationUpdateIEValue {
				sealed := s54.MMEConfigurationUpdateIEValue{}
				*s54.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s54.BridgeMMEConfigurationUpdateIEValueFieldRowServedDCNs(&sealed) = new(s39.ServedDCNs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEDirectInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s43.MMEDirectInformationTransferIEValue)(nil))
		selectedAssert(&s43.MMEDirectInformationTransferIEValue{})
		opaque := func() s43.MMEDirectInformationTransferIEValue {
			sealed := s43.MMEDirectInformationTransferIEValue{}
			*s43.BridgeMMEDirectInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeMMEDirectInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.MMEDirectInformationTransferIEValue {
				sealed := s43.MMEDirectInformationTransferIEValue{}
				*s43.BridgeMMEDirectInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(122)
				*s43.BridgeMMEDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeMDT(&sealed) = new(s43.InterSystemInformationTransferType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEEarlyStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s47.MMEEarlyStatusTransferIEValue)(nil))
		selectedAssert(&s47.MMEEarlyStatusTransferIEValue{})
		opaque := func() s47.MMEEarlyStatusTransferIEValue {
			sealed := s47.MMEEarlyStatusTransferIEValue{}
			*s47.BridgeMMEEarlyStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s47.BridgeMMEEarlyStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.MMEEarlyStatusTransferIEValue {
				sealed := s47.MMEEarlyStatusTransferIEValue{}
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.MMEEarlyStatusTransferIEValue {
				sealed := s47.MMEEarlyStatusTransferIEValue{}
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.MMEEarlyStatusTransferIEValue {
				sealed := s47.MMEEarlyStatusTransferIEValue{}
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(321)
				*s47.BridgeMMEEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(&sealed) = new(s47.ENBEarlyStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s25.MMEStatusTransferIEValue)(nil))
		selectedAssert(&s25.MMEStatusTransferIEValue{})
		opaque := func() s25.MMEStatusTransferIEValue {
			sealed := s25.MMEStatusTransferIEValue{}
			*s25.BridgeMMEStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s25.BridgeMMEStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s25.MMEStatusTransferIEValue {
				sealed := s25.MMEStatusTransferIEValue{}
				*s25.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s25.BridgeMMEStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s25.MMEStatusTransferIEValue {
				sealed := s25.MMEStatusTransferIEValue{}
				*s25.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s25.BridgeMMEStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s25.MMEStatusTransferIEValue {
				sealed := s25.MMEStatusTransferIEValue{}
				*s25.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(90)
				*s25.BridgeMMEStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(&sealed) = new(s25.ENBStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MeasurementThresholdL1LoggedMDTExtIEValue", func(t *testing.T) {
		selectedAssert((*s06.MeasurementThresholdL1LoggedMDTExtIEValue)(nil))
		selectedAssert(&s06.MeasurementThresholdL1LoggedMDTExtIEValue{})
		opaque := func() s06.MeasurementThresholdL1LoggedMDTExtIEValue {
			sealed := s06.MeasurementThresholdL1LoggedMDTExtIEValue{}
			*s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldIsOpaque(&sealed) = true
			*s06.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("MutingPatternInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.MutingPatternInformationExtIEsValue)(nil))
		selectedAssert(&s06.MutingPatternInformationExtIEsValue{})
		opaque := func() s06.MutingPatternInformationExtIEsValue {
			sealed := s06.MutingPatternInformationExtIEsValue{}
			*s06.BridgeMutingPatternInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeMutingPatternInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NASDeliveryIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s12.NASDeliveryIndicationIEValue)(nil))
		selectedAssert(&s12.NASDeliveryIndicationIEValue{})
		opaque := func() s12.NASDeliveryIndicationIEValue {
			sealed := s12.NASDeliveryIndicationIEValue{}
			*s12.BridgeNASDeliveryIndicationIEValueFieldIsOpaque(&sealed) = true
			*s12.BridgeNASDeliveryIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s12.NASDeliveryIndicationIEValue {
				sealed := s12.NASDeliveryIndicationIEValue{}
				*s12.BridgeNASDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s12.BridgeNASDeliveryIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.NASDeliveryIndicationIEValue {
				sealed := s12.NASDeliveryIndicationIEValue{}
				*s12.BridgeNASDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s12.BridgeNASDeliveryIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("NASNonDeliveryIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s22.NASNonDeliveryIndicationIEValue)(nil))
		selectedAssert(&s22.NASNonDeliveryIndicationIEValue{})
		opaque := func() s22.NASNonDeliveryIndicationIEValue {
			sealed := s22.NASNonDeliveryIndicationIEValue{}
			*s22.BridgeNASNonDeliveryIndicationIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeNASNonDeliveryIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.NASNonDeliveryIndicationIEValue {
				sealed := s22.NASNonDeliveryIndicationIEValue{}
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.NASNonDeliveryIndicationIEValue {
				sealed := s22.NASNonDeliveryIndicationIEValue{}
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.NASNonDeliveryIndicationIEValue {
				sealed := s22.NASNonDeliveryIndicationIEValue{}
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.NASNonDeliveryIndicationIEValue {
				sealed := s22.NASNonDeliveryIndicationIEValue{}
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeNASNonDeliveryIndicationIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("NBIoTPagingEDRXInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NBIoTPagingEDRXInformationExtIEsValue)(nil))
		selectedAssert(&s06.NBIoTPagingEDRXInformationExtIEsValue{})
		opaque := func() s06.NBIoTPagingEDRXInformationExtIEsValue {
			sealed := s06.NBIoTPagingEDRXInformationExtIEsValue{}
			*s06.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NGENBExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NGENBExtIEsValue)(nil))
		selectedAssert(&s06.NGENBExtIEsValue{})
		opaque := func() s06.NGENBExtIEsValue {
			sealed := s06.NGENBExtIEsValue{}
			*s06.BridgeNGENBExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNGENBExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRCGIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NRCGIExtIEsValue)(nil))
		selectedAssert(&s06.NRCGIExtIEsValue{})
		opaque := func() s06.NRCGIExtIEsValue {
			sealed := s06.NRCGIExtIEsValue{}
			*s06.BridgeNRCGIExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNRCGIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRUESecurityCapabilitiesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NRUESecurityCapabilitiesExtIEsValue)(nil))
		selectedAssert(&s06.NRUESecurityCapabilitiesExtIEsValue{})
		opaque := func() s06.NRUESecurityCapabilitiesExtIEsValue {
			sealed := s06.NRUESecurityCapabilitiesExtIEsValue{}
			*s06.BridgeNRUESecurityCapabilitiesExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNRUESecurityCapabilitiesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRUESidelinkAggregateMaximumBitrateExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue)(nil))
		selectedAssert(&s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue{})
		opaque := func() s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue {
			sealed := s06.NRUESidelinkAggregateMaximumBitrateExtIEsValue{}
			*s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRV2XServicesAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.NRV2XServicesAuthorizedExtIEsValue)(nil))
		selectedAssert(&s06.NRV2XServicesAuthorizedExtIEsValue{})
		opaque := func() s06.NRV2XServicesAuthorizedExtIEsValue {
			sealed := s06.NRV2XServicesAuthorizedExtIEsValue{}
			*s06.BridgeNRV2XServicesAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeNRV2XServicesAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("OverloadStartIEValue", func(t *testing.T) {
		selectedAssert((*s51.OverloadStartIEValue)(nil))
		selectedAssert(&s51.OverloadStartIEValue{})
		opaque := func() s51.OverloadStartIEValue {
			sealed := s51.OverloadStartIEValue{}
			*s51.BridgeOverloadStartIEValueFieldIsOpaque(&sealed) = true
			*s51.BridgeOverloadStartIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.OverloadStartIEValue {
				sealed := s51.OverloadStartIEValue{}
				*s51.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(101)
				*s51.BridgeOverloadStartIEValueFieldRowOverloadResponse(&sealed) = new(s23.OverloadResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.OverloadStartIEValue {
				sealed := s51.OverloadStartIEValue{}
				*s51.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(154)
				*s51.BridgeOverloadStartIEValueFieldRowGUMMEIList(&sealed) = new(s21.GUMMEIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.OverloadStartIEValue {
				sealed := s51.OverloadStartIEValue{}
				*s51.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(161)
				*s51.BridgeOverloadStartIEValueFieldRowTrafficLoadReductionIndication(&sealed) = new(s00.TrafficLoadReductionIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("OverloadStopIEValue", func(t *testing.T) {
		selectedAssert((*s52.OverloadStopIEValue)(nil))
		selectedAssert(&s52.OverloadStopIEValue{})
		opaque := func() s52.OverloadStopIEValue {
			sealed := s52.OverloadStopIEValue{}
			*s52.BridgeOverloadStopIEValueFieldIsOpaque(&sealed) = true
			*s52.BridgeOverloadStopIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s52.OverloadStopIEValue {
				sealed := s52.OverloadStopIEValue{}
				*s52.BridgeOverloadStopIEValueFieldId(&sealed) = s00.ProtocolIEID(154)
				*s52.BridgeOverloadStopIEValueFieldRowGUMMEIList(&sealed) = new(s21.GUMMEIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PC5FlowBitRatesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PC5FlowBitRatesExtIEsValue)(nil))
		selectedAssert(&s06.PC5FlowBitRatesExtIEsValue{})
		opaque := func() s06.PC5FlowBitRatesExtIEsValue {
			sealed := s06.PC5FlowBitRatesExtIEsValue{}
			*s06.BridgePC5FlowBitRatesExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePC5FlowBitRatesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PC5QoSFlowItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PC5QoSFlowItemExtIEsValue)(nil))
		selectedAssert(&s06.PC5QoSFlowItemExtIEsValue{})
		opaque := func() s06.PC5QoSFlowItemExtIEsValue {
			sealed := s06.PC5QoSFlowItemExtIEsValue{}
			*s06.BridgePC5QoSFlowItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePC5QoSFlowItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PC5QoSParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PC5QoSParametersExtIEsValue)(nil))
		selectedAssert(&s06.PC5QoSParametersExtIEsValue{})
		opaque := func() s06.PC5QoSParametersExtIEsValue {
			sealed := s06.PC5QoSParametersExtIEsValue{}
			*s06.BridgePC5QoSParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePC5QoSParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PLMNAreaBasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PLMNAreaBasedQMCExtIEsValue)(nil))
		selectedAssert(&s06.PLMNAreaBasedQMCExtIEsValue{})
		opaque := func() s06.PLMNAreaBasedQMCExtIEsValue {
			sealed := s06.PLMNAreaBasedQMCExtIEsValue{}
			*s06.BridgePLMNAreaBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePLMNAreaBasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PSCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PSCellInformationExtIEsValue)(nil))
		selectedAssert(&s06.PSCellInformationExtIEsValue{})
		opaque := func() s06.PSCellInformationExtIEsValue {
			sealed := s06.PSCellInformationExtIEsValue{}
			*s06.BridgePSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePSCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PWSFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s52.PWSFailureIndicationIEValue)(nil))
		selectedAssert(&s52.PWSFailureIndicationIEValue{})
		opaque := func() s52.PWSFailureIndicationIEValue {
			sealed := s52.PWSFailureIndicationIEValue{}
			*s52.BridgePWSFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s52.BridgePWSFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s52.PWSFailureIndicationIEValue {
				sealed := s52.PWSFailureIndicationIEValue{}
				*s52.BridgePWSFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(222)
				*s52.BridgePWSFailureIndicationIEValueFieldRowPWSfailedECGIList(&sealed) = new(s23.PWSfailedECGIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s52.PWSFailureIndicationIEValue {
				sealed := s52.PWSFailureIndicationIEValue{}
				*s52.BridgePWSFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s52.BridgePWSFailureIndicationIEValueFieldRowGlobalENBID(&sealed) = new(s21.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PWSRestartIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s55.PWSRestartIndicationIEValue)(nil))
		selectedAssert(&s55.PWSRestartIndicationIEValue{})
		opaque := func() s55.PWSRestartIndicationIEValue {
			sealed := s55.PWSRestartIndicationIEValue{}
			*s55.BridgePWSRestartIndicationIEValueFieldIsOpaque(&sealed) = true
			*s55.BridgePWSRestartIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s55.PWSRestartIndicationIEValue {
				sealed := s55.PWSRestartIndicationIEValue{}
				*s55.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(182)
				*s55.BridgePWSRestartIndicationIEValueFieldRowECGIListForRestart(&sealed) = new(s20.ECGIListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s55.PWSRestartIndicationIEValue {
				sealed := s55.PWSRestartIndicationIEValue{}
				*s55.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s55.BridgePWSRestartIndicationIEValueFieldRowGlobalENBID(&sealed) = new(s21.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s55.PWSRestartIndicationIEValue {
				sealed := s55.PWSRestartIndicationIEValue{}
				*s55.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(188)
				*s55.BridgePWSRestartIndicationIEValueFieldRowTAIListForRestart(&sealed) = new(s41.TAIListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s55.PWSRestartIndicationIEValue {
				sealed := s55.PWSRestartIndicationIEValue{}
				*s55.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(190)
				*s55.BridgePWSRestartIndicationIEValueFieldRowEmergencyAreaIDListForRestart(&sealed) = new(s00.EmergencyAreaIDListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PagingAttemptInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PagingAttemptInformationExtIEsValue)(nil))
		selectedAssert(&s06.PagingAttemptInformationExtIEsValue{})
		opaque := func() s06.PagingAttemptInformationExtIEsValue {
			sealed := s06.PagingAttemptInformationExtIEsValue{}
			*s06.BridgePagingAttemptInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePagingAttemptInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PagingEDRXInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.PagingEDRXInformationExtIEsValue)(nil))
		selectedAssert(&s06.PagingEDRXInformationExtIEsValue{})
		opaque := func() s06.PagingEDRXInformationExtIEsValue {
			sealed := s06.PagingEDRXInformationExtIEsValue{}
			*s06.BridgePagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgePagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PagingIEValue", func(t *testing.T) {
		selectedAssert((*s61.PagingIEValue)(nil))
		selectedAssert(&s61.PagingIEValue{})
		opaque := func() s61.PagingIEValue {
			sealed := s61.PagingIEValue{}
			*s61.BridgePagingIEValueFieldIsOpaque(&sealed) = true
			*s61.BridgePagingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(80)
				*s61.BridgePagingIEValueFieldRowUEIdentityIndexValue(&sealed) = new(s00.UEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(43)
				*s61.BridgePagingIEValueFieldRowUEPagingID(&sealed) = new(s36.UEPagingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(44)
				*s61.BridgePagingIEValueFieldRowPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(109)
				*s61.BridgePagingIEValueFieldRowCNDomain(&sealed) = new(s00.CNDomain)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(46)
				*s61.BridgePagingIEValueFieldRowTAIList(&sealed) = new(s42.TAIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s61.BridgePagingIEValueFieldRowCSGIdList(&sealed) = new(s17.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(151)
				*s61.BridgePagingIEValueFieldRowPagingPriority(&sealed) = new(s00.PagingPriority)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(198)
				*s61.BridgePagingIEValueFieldRowUERadioCapabilityForPaging(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(211)
				*s61.BridgePagingIEValueFieldRowAssistanceDataForPaging(&sealed) = new(s31.AssistanceDataForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(227)
				*s61.BridgePagingIEValueFieldRowPagingEDRXInformation(&sealed) = new(s23.PagingEDRXInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(231)
				*s61.BridgePagingIEValueFieldRowExtendedUEIdentityIndexValue(&sealed) = new(s00.ExtendedUEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(239)
				*s61.BridgePagingIEValueFieldRowNBIoTPagingEDRXInformation(&sealed) = new(s23.NBIoTPagingEDRXInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(244)
				*s61.BridgePagingIEValueFieldRowNBIoTUEIdentityIndexValue(&sealed) = new(s00.NBIoTUEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s61.BridgePagingIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s61.BridgePagingIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(304)
				*s61.BridgePagingIEValueFieldRowDataSize(&sealed) = new(s00.DataSize)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(323)
				*s61.BridgePagingIEValueFieldRowWUSAssistanceInformation(&sealed) = new(s61.WUSAssistanceInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(324)
				*s61.BridgePagingIEValueFieldRowNBIoTPagingDRX(&sealed) = new(s00.NBIoTPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s61.PagingIEValue {
				sealed := s61.PagingIEValue{}
				*s61.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(331)
				*s61.BridgePagingIEValueFieldRowPagingCause(&sealed) = new(s00.PagingCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s58.PathSwitchRequestAcknowledgeIEValue)(nil))
		selectedAssert(&s58.PathSwitchRequestAcknowledgeIEValue{})
		opaque := func() s58.PathSwitchRequestAcknowledgeIEValue {
			sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
			*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(95)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(&sealed) = new(s20.ERABToBeSwitchedULList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(&sealed) = new(s19.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(&sealed) = new(s36.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(&sealed) = new(s23.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s57.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s47.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(&sealed) = new(s53.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s23.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s23.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(&sealed) = new(s28.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(&sealed) = new(s47.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(341)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(&sealed) = new(s37.ERABToBeUpdatedList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.PathSwitchRequestAcknowledgeIEValue {
				sealed := s58.PathSwitchRequestAcknowledgeIEValue{}
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s58.BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestFailureIEValue", func(t *testing.T) {
		selectedAssert((*s27.PathSwitchRequestFailureIEValue)(nil))
		selectedAssert(&s27.PathSwitchRequestFailureIEValue{})
		opaque := func() s27.PathSwitchRequestFailureIEValue {
			sealed := s27.PathSwitchRequestFailureIEValue{}
			*s27.BridgePathSwitchRequestFailureIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgePathSwitchRequestFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.PathSwitchRequestFailureIEValue {
				sealed := s27.PathSwitchRequestFailureIEValue{}
				*s27.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgePathSwitchRequestFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.PathSwitchRequestFailureIEValue {
				sealed := s27.PathSwitchRequestFailureIEValue{}
				*s27.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgePathSwitchRequestFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.PathSwitchRequestFailureIEValue {
				sealed := s27.PathSwitchRequestFailureIEValue{}
				*s27.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgePathSwitchRequestFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.PathSwitchRequestFailureIEValue {
				sealed := s27.PathSwitchRequestFailureIEValue{}
				*s27.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgePathSwitchRequestFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestIEValue", func(t *testing.T) {
		selectedAssert((*s51.PathSwitchRequestIEValue)(nil))
		selectedAssert(&s51.PathSwitchRequestIEValue{})
		opaque := func() s51.PathSwitchRequestIEValue {
			sealed := s51.PathSwitchRequestIEValue{}
			*s51.BridgePathSwitchRequestIEValueFieldIsOpaque(&sealed) = true
			*s51.BridgePathSwitchRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s51.BridgePathSwitchRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(22)
				*s51.BridgePathSwitchRequestIEValueFieldRowERABToBeSwitchedDLList(&sealed) = new(s38.ERABToBeSwitchedDLList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(88)
				*s51.BridgePathSwitchRequestIEValueFieldRowSourceMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s51.BridgePathSwitchRequestIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s51.BridgePathSwitchRequestIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s51.BridgePathSwitchRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s47.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s51.BridgePathSwitchRequestIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s51.BridgePathSwitchRequestIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(157)
				*s51.BridgePathSwitchRequestIEValueFieldRowSourceMMEGUMMEI(&sealed) = new(s21.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s51.BridgePathSwitchRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s51.BridgePathSwitchRequestIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s44.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s51.BridgePathSwitchRequestIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(245)
				*s51.BridgePathSwitchRequestIEValueFieldRowRRCResumeCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s51.BridgePathSwitchRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s51.BridgePathSwitchRequestIEValueFieldRowPSCellInformation(&sealed) = new(s23.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.PathSwitchRequestIEValue {
				sealed := s51.PathSwitchRequestIEValue{}
				*s51.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s51.BridgePathSwitchRequestIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PrivateMessageIEsValue", func(t *testing.T) {
		selectedAssert((*s29.PrivateMessageIEsValue)(nil))
		selectedAssert(&s29.PrivateMessageIEsValue{})
		opaque := func() s29.PrivateMessageIEsValue {
			sealed := s29.PrivateMessageIEsValue{}
			*s29.BridgePrivateMessageIEsValueFieldValid(&sealed) = true
			*s29.BridgePrivateMessageIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ProSeAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.ProSeAuthorizedExtIEsValue)(nil))
		selectedAssert(&s06.ProSeAuthorizedExtIEsValue{})
		opaque := func() s06.ProSeAuthorizedExtIEsValue {
			sealed := s06.ProSeAuthorizedExtIEsValue{}
			*s06.BridgeProSeAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeProSeAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.ProSeAuthorizedExtIEsValue {
				sealed := s06.ProSeAuthorizedExtIEsValue{}
				*s06.BridgeProSeAuthorizedExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(216)
				*s06.BridgeProSeAuthorizedExtIEsValueFieldRowProSeUEtoNetworkRelaying(&sealed) = new(s00.ProSeUEtoNetworkRelaying)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RATRestrictionsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RATRestrictionsItemExtIEsValue)(nil))
		selectedAssert(&s06.RATRestrictionsItemExtIEsValue{})
		opaque := func() s06.RATRestrictionsItemExtIEsValue {
			sealed := s06.RATRestrictionsItemExtIEsValue{}
			*s06.BridgeRATRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRATRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RIMTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RIMTransferExtIEsValue)(nil))
		selectedAssert(&s06.RIMTransferExtIEsValue{})
		opaque := func() s06.RIMTransferExtIEsValue {
			sealed := s06.RIMTransferExtIEsValue{}
			*s06.BridgeRIMTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRIMTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RLFReportInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RLFReportInformationExtIEsValue)(nil))
		selectedAssert(&s06.RLFReportInformationExtIEsValue{})
		opaque := func() s06.RLFReportInformationExtIEsValue {
			sealed := s06.RLFReportInformationExtIEsValue{}
			*s06.BridgeRLFReportInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRLFReportInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.RLFReportInformationExtIEsValue {
				sealed := s06.RLFReportInformationExtIEsValue{}
				*s06.BridgeRLFReportInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(313)
				*s06.BridgeRLFReportInformationExtIEsValueFieldRowNBIoTRLFReportContainer(&sealed) = new(s00.NBIoTRLFReportContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedCellItemIEValue", func(t *testing.T) {
		selectedAssert((*s30.RecommendedCellItemIEValue)(nil))
		selectedAssert(&s30.RecommendedCellItemIEValue{})
		opaque := func() s30.RecommendedCellItemIEValue {
			sealed := s30.RecommendedCellItemIEValue{}
			*s30.BridgeRecommendedCellItemIEValueFieldIsOpaque(&sealed) = true
			*s30.BridgeRecommendedCellItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s30.RecommendedCellItemIEValue {
				sealed := s30.RecommendedCellItemIEValue{}
				*s30.BridgeRecommendedCellItemIEValueFieldId(&sealed) = s00.ProtocolIEID(214)
				*s30.BridgeRecommendedCellItemIEValueFieldRowRecommendedCellItem(&sealed) = new(s30.RecommendedCellItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedCellsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RecommendedCellsForPagingExtIEsValue)(nil))
		selectedAssert(&s06.RecommendedCellsForPagingExtIEsValue{})
		opaque := func() s06.RecommendedCellsForPagingExtIEsValue {
			sealed := s06.RecommendedCellsForPagingExtIEsValue{}
			*s06.BridgeRecommendedCellsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRecommendedCellsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedCellsForPagingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RecommendedCellsForPagingItemExtIEsValue)(nil))
		selectedAssert(&s06.RecommendedCellsForPagingItemExtIEsValue{})
		opaque := func() s06.RecommendedCellsForPagingItemExtIEsValue {
			sealed := s06.RecommendedCellsForPagingItemExtIEsValue{}
			*s06.BridgeRecommendedCellsForPagingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRecommendedCellsForPagingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedENBItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RecommendedENBItemExtIEsValue)(nil))
		selectedAssert(&s06.RecommendedENBItemExtIEsValue{})
		opaque := func() s06.RecommendedENBItemExtIEsValue {
			sealed := s06.RecommendedENBItemExtIEsValue{}
			*s06.BridgeRecommendedENBItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRecommendedENBItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedENBItemIEValue", func(t *testing.T) {
		selectedAssert((*s40.RecommendedENBItemIEValue)(nil))
		selectedAssert(&s40.RecommendedENBItemIEValue{})
		opaque := func() s40.RecommendedENBItemIEValue {
			sealed := s40.RecommendedENBItemIEValue{}
			*s40.BridgeRecommendedENBItemIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeRecommendedENBItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.RecommendedENBItemIEValue {
				sealed := s40.RecommendedENBItemIEValue{}
				*s40.BridgeRecommendedENBItemIEValueFieldId(&sealed) = s00.ProtocolIEID(215)
				*s40.BridgeRecommendedENBItemIEValueFieldRowRecommendedENBItem(&sealed) = new(s40.RecommendedENBItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedENBsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RecommendedENBsForPagingExtIEsValue)(nil))
		selectedAssert(&s06.RecommendedENBsForPagingExtIEsValue{})
		opaque := func() s06.RecommendedENBsForPagingExtIEsValue {
			sealed := s06.RecommendedENBsForPagingExtIEsValue{}
			*s06.BridgeRecommendedENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRecommendedENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RequestTypeExtIEsValue", func(t *testing.T) {
		selectedAssert((*s08.RequestTypeExtIEsValue)(nil))
		selectedAssert(&s08.RequestTypeExtIEsValue{})
		opaque := func() s08.RequestTypeExtIEsValue {
			sealed := s08.RequestTypeExtIEsValue{}
			*s08.BridgeRequestTypeExtIEsValueFieldIsOpaque(&sealed) = true
			*s08.BridgeRequestTypeExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.RequestTypeExtIEsValue {
				sealed := s08.RequestTypeExtIEsValue{}
				*s08.BridgeRequestTypeExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(298)
				*s08.BridgeRequestTypeExtIEsValueFieldRowRequestTypeAdditionalInfo(&sealed) = new(s00.RequestTypeAdditionalInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RequestedTNLInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RequestedTNLInfoExtIEsValue)(nil))
		selectedAssert(&s06.RequestedTNLInfoExtIEsValue{})
		opaque := func() s06.RequestedTNLInfoExtIEsValue {
			sealed := s06.RequestedTNLInfoExtIEsValue{}
			*s06.BridgeRequestedTNLInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRequestedTNLInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RerouteNASRequestIEValue", func(t *testing.T) {
		selectedAssert((*s23.RerouteNASRequestIEValue)(nil))
		selectedAssert(&s23.RerouteNASRequestIEValue{})
		opaque := func() s23.RerouteNASRequestIEValue {
			sealed := s23.RerouteNASRequestIEValue{}
			*s23.BridgeRerouteNASRequestIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeRerouteNASRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeRerouteNASRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(225)
				*s23.BridgeRerouteNASRequestIEValueFieldRowS1Message(&sealed) = new([]byte)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s23.BridgeRerouteNASRequestIEValueFieldRowMMEGroupID(&sealed) = new(s00.MMEGroupID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(224)
				*s23.BridgeRerouteNASRequestIEValueFieldRowAdditionalGUTI(&sealed) = new(s21.AdditionalGUTI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.RerouteNASRequestIEValue {
				sealed := s23.RerouteNASRequestIEValue{}
				*s23.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s23.BridgeRerouteNASRequestIEValueFieldRowUEUsageType(&sealed) = new(s00.UEUsageType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ResetAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s55.ResetAcknowledgeIEValue)(nil))
		selectedAssert(&s55.ResetAcknowledgeIEValue{})
		opaque := func() s55.ResetAcknowledgeIEValue {
			sealed := s55.ResetAcknowledgeIEValue{}
			*s55.BridgeResetAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s55.BridgeResetAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s55.ResetAcknowledgeIEValue {
				sealed := s55.ResetAcknowledgeIEValue{}
				*s55.BridgeResetAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(93)
				*s55.BridgeResetAcknowledgeIEValueFieldRowUEAssociatedLogicalS1ConnectionListResAck(&sealed) = new(s45.UEAssociatedLogicalS1ConnectionListResAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s55.ResetAcknowledgeIEValue {
				sealed := s55.ResetAcknowledgeIEValue{}
				*s55.BridgeResetAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s55.BridgeResetAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ResetIEValue", func(t *testing.T) {
		selectedAssert((*s45.ResetIEValue)(nil))
		selectedAssert(&s45.ResetIEValue{})
		opaque := func() s45.ResetIEValue {
			sealed := s45.ResetIEValue{}
			*s45.BridgeResetIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeResetIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.ResetIEValue {
				sealed := s45.ResetIEValue{}
				*s45.BridgeResetIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s45.BridgeResetIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ResetIEValue {
				sealed := s45.ResetIEValue{}
				*s45.BridgeResetIEValueFieldId(&sealed) = s00.ProtocolIEID(92)
				*s45.BridgeResetIEValueFieldRowResetType(&sealed) = new(s45.ResetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RetrieveUEInformationIEValue", func(t *testing.T) {
		selectedAssert((*s36.RetrieveUEInformationIEValue)(nil))
		selectedAssert(&s36.RetrieveUEInformationIEValue{})
		opaque := func() s36.RetrieveUEInformationIEValue {
			sealed := s36.RetrieveUEInformationIEValue{}
			*s36.BridgeRetrieveUEInformationIEValueFieldIsOpaque(&sealed) = true
			*s36.BridgeRetrieveUEInformationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.RetrieveUEInformationIEValue {
				sealed := s36.RetrieveUEInformationIEValue{}
				*s36.BridgeRetrieveUEInformationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s36.BridgeRetrieveUEInformationIEValueFieldRowSTMSI(&sealed) = new(s36.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalFailureIEValue", func(t *testing.T) {
		selectedAssert((*s27.S1RemovalFailureIEValue)(nil))
		selectedAssert(&s27.S1RemovalFailureIEValue{})
		opaque := func() s27.S1RemovalFailureIEValue {
			sealed := s27.S1RemovalFailureIEValue{}
			*s27.BridgeS1RemovalFailureIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeS1RemovalFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.S1RemovalFailureIEValue {
				sealed := s27.S1RemovalFailureIEValue{}
				*s27.BridgeS1RemovalFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgeS1RemovalFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.S1RemovalFailureIEValue {
				sealed := s27.S1RemovalFailureIEValue{}
				*s27.BridgeS1RemovalFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeS1RemovalFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalRequestIEValue", func(t *testing.T) {
		selectedAssert((*s24.S1RemovalRequestIEValue)(nil))
		selectedAssert(&s24.S1RemovalRequestIEValue{})
		opaque := func() s24.S1RemovalRequestIEValue {
			sealed := s24.S1RemovalRequestIEValue{}
			*s24.BridgeS1RemovalRequestIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeS1RemovalRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.S1RemovalRequestIEValue {
				sealed := s24.S1RemovalRequestIEValue{}
				*s24.BridgeS1RemovalRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s24.BridgeS1RemovalRequestIEValueFieldRowGlobalENBID(&sealed) = new(s21.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalResponseIEValue", func(t *testing.T) {
		selectedAssert((*s27.S1RemovalResponseIEValue)(nil))
		selectedAssert(&s27.S1RemovalResponseIEValue{})
		opaque := func() s27.S1RemovalResponseIEValue {
			sealed := s27.S1RemovalResponseIEValue{}
			*s27.BridgeS1RemovalResponseIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeS1RemovalResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.S1RemovalResponseIEValue {
				sealed := s27.S1RemovalResponseIEValue{}
				*s27.BridgeS1RemovalResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s27.BridgeS1RemovalResponseIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.S1RemovalResponseIEValue {
				sealed := s27.S1RemovalResponseIEValue{}
				*s27.BridgeS1RemovalResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeS1RemovalResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupFailureIEValue", func(t *testing.T) {
		selectedAssert((*s27.S1SetupFailureIEValue)(nil))
		selectedAssert(&s27.S1SetupFailureIEValue{})
		opaque := func() s27.S1SetupFailureIEValue {
			sealed := s27.S1SetupFailureIEValue{}
			*s27.BridgeS1SetupFailureIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeS1SetupFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.S1SetupFailureIEValue {
				sealed := s27.S1SetupFailureIEValue{}
				*s27.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgeS1SetupFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.S1SetupFailureIEValue {
				sealed := s27.S1SetupFailureIEValue{}
				*s27.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s27.BridgeS1SetupFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.S1SetupFailureIEValue {
				sealed := s27.S1SetupFailureIEValue{}
				*s27.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeS1SetupFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s54.S1SetupRequestIEValue)(nil))
		selectedAssert(&s54.S1SetupRequestIEValue{})
		opaque := func() s54.S1SetupRequestIEValue {
			sealed := s54.S1SetupRequestIEValue{}
			*s54.BridgeS1SetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s54.BridgeS1SetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s54.BridgeS1SetupRequestIEValueFieldRowGlobalENBID(&sealed) = new(s21.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(60)
				*s54.BridgeS1SetupRequestIEValueFieldRowENBname(&sealed) = new(s00.ENBname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(64)
				*s54.BridgeS1SetupRequestIEValueFieldRowSupportedTAs(&sealed) = new(s40.SupportedTAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(137)
				*s54.BridgeS1SetupRequestIEValueFieldRowDefaultPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s54.BridgeS1SetupRequestIEValueFieldRowCSGIdList(&sealed) = new(s17.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(228)
				*s54.BridgeS1SetupRequestIEValueFieldRowUERetentionInformation(&sealed) = new(s00.UERetentionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(234)
				*s54.BridgeS1SetupRequestIEValueFieldRowNBIoTDefaultPagingDRX(&sealed) = new(s00.NBIoTDefaultPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupRequestIEValue {
				sealed := s54.S1SetupRequestIEValue{}
				*s54.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(291)
				*s54.BridgeS1SetupRequestIEValueFieldRowConnectedengNBList(&sealed) = new(s40.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s54.S1SetupResponseIEValue)(nil))
		selectedAssert(&s54.S1SetupResponseIEValue{})
		opaque := func() s54.S1SetupResponseIEValue {
			sealed := s54.S1SetupResponseIEValue{}
			*s54.BridgeS1SetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s54.BridgeS1SetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s54.BridgeS1SetupResponseIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s54.BridgeS1SetupResponseIEValueFieldRowServedGUMMEIs(&sealed) = new(s39.ServedGUMMEIs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s54.BridgeS1SetupResponseIEValueFieldRowRelativeMMECapacity(&sealed) = new(s00.RelativeMMECapacity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(163)
				*s54.BridgeS1SetupResponseIEValueFieldRowMMERelaySupportIndicator(&sealed) = new(s00.MMERelaySupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s54.BridgeS1SetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(228)
				*s54.BridgeS1SetupResponseIEValueFieldRowUERetentionInformation(&sealed) = new(s00.UERetentionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s54.BridgeS1SetupResponseIEValueFieldRowServedDCNs(&sealed) = new(s39.ServedDCNs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s54.S1SetupResponseIEValue {
				sealed := s54.S1SetupResponseIEValue{}
				*s54.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(303)
				*s54.BridgeS1SetupResponseIEValueFieldRowIABSupported(&sealed) = new(s00.IABSupported)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONConfigurationTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s64.SONConfigurationTransferExtIEsValue)(nil))
		selectedAssert(&s64.SONConfigurationTransferExtIEsValue{})
		opaque := func() s64.SONConfigurationTransferExtIEsValue {
			sealed := s64.SONConfigurationTransferExtIEsValue{}
			*s64.BridgeSONConfigurationTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s64.BridgeSONConfigurationTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s64.SONConfigurationTransferExtIEsValue {
				sealed := s64.SONConfigurationTransferExtIEsValue{}
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(152)
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldRowX2TNLConfigurationInfo(&sealed) = new(s64.X2TNLConfigurationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SONConfigurationTransferExtIEsValue {
				sealed := s64.SONConfigurationTransferExtIEsValue{}
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(209)
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldRowSynchronisationInformation(&sealed) = new(s40.SynchronisationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SONConfigurationTransferExtIEsValue {
				sealed := s64.SONConfigurationTransferExtIEsValue{}
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(356)
				*s64.BridgeSONConfigurationTransferExtIEsValueFieldRowRequestedTNLInfo(&sealed) = new(s31.RequestedTNLInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONInformationExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s24.SONInformationExtensionIEIEValue)(nil))
		selectedAssert(&s24.SONInformationExtensionIEIEValue{})
		opaque := func() s24.SONInformationExtensionIEIEValue {
			sealed := s24.SONInformationExtensionIEIEValue{}
			*s24.BridgeSONInformationExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeSONInformationExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.SONInformationExtensionIEIEValue {
				sealed := s24.SONInformationExtensionIEIEValue{}
				*s24.BridgeSONInformationExtensionIEIEValueFieldId(&sealed) = s00.ProtocolIEID(206)
				*s24.BridgeSONInformationExtensionIEIEValueFieldRowSONInformationReport(&sealed) = new(s24.SONInformationReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONInformationReplyExtIEsValue", func(t *testing.T) {
		selectedAssert((*s44.SONInformationReplyExtIEsValue)(nil))
		selectedAssert(&s44.SONInformationReplyExtIEsValue{})
		opaque := func() s44.SONInformationReplyExtIEsValue {
			sealed := s44.SONInformationReplyExtIEsValue{}
			*s44.BridgeSONInformationReplyExtIEsValueFieldIsOpaque(&sealed) = true
			*s44.BridgeSONInformationReplyExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.SONInformationReplyExtIEsValue {
				sealed := s44.SONInformationReplyExtIEsValue{}
				*s44.BridgeSONInformationReplyExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(149)
				*s44.BridgeSONInformationReplyExtIEsValueFieldRowTimeSynchronisationInfo(&sealed) = new(s44.TimeSynchronisationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.SONInformationReplyExtIEsValue {
				sealed := s44.SONInformationReplyExtIEsValue{}
				*s44.BridgeSONInformationReplyExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(208)
				*s44.BridgeSONInformationReplyExtIEsValueFieldRowMutingPatternInformation(&sealed) = new(s22.MutingPatternInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("STMSIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.STMSIExtIEsValue)(nil))
		selectedAssert(&s06.STMSIExtIEsValue{})
		opaque := func() s06.STMSIExtIEsValue {
			sealed := s06.STMSIExtIEsValue{}
			*s06.BridgeSTMSIExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSTMSIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ScheduledCommunicationTimeExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.ScheduledCommunicationTimeExtIEsValue)(nil))
		selectedAssert(&s06.ScheduledCommunicationTimeExtIEsValue{})
		opaque := func() s06.ScheduledCommunicationTimeExtIEsValue {
			sealed := s06.ScheduledCommunicationTimeExtIEsValue{}
			*s06.BridgeScheduledCommunicationTimeExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeScheduledCommunicationTimeExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecondaryRATDataUsageReportIEValue", func(t *testing.T) {
		selectedAssert((*s56.SecondaryRATDataUsageReportIEValue)(nil))
		selectedAssert(&s56.SecondaryRATDataUsageReportIEValue{})
		opaque := func() s56.SecondaryRATDataUsageReportIEValue {
			sealed := s56.SecondaryRATDataUsageReportIEValue{}
			*s56.BridgeSecondaryRATDataUsageReportIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeSecondaryRATDataUsageReportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(266)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowHandoverFlag(&sealed) = new(s00.HandoverFlag)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.SecondaryRATDataUsageReportIEValue {
				sealed := s56.SecondaryRATDataUsageReportIEValue{}
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeSecondaryRATDataUsageReportIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SecondaryRATDataUsageReportItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SecondaryRATDataUsageReportItemExtIEsValue)(nil))
		selectedAssert(&s06.SecondaryRATDataUsageReportItemExtIEsValue{})
		opaque := func() s06.SecondaryRATDataUsageReportItemExtIEsValue {
			sealed := s06.SecondaryRATDataUsageReportItemExtIEsValue{}
			*s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecondaryRATDataUsageReportItemIEValue", func(t *testing.T) {
		selectedAssert((*s36.SecondaryRATDataUsageReportItemIEValue)(nil))
		selectedAssert(&s36.SecondaryRATDataUsageReportItemIEValue{})
		opaque := func() s36.SecondaryRATDataUsageReportItemIEValue {
			sealed := s36.SecondaryRATDataUsageReportItemIEValue{}
			*s36.BridgeSecondaryRATDataUsageReportItemIEValueFieldIsOpaque(&sealed) = true
			*s36.BridgeSecondaryRATDataUsageReportItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.SecondaryRATDataUsageReportItemIEValue {
				sealed := s36.SecondaryRATDataUsageReportItemIEValue{}
				*s36.BridgeSecondaryRATDataUsageReportItemIEValueFieldId(&sealed) = s00.ProtocolIEID(265)
				*s36.BridgeSecondaryRATDataUsageReportItemIEValueFieldRowSecondaryRATDataUsageReportItem(&sealed) = new(s36.SecondaryRATDataUsageReportItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SecurityContextExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SecurityContextExtIEsValue)(nil))
		selectedAssert(&s06.SecurityContextExtIEsValue{})
		opaque := func() s06.SecurityContextExtIEsValue {
			sealed := s06.SecurityContextExtIEsValue{}
			*s06.BridgeSecurityContextExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSecurityContextExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecurityIndicationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SecurityIndicationExtIEsValue)(nil))
		selectedAssert(&s06.SecurityIndicationExtIEsValue{})
		opaque := func() s06.SecurityIndicationExtIEsValue {
			sealed := s06.SecurityIndicationExtIEsValue{}
			*s06.BridgeSecurityIndicationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSecurityIndicationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecurityResultExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SecurityResultExtIEsValue)(nil))
		selectedAssert(&s06.SecurityResultExtIEsValue{})
		opaque := func() s06.SecurityResultExtIEsValue {
			sealed := s06.SecurityResultExtIEsValue{}
			*s06.BridgeSecurityResultExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSecurityResultExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorMeasConfigNameItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SensorMeasConfigNameItemExtIEsValue)(nil))
		selectedAssert(&s06.SensorMeasConfigNameItemExtIEsValue{})
		opaque := func() s06.SensorMeasConfigNameItemExtIEsValue {
			sealed := s06.SensorMeasConfigNameItemExtIEsValue{}
			*s06.BridgeSensorMeasConfigNameItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSensorMeasConfigNameItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.SensorMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s07.SensorMeasurementConfigurationExtIEsValue{})
		opaque := func() s07.SensorMeasurementConfigurationExtIEsValue {
			sealed := s07.SensorMeasurementConfigurationExtIEsValue{}
			*s07.BridgeSensorMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSensorMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorNameConfigExtIEValue", func(t *testing.T) {
		selectedAssert((*s07.SensorNameConfigExtIEValue)(nil))
		selectedAssert(&s07.SensorNameConfigExtIEValue{})
		opaque := func() s07.SensorNameConfigExtIEValue {
			sealed := s07.SensorNameConfigExtIEValue{}
			*s07.BridgeSensorNameConfigExtIEValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSensorNameConfigExtIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ServedDCNsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.ServedDCNsItemExtIEsValue)(nil))
		selectedAssert(&s07.ServedDCNsItemExtIEsValue{})
		opaque := func() s07.ServedDCNsItemExtIEsValue {
			sealed := s07.ServedDCNsItemExtIEsValue{}
			*s07.BridgeServedDCNsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeServedDCNsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ServedGUMMEIsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.ServedGUMMEIsItemExtIEsValue)(nil))
		selectedAssert(&s07.ServedGUMMEIsItemExtIEsValue{})
		opaque := func() s07.ServedGUMMEIsItemExtIEsValue {
			sealed := s07.ServedGUMMEIsItemExtIEsValue{}
			*s07.BridgeServedGUMMEIsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeServedGUMMEIsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s07.ServedGUMMEIsItemExtIEsValue {
				sealed := s07.ServedGUMMEIsItemExtIEsValue{}
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s07.BridgeServedGUMMEIsItemExtIEsValueFieldRowGUMMEIType(&sealed) = new(s00.GUMMEIType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SourceNgRanNodeIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.SourceNgRanNodeIDExtIEsValue)(nil))
		selectedAssert(&s07.SourceNgRanNodeIDExtIEsValue{})
		opaque := func() s07.SourceNgRanNodeIDExtIEsValue {
			sealed := s07.SourceNgRanNodeIDExtIEsValue{}
			*s07.BridgeSourceNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSourceNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceNodeIDExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s07.SourceNodeIDExtensionIEIEValue)(nil))
		selectedAssert(&s07.SourceNodeIDExtensionIEIEValue{})
		opaque := func() s07.SourceNodeIDExtensionIEIEValue {
			sealed := s07.SourceNodeIDExtensionIEIEValue{}
			*s07.BridgeSourceNodeIDExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSourceNodeIDExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceeNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.SourceeNBIDExtIEsValue)(nil))
		selectedAssert(&s07.SourceeNBIDExtIEsValue{})
		opaque := func() s07.SourceeNBIDExtIEsValue {
			sealed := s07.SourceeNBIDExtIEsValue{}
			*s07.BridgeSourceeNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSourceeNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceeNBToTargeteNBTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{})
		opaque := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
			*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(175)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowMobilityInformation(&sealed) = new(s00.S1APIEsMobilityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(194)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEHistoryInformationFromTheUE(&sealed) = new(s00.UEHistoryInformationFromTheUE)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(296)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIMSvoiceEPSfallbackfrom5G(&sealed) = new(s00.IMSvoiceEPSfallbackfrom5G)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(300)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowContextatSource(&sealed) = new(s23.ContextatSource)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(311)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIntersystemMeasurementConfiguration(&sealed) = new(s28.IntersystemMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(312)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceNodeID(&sealed) = new(s39.SourceNodeID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(326)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowEmergencyIndicator(&sealed) = new(s00.EmergencyIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(337)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEContextReferenceatSourceeNB(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(343)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceSNID(&sealed) = new(s23.GlobalRANNODEID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s43.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(350)
				*s43.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowTimeBasedHandoverInformation(&sealed) = new(s43.TimeBasedHandoverInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SubscriptionBasedUEDifferentiationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue)(nil))
		selectedAssert(&s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue{})
		opaque := func() s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue {
			sealed := s07.SubscriptionBasedUEDifferentiationInfoExtIEsValue{}
			*s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SuccessfulValue", func(t *testing.T) {
		selectedAssert((*s64.SuccessfulValue)(nil))
		selectedAssert(&s64.SuccessfulValue{})
		opaque := func() s64.SuccessfulValue {
			sealed := s64.SuccessfulValue{}
			*s64.BridgeSuccessfulValueFieldIsOpaque(&sealed) = true
			*s64.BridgeSuccessfulValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s64.BridgeSuccessfulValueFieldBodyHandoverCommand(&sealed) = new(s50.HandoverCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s64.BridgeSuccessfulValueFieldBodyHandoverRequestAcknowledge(&sealed) = new(s49.HandoverRequestAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s64.BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(&sealed) = new(s58.PathSwitchRequestAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s64.BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(&sealed) = new(s29.HandoverCancelAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s64.BridgeSuccessfulValueFieldBodyERABSetupResponse(&sealed) = new(s57.ERABSetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s64.BridgeSuccessfulValueFieldBodyERABModifyResponse(&sealed) = new(s57.ERABModifyResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s64.BridgeSuccessfulValueFieldBodyERABReleaseResponse(&sealed) = new(s57.ERABReleaseResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s64.BridgeSuccessfulValueFieldBodyInitialContextSetupResponse(&sealed) = new(s50.InitialContextSetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s64.BridgeSuccessfulValueFieldBodyResetAcknowledge(&sealed) = new(s55.ResetAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s64.BridgeSuccessfulValueFieldBodyS1SetupResponse(&sealed) = new(s54.S1SetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s64.BridgeSuccessfulValueFieldBodyUEContextModificationResponse(&sealed) = new(s46.UEContextModificationResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s64.BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(&sealed) = new(s57.UEContextReleaseComplete)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s64.BridgeSuccessfulValueFieldBodyENBConfigurationUpdateAcknowledge(&sealed) = new(s28.ENBConfigurationUpdateAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s64.BridgeSuccessfulValueFieldBodyMMEConfigurationUpdateAcknowledge(&sealed) = new(s30.MMEConfigurationUpdateAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s64.BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(&sealed) = new(s64.WriteReplaceWarningResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(43)
				*s64.BridgeSuccessfulValueFieldBodyKillResponse(&sealed) = new(s42.KillResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s64.BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(&sealed) = new(s46.UERadioCapabilityMatchResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(50)
				*s64.BridgeSuccessfulValueFieldBodyERABModificationConfirm(&sealed) = new(s49.ERABModificationConfirm)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s64.BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(&sealed) = new(s45.UEContextModificationConfirm)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s64.BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(&sealed) = new(s46.UEContextSuspendResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s64.BridgeSuccessfulValueFieldBodyUEContextResumeResponse(&sealed) = new(s49.UEContextResumeResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s64.BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(&sealed) = new(s46.UERadioCapabilityIDMappingResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s64.SuccessfulValue {
				sealed := s64.SuccessfulValue{}
				*s64.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s64.BridgeSuccessfulValueFieldBodyS1RemovalResponse(&sealed) = new(s31.S1RemovalResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SupportedTAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s08.SupportedTAsItemExtIEsValue)(nil))
		selectedAssert(&s08.SupportedTAsItemExtIEsValue{})
		opaque := func() s08.SupportedTAsItemExtIEsValue {
			sealed := s08.SupportedTAsItemExtIEsValue{}
			*s08.BridgeSupportedTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s08.BridgeSupportedTAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.SupportedTAsItemExtIEsValue {
				sealed := s08.SupportedTAsItemExtIEsValue{}
				*s08.BridgeSupportedTAsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(232)
				*s08.BridgeSupportedTAsItemExtIEsValueFieldRowRATType(&sealed) = new(s00.RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SynchronisationInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.SynchronisationInformationExtIEsValue)(nil))
		selectedAssert(&s07.SynchronisationInformationExtIEsValue{})
		opaque := func() s07.SynchronisationInformationExtIEsValue {
			sealed := s07.SynchronisationInformationExtIEsValue{}
			*s07.BridgeSynchronisationInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeSynchronisationInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TABasedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TABasedMDTExtIEsValue)(nil))
		selectedAssert(&s07.TABasedMDTExtIEsValue{})
		opaque := func() s07.TABasedMDTExtIEsValue {
			sealed := s07.TABasedMDTExtIEsValue{}
			*s07.BridgeTABasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTABasedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TABasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TABasedQMCExtIEsValue)(nil))
		selectedAssert(&s07.TABasedQMCExtIEsValue{})
		opaque := func() s07.TABasedQMCExtIEsValue {
			sealed := s07.TABasedQMCExtIEsValue{}
			*s07.BridgeTABasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTABasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBasedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAIBasedMDTExtIEsValue)(nil))
		selectedAssert(&s07.TAIBasedMDTExtIEsValue{})
		opaque := func() s07.TAIBasedMDTExtIEsValue {
			sealed := s07.TAIBasedMDTExtIEsValue{}
			*s07.BridgeTAIBasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAIBasedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAIBasedQMCExtIEsValue)(nil))
		selectedAssert(&s07.TAIBasedQMCExtIEsValue{})
		opaque := func() s07.TAIBasedQMCExtIEsValue {
			sealed := s07.TAIBasedQMCExtIEsValue{}
			*s07.BridgeTAIBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAIBasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBroadcastItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAIBroadcastItemExtIEsValue)(nil))
		selectedAssert(&s07.TAIBroadcastItemExtIEsValue{})
		opaque := func() s07.TAIBroadcastItemExtIEsValue {
			sealed := s07.TAIBroadcastItemExtIEsValue{}
			*s07.BridgeTAIBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAIBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAICancelledItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAICancelledItemExtIEsValue)(nil))
		selectedAssert(&s07.TAICancelledItemExtIEsValue{})
		opaque := func() s07.TAICancelledItemExtIEsValue {
			sealed := s07.TAICancelledItemExtIEsValue{}
			*s07.BridgeTAICancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAICancelledItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAIExtIEsValue)(nil))
		selectedAssert(&s07.TAIExtIEsValue{})
		opaque := func() s07.TAIExtIEsValue {
			sealed := s07.TAIExtIEsValue{}
			*s07.BridgeTAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TAIItemExtIEsValue)(nil))
		selectedAssert(&s07.TAIItemExtIEsValue{})
		opaque := func() s07.TAIItemExtIEsValue {
			sealed := s07.TAIItemExtIEsValue{}
			*s07.BridgeTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIItemIEValue", func(t *testing.T) {
		selectedAssert((*s42.TAIItemIEValue)(nil))
		selectedAssert(&s42.TAIItemIEValue{})
		opaque := func() s42.TAIItemIEValue {
			sealed := s42.TAIItemIEValue{}
			*s42.BridgeTAIItemIEValueFieldIsOpaque(&sealed) = true
			*s42.BridgeTAIItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.TAIItemIEValue {
				sealed := s42.TAIItemIEValue{}
				*s42.BridgeTAIItemIEValueFieldId(&sealed) = s00.ProtocolIEID(47)
				*s42.BridgeTAIItemIEValueFieldRowTAIItem(&sealed) = new(s42.TAIItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TargetNgRanNodeIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TargetNgRanNodeIDExtIEsValue)(nil))
		selectedAssert(&s07.TargetNgRanNodeIDExtIEsValue{})
		opaque := func() s07.TargetNgRanNodeIDExtIEsValue {
			sealed := s07.TargetNgRanNodeIDExtIEsValue{}
			*s07.BridgeTargetNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTargetNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargetRNCIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TargetRNCIDExtIEsValue)(nil))
		selectedAssert(&s07.TargetRNCIDExtIEsValue{})
		opaque := func() s07.TargetRNCIDExtIEsValue {
			sealed := s07.TargetRNCIDExtIEsValue{}
			*s07.BridgeTargetRNCIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTargetRNCIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargeteNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TargeteNBIDExtIEsValue)(nil))
		selectedAssert(&s07.TargeteNBIDExtIEsValue{})
		opaque := func() s07.TargeteNBIDExtIEsValue {
			sealed := s07.TargeteNBIDExtIEsValue{}
			*s07.BridgeTargeteNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTargeteNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargeteNBToSourceeNBTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{})
		opaque := func() s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			sealed := s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
			*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(318)
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDAPSResponseInfoList(&sealed) = new(s17.DAPSResponseInfoList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(330)
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowRACSIndication(&sealed) = new(s00.RACSIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(335)
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowERABSecurityResultList(&sealed) = new(s38.ERABSecurityResultList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s49.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s49.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TimeBasedHandoverInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TimeBasedHandoverInformationExtIEsValue)(nil))
		selectedAssert(&s07.TimeBasedHandoverInformationExtIEsValue{})
		opaque := func() s07.TimeBasedHandoverInformationExtIEsValue {
			sealed := s07.TimeBasedHandoverInformationExtIEsValue{}
			*s07.BridgeTimeBasedHandoverInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTimeBasedHandoverInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TimeSynchronisationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TimeSynchronisationInfoExtIEsValue)(nil))
		selectedAssert(&s07.TimeSynchronisationInfoExtIEsValue{})
		opaque := func() s07.TimeSynchronisationInfoExtIEsValue {
			sealed := s07.TimeSynchronisationInfoExtIEsValue{}
			*s07.BridgeTimeSynchronisationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTimeSynchronisationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s07.TimeSynchronisationInfoExtIEsValue {
				sealed := s07.TimeSynchronisationInfoExtIEsValue{}
				*s07.BridgeTimeSynchronisationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(207)
				*s07.BridgeTimeSynchronisationInfoExtIEsValueFieldRowMutingAvailabilityIndication(&sealed) = new(s00.MutingAvailabilityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceActivationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s59.TraceActivationExtIEsValue)(nil))
		selectedAssert(&s59.TraceActivationExtIEsValue{})
		opaque := func() s59.TraceActivationExtIEsValue {
			sealed := s59.TraceActivationExtIEsValue{}
			*s59.BridgeTraceActivationExtIEsValueFieldIsOpaque(&sealed) = true
			*s59.BridgeTraceActivationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s59.TraceActivationExtIEsValue {
				sealed := s59.TraceActivationExtIEsValue{}
				*s59.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(162)
				*s59.BridgeTraceActivationExtIEsValueFieldRowMDTConfiguration(&sealed) = new(s59.MDTConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.TraceActivationExtIEsValue {
				sealed := s59.TraceActivationExtIEsValue{}
				*s59.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(262)
				*s59.BridgeTraceActivationExtIEsValueFieldRowUEAppLayerMeasConfig(&sealed) = new(s45.UEAppLayerMeasConfig)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.TraceActivationExtIEsValue {
				sealed := s59.TraceActivationExtIEsValue{}
				*s59.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(316)
				*s59.BridgeTraceActivationExtIEsValueFieldRowMDTConfigurationNR(&sealed) = new(s00.MDTConfigurationNR)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s59.TraceActivationExtIEsValue {
				sealed := s59.TraceActivationExtIEsValue{}
				*s59.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(325)
				*s59.BridgeTraceActivationExtIEsValueFieldRowTraceCollectionEntityURI(&sealed) = new(s00.URIAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s24.TraceFailureIndicationIEValue)(nil))
		selectedAssert(&s24.TraceFailureIndicationIEValue{})
		opaque := func() s24.TraceFailureIndicationIEValue {
			sealed := s24.TraceFailureIndicationIEValue{}
			*s24.BridgeTraceFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeTraceFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.TraceFailureIndicationIEValue {
				sealed := s24.TraceFailureIndicationIEValue{}
				*s24.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s24.BridgeTraceFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.TraceFailureIndicationIEValue {
				sealed := s24.TraceFailureIndicationIEValue{}
				*s24.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s24.BridgeTraceFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.TraceFailureIndicationIEValue {
				sealed := s24.TraceFailureIndicationIEValue{}
				*s24.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s24.BridgeTraceFailureIndicationIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.TraceFailureIndicationIEValue {
				sealed := s24.TraceFailureIndicationIEValue{}
				*s24.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s24.BridgeTraceFailureIndicationIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceStartIEValue", func(t *testing.T) {
		selectedAssert((*s60.TraceStartIEValue)(nil))
		selectedAssert(&s60.TraceStartIEValue{})
		opaque := func() s60.TraceStartIEValue {
			sealed := s60.TraceStartIEValue{}
			*s60.BridgeTraceStartIEValueFieldIsOpaque(&sealed) = true
			*s60.BridgeTraceStartIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s60.TraceStartIEValue {
				sealed := s60.TraceStartIEValue{}
				*s60.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s60.BridgeTraceStartIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.TraceStartIEValue {
				sealed := s60.TraceStartIEValue{}
				*s60.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s60.BridgeTraceStartIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s60.TraceStartIEValue {
				sealed := s60.TraceStartIEValue{}
				*s60.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s60.BridgeTraceStartIEValueFieldRowTraceActivation(&sealed) = new(s59.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TunnelInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.TunnelInformationExtIEsValue)(nil))
		selectedAssert(&s07.TunnelInformationExtIEsValue{})
		opaque := func() s07.TunnelInformationExtIEsValue {
			sealed := s07.TunnelInformationExtIEsValue{}
			*s07.BridgeTunnelInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeTunnelInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UEAggregateMaximumBitratesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UEAggregateMaximumBitratesExtIEsValue)(nil))
		selectedAssert(&s07.UEAggregateMaximumBitratesExtIEsValue{})
		opaque := func() s07.UEAggregateMaximumBitratesExtIEsValue {
			sealed := s07.UEAggregateMaximumBitratesExtIEsValue{}
			*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s07.UEAggregateMaximumBitratesExtIEsValue {
				sealed := s07.UEAggregateMaximumBitratesExtIEsValue{}
				*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(259)
				*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldRowExtendedUEaggregateMaximumBitRateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s07.UEAggregateMaximumBitratesExtIEsValue {
				sealed := s07.UEAggregateMaximumBitratesExtIEsValue{}
				*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(260)
				*s07.BridgeUEAggregateMaximumBitratesExtIEsValueFieldRowExtendedUEaggregateMaximumBitRateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAppLayerMeasConfigExtIEsValue", func(t *testing.T) {
		selectedAssert((*s08.UEAppLayerMeasConfigExtIEsValue)(nil))
		selectedAssert(&s08.UEAppLayerMeasConfigExtIEsValue{})
		opaque := func() s08.UEAppLayerMeasConfigExtIEsValue {
			sealed := s08.UEAppLayerMeasConfigExtIEsValue{}
			*s08.BridgeUEAppLayerMeasConfigExtIEsValueFieldIsOpaque(&sealed) = true
			*s08.BridgeUEAppLayerMeasConfigExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.UEAppLayerMeasConfigExtIEsValue {
				sealed := s08.UEAppLayerMeasConfigExtIEsValue{}
				*s08.BridgeUEAppLayerMeasConfigExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(276)
				*s08.BridgeUEAppLayerMeasConfigExtIEsValueFieldRowServiceType(&sealed) = new(s00.ServiceType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UEAssociatedLogicalS1ConnectionItemExtIEsValue)(nil))
		selectedAssert(&s07.UEAssociatedLogicalS1ConnectionItemExtIEsValue{})
		opaque := func() s07.UEAssociatedLogicalS1ConnectionItemExtIEsValue {
			sealed := s07.UEAssociatedLogicalS1ConnectionItemExtIEsValue{}
			*s07.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemResAckIEValue", func(t *testing.T) {
		selectedAssert((*s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue)(nil))
		selectedAssert(&s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue{})
		opaque := func() s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue {
			sealed := s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue{}
			*s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue {
				sealed := s45.UEAssociatedLogicalS1ConnectionItemResAckIEValue{}
				*s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldId(&sealed) = s00.ProtocolIEID(91)
				*s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(&sealed) = new(s45.UEAssociatedLogicalS1ConnectionItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemResIEValue", func(t *testing.T) {
		selectedAssert((*s45.UEAssociatedLogicalS1ConnectionItemResIEValue)(nil))
		selectedAssert(&s45.UEAssociatedLogicalS1ConnectionItemResIEValue{})
		opaque := func() s45.UEAssociatedLogicalS1ConnectionItemResIEValue {
			sealed := s45.UEAssociatedLogicalS1ConnectionItemResIEValue{}
			*s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.UEAssociatedLogicalS1ConnectionItemResIEValue {
				sealed := s45.UEAssociatedLogicalS1ConnectionItemResIEValue{}
				*s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldId(&sealed) = s00.ProtocolIEID(91)
				*s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(&sealed) = new(s45.UEAssociatedLogicalS1ConnectionItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UECapabilityInfoIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s14.UECapabilityInfoIndicationIEValue)(nil))
		selectedAssert(&s14.UECapabilityInfoIndicationIEValue{})
		opaque := func() s14.UECapabilityInfoIndicationIEValue {
			sealed := s14.UECapabilityInfoIndicationIEValue{}
			*s14.BridgeUECapabilityInfoIndicationIEValueFieldIsOpaque(&sealed) = true
			*s14.BridgeUECapabilityInfoIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(198)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityForPaging(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = new(s00.UEApplicationLayerMeasurementCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(272)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowLTEMIndication(&sealed) = new(s00.LTEMIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(315)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityNRFormat(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UECapabilityInfoIndicationIEValue {
				sealed := s14.UECapabilityInfoIndicationIEValue{}
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(327)
				*s14.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityForPagingNRFormat(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationConfirmIEValue", func(t *testing.T) {
		selectedAssert((*s27.UEContextModificationConfirmIEValue)(nil))
		selectedAssert(&s27.UEContextModificationConfirmIEValue{})
		opaque := func() s27.UEContextModificationConfirmIEValue {
			sealed := s27.UEContextModificationConfirmIEValue{}
			*s27.BridgeUEContextModificationConfirmIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeUEContextModificationConfirmIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.UEContextModificationConfirmIEValue {
				sealed := s27.UEContextModificationConfirmIEValue{}
				*s27.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextModificationConfirmIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationConfirmIEValue {
				sealed := s27.UEContextModificationConfirmIEValue{}
				*s27.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgeUEContextModificationConfirmIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationConfirmIEValue {
				sealed := s27.UEContextModificationConfirmIEValue{}
				*s27.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s27.BridgeUEContextModificationConfirmIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationConfirmIEValue {
				sealed := s27.UEContextModificationConfirmIEValue{}
				*s27.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeUEContextModificationConfirmIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationFailureIEValue", func(t *testing.T) {
		selectedAssert((*s27.UEContextModificationFailureIEValue)(nil))
		selectedAssert(&s27.UEContextModificationFailureIEValue{})
		opaque := func() s27.UEContextModificationFailureIEValue {
			sealed := s27.UEContextModificationFailureIEValue{}
			*s27.BridgeUEContextModificationFailureIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeUEContextModificationFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.UEContextModificationFailureIEValue {
				sealed := s27.UEContextModificationFailureIEValue{}
				*s27.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextModificationFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationFailureIEValue {
				sealed := s27.UEContextModificationFailureIEValue{}
				*s27.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgeUEContextModificationFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationFailureIEValue {
				sealed := s27.UEContextModificationFailureIEValue{}
				*s27.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgeUEContextModificationFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationFailureIEValue {
				sealed := s27.UEContextModificationFailureIEValue{}
				*s27.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeUEContextModificationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s24.UEContextModificationIndicationIEValue)(nil))
		selectedAssert(&s24.UEContextModificationIndicationIEValue{})
		opaque := func() s24.UEContextModificationIndicationIEValue {
			sealed := s24.UEContextModificationIndicationIEValue{}
			*s24.BridgeUEContextModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeUEContextModificationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.UEContextModificationIndicationIEValue {
				sealed := s24.UEContextModificationIndicationIEValue{}
				*s24.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s24.BridgeUEContextModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UEContextModificationIndicationIEValue {
				sealed := s24.UEContextModificationIndicationIEValue{}
				*s24.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s24.BridgeUEContextModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UEContextModificationIndicationIEValue {
				sealed := s24.UEContextModificationIndicationIEValue{}
				*s24.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s24.BridgeUEContextModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = new(s17.CSGMembershipInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationRequestIEValue", func(t *testing.T) {
		selectedAssert((*s58.UEContextModificationRequestIEValue)(nil))
		selectedAssert(&s58.UEContextModificationRequestIEValue{})
		opaque := func() s58.UEContextModificationRequestIEValue {
			sealed := s58.UEContextModificationRequestIEValue{}
			*s58.BridgeUEContextModificationRequestIEValueFieldIsOpaque(&sealed) = true
			*s58.BridgeUEContextModificationRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(&sealed) = new(s00.SecurityKey)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s45.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(&sealed) = new(s00.CSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s47.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(&sealed) = new(s22.LAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = new(s00.AdditionalCSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s23.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(243)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(&sealed) = new(s00.SRVCCOperationNotPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s57.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s47.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s23.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s23.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s23.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s28.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s58.UEContextModificationRequestIEValue {
				sealed := s58.UEContextModificationRequestIEValue{}
				*s58.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s58.BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationResponseIEValue", func(t *testing.T) {
		selectedAssert((*s27.UEContextModificationResponseIEValue)(nil))
		selectedAssert(&s27.UEContextModificationResponseIEValue{})
		opaque := func() s27.UEContextModificationResponseIEValue {
			sealed := s27.UEContextModificationResponseIEValue{}
			*s27.BridgeUEContextModificationResponseIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeUEContextModificationResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.UEContextModificationResponseIEValue {
				sealed := s27.UEContextModificationResponseIEValue{}
				*s27.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextModificationResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationResponseIEValue {
				sealed := s27.UEContextModificationResponseIEValue{}
				*s27.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgeUEContextModificationResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextModificationResponseIEValue {
				sealed := s27.UEContextModificationResponseIEValue{}
				*s27.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeUEContextModificationResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseCommandIEValue", func(t *testing.T) {
		selectedAssert((*s46.UEContextReleaseCommandIEValue)(nil))
		selectedAssert(&s46.UEContextReleaseCommandIEValue{})
		opaque := func() s46.UEContextReleaseCommandIEValue {
			sealed := s46.UEContextReleaseCommandIEValue{}
			*s46.BridgeUEContextReleaseCommandIEValueFieldIsOpaque(&sealed) = true
			*s46.BridgeUEContextReleaseCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s46.UEContextReleaseCommandIEValue {
				sealed := s46.UEContextReleaseCommandIEValue{}
				*s46.BridgeUEContextReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(99)
				*s46.BridgeUEContextReleaseCommandIEValueFieldRowUES1APIDs(&sealed) = new(s46.UES1APIDs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextReleaseCommandIEValue {
				sealed := s46.UEContextReleaseCommandIEValue{}
				*s46.BridgeUEContextReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s46.BridgeUEContextReleaseCommandIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseCompleteIEValue", func(t *testing.T) {
		selectedAssert((*s56.UEContextReleaseCompleteIEValue)(nil))
		selectedAssert(&s56.UEContextReleaseCompleteIEValue{})
		opaque := func() s56.UEContextReleaseCompleteIEValue {
			sealed := s56.UEContextReleaseCompleteIEValue{}
			*s56.BridgeUEContextReleaseCompleteIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeUEContextReleaseCompleteIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = new(s42.InformationOnRecommendedCellsAndENBsForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = new(s20.CellIdentifierAndCELevelForCECapableUEs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextReleaseCompleteIEValue {
				sealed := s56.UEContextReleaseCompleteIEValue{}
				*s56.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeUEContextReleaseCompleteIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseRequestIEValue", func(t *testing.T) {
		selectedAssert((*s53.UEContextReleaseRequestIEValue)(nil))
		selectedAssert(&s53.UEContextReleaseRequestIEValue{})
		opaque := func() s53.UEContextReleaseRequestIEValue {
			sealed := s53.UEContextReleaseRequestIEValue{}
			*s53.BridgeUEContextReleaseRequestIEValueFieldIsOpaque(&sealed) = true
			*s53.BridgeUEContextReleaseRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s53.UEContextReleaseRequestIEValue {
				sealed := s53.UEContextReleaseRequestIEValue{}
				*s53.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s53.BridgeUEContextReleaseRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.UEContextReleaseRequestIEValue {
				sealed := s53.UEContextReleaseRequestIEValue{}
				*s53.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s53.BridgeUEContextReleaseRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.UEContextReleaseRequestIEValue {
				sealed := s53.UEContextReleaseRequestIEValue{}
				*s53.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s53.BridgeUEContextReleaseRequestIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.UEContextReleaseRequestIEValue {
				sealed := s53.UEContextReleaseRequestIEValue{}
				*s53.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(164)
				*s53.BridgeUEContextReleaseRequestIEValueFieldRowGWContextReleaseIndication(&sealed) = new(s00.GWContextReleaseIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s53.UEContextReleaseRequestIEValue {
				sealed := s53.UEContextReleaseRequestIEValue{}
				*s53.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s53.BridgeUEContextReleaseRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeFailureIEValue", func(t *testing.T) {
		selectedAssert((*s27.UEContextResumeFailureIEValue)(nil))
		selectedAssert(&s27.UEContextResumeFailureIEValue{})
		opaque := func() s27.UEContextResumeFailureIEValue {
			sealed := s27.UEContextResumeFailureIEValue{}
			*s27.BridgeUEContextResumeFailureIEValueFieldIsOpaque(&sealed) = true
			*s27.BridgeUEContextResumeFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowCause(&sealed) = new(s17.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeRequestIEValue", func(t *testing.T) {
		selectedAssert((*s48.UEContextResumeRequestIEValue)(nil))
		selectedAssert(&s48.UEContextResumeRequestIEValue{})
		opaque := func() s48.UEContextResumeRequestIEValue {
			sealed := s48.UEContextResumeRequestIEValue{}
			*s48.BridgeUEContextResumeRequestIEValueFieldIsOpaque(&sealed) = true
			*s48.BridgeUEContextResumeRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.UEContextResumeRequestIEValue {
				sealed := s48.UEContextResumeRequestIEValue{}
				*s48.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeUEContextResumeRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeRequestIEValue {
				sealed := s48.UEContextResumeRequestIEValue{}
				*s48.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s48.BridgeUEContextResumeRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeRequestIEValue {
				sealed := s48.UEContextResumeRequestIEValue{}
				*s48.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(235)
				*s48.BridgeUEContextResumeRequestIEValueFieldRowERABFailedToResumeListResumeReq(&sealed) = new(s18.ERABFailedToResumeListResumeReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeRequestIEValue {
				sealed := s48.UEContextResumeRequestIEValue{}
				*s48.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(245)
				*s48.BridgeUEContextResumeRequestIEValueFieldRowRRCResumeCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeResponseIEValue", func(t *testing.T) {
		selectedAssert((*s48.UEContextResumeResponseIEValue)(nil))
		selectedAssert(&s48.UEContextResumeResponseIEValue{})
		opaque := func() s48.UEContextResumeResponseIEValue {
			sealed := s48.UEContextResumeResponseIEValue{}
			*s48.BridgeUEContextResumeResponseIEValueFieldIsOpaque(&sealed) = true
			*s48.BridgeUEContextResumeResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(237)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowERABFailedToResumeListResumeRes(&sealed) = new(s18.ERABFailedToResumeListResumeRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowSecurityContext(&sealed) = new(s36.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.UEContextResumeResponseIEValue {
				sealed := s48.UEContextResumeResponseIEValue{}
				*s48.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s48.BridgeUEContextResumeResponseIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextSuspendRequestIEValue", func(t *testing.T) {
		selectedAssert((*s56.UEContextSuspendRequestIEValue)(nil))
		selectedAssert(&s56.UEContextSuspendRequestIEValue{})
		opaque := func() s56.UEContextSuspendRequestIEValue {
			sealed := s56.UEContextSuspendRequestIEValue{}
			*s56.BridgeUEContextSuspendRequestIEValueFieldIsOpaque(&sealed) = true
			*s56.BridgeUEContextSuspendRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = new(s42.InformationOnRecommendedCellsAndENBsForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = new(s20.CellIdentifierAndCELevelForCECapableUEs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s36.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowUserLocationInformation(&sealed) = new(s55.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s56.UEContextSuspendRequestIEValue {
				sealed := s56.UEContextSuspendRequestIEValue{}
				*s56.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s56.BridgeUEContextSuspendRequestIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextSuspendResponseIEValue", func(t *testing.T) {
		selectedAssert((*s36.UEContextSuspendResponseIEValue)(nil))
		selectedAssert(&s36.UEContextSuspendResponseIEValue{})
		opaque := func() s36.UEContextSuspendResponseIEValue {
			sealed := s36.UEContextSuspendResponseIEValue{}
			*s36.BridgeUEContextSuspendResponseIEValueFieldIsOpaque(&sealed) = true
			*s36.BridgeUEContextSuspendResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UEContextSuspendResponseIEValue {
				sealed := s36.UEContextSuspendResponseIEValue{}
				*s36.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s36.BridgeUEContextSuspendResponseIEValueFieldRowSecurityContext(&sealed) = new(s36.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s39.UEInformationTransferIEValue)(nil))
		selectedAssert(&s39.UEInformationTransferIEValue{})
		opaque := func() s39.UEInformationTransferIEValue {
			sealed := s39.UEInformationTransferIEValue{}
			*s39.BridgeUEInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeUEInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s39.BridgeUEInformationTransferIEValueFieldRowSTMSI(&sealed) = new(s36.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
				*s39.BridgeUEInformationTransferIEValueFieldRowUELevelQoSParameters(&sealed) = new(s21.ERABLevelQoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s39.BridgeUEInformationTransferIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s39.BridgeUEInformationTransferIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s39.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s39.BridgeUEInformationTransferIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.UEInformationTransferIEValue {
				sealed := s39.UEInformationTransferIEValue{}
				*s39.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s39.BridgeUEInformationTransferIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityIDMappingRequestIEValue", func(t *testing.T) {
		selectedAssert((*s08.UERadioCapabilityIDMappingRequestIEValue)(nil))
		selectedAssert(&s08.UERadioCapabilityIDMappingRequestIEValue{})
		opaque := func() s08.UERadioCapabilityIDMappingRequestIEValue {
			sealed := s08.UERadioCapabilityIDMappingRequestIEValue{}
			*s08.BridgeUERadioCapabilityIDMappingRequestIEValueFieldIsOpaque(&sealed) = true
			*s08.BridgeUERadioCapabilityIDMappingRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.UERadioCapabilityIDMappingRequestIEValue {
				sealed := s08.UERadioCapabilityIDMappingRequestIEValue{}
				*s08.BridgeUERadioCapabilityIDMappingRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s08.BridgeUERadioCapabilityIDMappingRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityIDMappingResponseIEValue", func(t *testing.T) {
		selectedAssert((*s28.UERadioCapabilityIDMappingResponseIEValue)(nil))
		selectedAssert(&s28.UERadioCapabilityIDMappingResponseIEValue{})
		opaque := func() s28.UERadioCapabilityIDMappingResponseIEValue {
			sealed := s28.UERadioCapabilityIDMappingResponseIEValue{}
			*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s28.UERadioCapabilityIDMappingResponseIEValue{}
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s28.UERadioCapabilityIDMappingResponseIEValue{}
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s28.UERadioCapabilityIDMappingResponseIEValue{}
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s28.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityMatchRequestIEValue", func(t *testing.T) {
		selectedAssert((*s14.UERadioCapabilityMatchRequestIEValue)(nil))
		selectedAssert(&s14.UERadioCapabilityMatchRequestIEValue{})
		opaque := func() s14.UERadioCapabilityMatchRequestIEValue {
			sealed := s14.UERadioCapabilityMatchRequestIEValue{}
			*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldIsOpaque(&sealed) = true
			*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.UERadioCapabilityMatchRequestIEValue {
				sealed := s14.UERadioCapabilityMatchRequestIEValue{}
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UERadioCapabilityMatchRequestIEValue {
				sealed := s14.UERadioCapabilityMatchRequestIEValue{}
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UERadioCapabilityMatchRequestIEValue {
				sealed := s14.UERadioCapabilityMatchRequestIEValue{}
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UERadioCapabilityMatchRequestIEValue {
				sealed := s14.UERadioCapabilityMatchRequestIEValue{}
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s14.BridgeUERadioCapabilityMatchRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityMatchResponseIEValue", func(t *testing.T) {
		selectedAssert((*s28.UERadioCapabilityMatchResponseIEValue)(nil))
		selectedAssert(&s28.UERadioCapabilityMatchResponseIEValue{})
		opaque := func() s28.UERadioCapabilityMatchResponseIEValue {
			sealed := s28.UERadioCapabilityMatchResponseIEValue{}
			*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.UERadioCapabilityMatchResponseIEValue {
				sealed := s28.UERadioCapabilityMatchResponseIEValue{}
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UERadioCapabilityMatchResponseIEValue {
				sealed := s28.UERadioCapabilityMatchResponseIEValue{}
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UERadioCapabilityMatchResponseIEValue {
				sealed := s28.UERadioCapabilityMatchResponseIEValue{}
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(169)
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldRowVoiceSupportMatchIndicator(&sealed) = new(s00.VoiceSupportMatchIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UERadioCapabilityMatchResponseIEValue {
				sealed := s28.UERadioCapabilityMatchResponseIEValue{}
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s28.BridgeUERadioCapabilityMatchResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UES1APIDPairExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UES1APIDPairExtIEsValue)(nil))
		selectedAssert(&s07.UES1APIDPairExtIEsValue{})
		opaque := func() s07.UES1APIDPairExtIEsValue {
			sealed := s07.UES1APIDPairExtIEsValue{}
			*s07.BridgeUES1APIDPairExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUES1APIDPairExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UESecurityCapabilitiesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UESecurityCapabilitiesExtIEsValue)(nil))
		selectedAssert(&s07.UESecurityCapabilitiesExtIEsValue{})
		opaque := func() s07.UESecurityCapabilitiesExtIEsValue {
			sealed := s07.UESecurityCapabilitiesExtIEsValue{}
			*s07.BridgeUESecurityCapabilitiesExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUESecurityCapabilitiesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UESidelinkAggregateMaximumBitratesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UESidelinkAggregateMaximumBitratesExtIEsValue)(nil))
		selectedAssert(&s07.UESidelinkAggregateMaximumBitratesExtIEsValue{})
		opaque := func() s07.UESidelinkAggregateMaximumBitratesExtIEsValue {
			sealed := s07.UESidelinkAggregateMaximumBitratesExtIEsValue{}
			*s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ULCPSecurityInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.ULCPSecurityInformationExtIEsValue)(nil))
		selectedAssert(&s07.ULCPSecurityInformationExtIEsValue{})
		opaque := func() s07.ULCPSecurityInformationExtIEsValue {
			sealed := s07.ULCPSecurityInformationExtIEsValue{}
			*s07.BridgeULCPSecurityInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeULCPSecurityInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UnsuccessfulValue", func(t *testing.T) {
		selectedAssert((*s46.UnsuccessfulValue)(nil))
		selectedAssert(&s46.UnsuccessfulValue{})
		opaque := func() s46.UnsuccessfulValue {
			sealed := s46.UnsuccessfulValue{}
			*s46.BridgeUnsuccessfulValueFieldIsOpaque(&sealed) = true
			*s46.BridgeUnsuccessfulValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s46.BridgeUnsuccessfulValueFieldBodyHandoverPreparationFailure(&sealed) = new(s29.HandoverPreparationFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s46.BridgeUnsuccessfulValueFieldBodyHandoverFailure(&sealed) = new(s29.HandoverFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s46.BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(&sealed) = new(s30.PathSwitchRequestFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s46.BridgeUnsuccessfulValueFieldBodyInitialContextSetupFailure(&sealed) = new(s30.InitialContextSetupFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s46.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = new(s31.S1SetupFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s46.BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(&sealed) = new(s45.UEContextModificationFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s46.BridgeUnsuccessfulValueFieldBodyENBConfigurationUpdateFailure(&sealed) = new(s28.ENBConfigurationUpdateFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s46.BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(&sealed) = new(s30.MMEConfigurationUpdateFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s46.BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(&sealed) = new(s46.UEContextResumeFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UnsuccessfulValue {
				sealed := s46.UnsuccessfulValue{}
				*s46.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s46.BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(&sealed) = new(s31.S1RemovalFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkNASTransportIEValue", func(t *testing.T) {
		selectedAssert((*s41.UplinkNASTransportIEValue)(nil))
		selectedAssert(&s41.UplinkNASTransportIEValue{})
		opaque := func() s41.UplinkNASTransportIEValue {
			sealed := s41.UplinkNASTransportIEValue{}
			*s41.BridgeUplinkNASTransportIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeUplinkNASTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s41.BridgeUplinkNASTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s41.BridgeUplinkNASTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s41.BridgeUplinkNASTransportIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s41.BridgeUplinkNASTransportIEValueFieldRowEUTRANCGI(&sealed) = new(s20.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s41.BridgeUplinkNASTransportIEValueFieldRowTAI(&sealed) = new(s40.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
				*s41.BridgeUplinkNASTransportIEValueFieldRowGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
				*s41.BridgeUplinkNASTransportIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s41.BridgeUplinkNASTransportIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s41.BridgeUplinkNASTransportIEValueFieldRowPSCellInformation(&sealed) = new(s23.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.UplinkNASTransportIEValue {
				sealed := s41.UplinkNASTransportIEValue{}
				*s41.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s41.BridgeUplinkNASTransportIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkNonUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s14.UplinkNonUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s14.UplinkNonUEAssociatedLPPaTransportIEValue{})
		opaque := func() s14.UplinkNonUEAssociatedLPPaTransportIEValue {
			sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValue{}
			*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.UplinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UplinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkNonUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s14.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkS1cdma2000tunnellingIEValue", func(t *testing.T) {
		selectedAssert((*s24.UplinkS1cdma2000tunnellingIEValue)(nil))
		selectedAssert(&s24.UplinkS1cdma2000tunnellingIEValue{})
		opaque := func() s24.UplinkS1cdma2000tunnellingIEValue {
			sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
			*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = new(s00.Cdma2000RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(72)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(&sealed) = new(s00.Cdma2000SectorID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(84)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(&sealed) = new(s00.Cdma2000HORequiredIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(102)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(&sealed) = new(s17.Cdma2000OneXSRVCCInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(97)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(&sealed) = new(s00.Cdma2000OneXRAND)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = new(s00.Cdma2000PDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(140)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(&sealed) = new(s00.EUTRANRoundTripDelayEstimationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s14.UplinkUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s14.UplinkUEAssociatedLPPaTransportIEValue{})
		opaque := func() s14.UplinkUEAssociatedLPPaTransportIEValue {
			sealed := s14.UplinkUEAssociatedLPPaTransportIEValue{}
			*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s14.UplinkUEAssociatedLPPaTransportIEValue{}
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s14.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UserLocationInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s25.UserLocationInformationExtIEsValue)(nil))
		selectedAssert(&s25.UserLocationInformationExtIEsValue{})
		opaque := func() s25.UserLocationInformationExtIEsValue {
			sealed := s25.UserLocationInformationExtIEsValue{}
			*s25.BridgeUserLocationInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s25.BridgeUserLocationInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s25.UserLocationInformationExtIEsValue {
				sealed := s25.UserLocationInformationExtIEsValue{}
				*s25.BridgeUserLocationInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s25.BridgeUserLocationInformationExtIEsValueFieldRowPSCellInformation(&sealed) = new(s23.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s25.UserLocationInformationExtIEsValue {
				sealed := s25.UserLocationInformationExtIEsValue{}
				*s25.BridgeUserLocationInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s25.BridgeUserLocationInformationExtIEsValueFieldRowLTENTNTAIInformation(&sealed) = new(s22.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("V2XServicesAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.V2XServicesAuthorizedExtIEsValue)(nil))
		selectedAssert(&s07.V2XServicesAuthorizedExtIEsValue{})
		opaque := func() s07.V2XServicesAuthorizedExtIEsValue {
			sealed := s07.V2XServicesAuthorizedExtIEsValue{}
			*s07.BridgeV2XServicesAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeV2XServicesAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WLANMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.WLANMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s07.WLANMeasurementConfigurationExtIEsValue{})
		opaque := func() s07.WLANMeasurementConfigurationExtIEsValue {
			sealed := s07.WLANMeasurementConfigurationExtIEsValue{}
			*s07.BridgeWLANMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeWLANMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WUSAssistanceInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s08.WUSAssistanceInformationExtIEsValue)(nil))
		selectedAssert(&s08.WUSAssistanceInformationExtIEsValue{})
		opaque := func() s08.WUSAssistanceInformationExtIEsValue {
			sealed := s08.WUSAssistanceInformationExtIEsValue{}
			*s08.BridgeWUSAssistanceInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s08.BridgeWUSAssistanceInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WriteReplaceWarningRequestIEValue", func(t *testing.T) {
		selectedAssert((*s42.WriteReplaceWarningRequestIEValue)(nil))
		selectedAssert(&s42.WriteReplaceWarningRequestIEValue{})
		opaque := func() s42.WriteReplaceWarningRequestIEValue {
			sealed := s42.WriteReplaceWarningRequestIEValue{}
			*s42.BridgeWriteReplaceWarningRequestIEValueFieldIsOpaque(&sealed) = true
			*s42.BridgeWriteReplaceWarningRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(113)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaList(&sealed) = new(s41.WarningAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(114)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowRepetitionPeriod(&sealed) = new(s00.RepetitionPeriod)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(144)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowExtendedRepetitionPeriod(&sealed) = new(s00.ExtendedRepetitionPeriod)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(115)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowNumberofBroadcastRequest(&sealed) = new(s00.NumberofBroadcastRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(116)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningType(&sealed) = new(s00.WarningType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(117)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningSecurityInfo(&sealed) = new(s00.WarningSecurityInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(118)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowDataCodingScheme(&sealed) = new(s00.DataCodingScheme)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(119)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningMessageContents(&sealed) = new(s00.WarningMessageContents)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(142)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowConcurrentWarningMessageIndicator(&sealed) = new(s00.ConcurrentWarningMessageIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.WriteReplaceWarningRequestIEValue {
				sealed := s42.WriteReplaceWarningRequestIEValue{}
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(286)
				*s42.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaCoordinates(&sealed) = new(s00.WarningAreaCoordinates)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("WriteReplaceWarningResponseIEValue", func(t *testing.T) {
		selectedAssert((*s41.WriteReplaceWarningResponseIEValue)(nil))
		selectedAssert(&s41.WriteReplaceWarningResponseIEValue{})
		opaque := func() s41.WriteReplaceWarningResponseIEValue {
			sealed := s41.WriteReplaceWarningResponseIEValue{}
			*s41.BridgeWriteReplaceWarningResponseIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeWriteReplaceWarningResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.WriteReplaceWarningResponseIEValue {
				sealed := s41.WriteReplaceWarningResponseIEValue{}
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.WriteReplaceWarningResponseIEValue {
				sealed := s41.WriteReplaceWarningResponseIEValue{}
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.WriteReplaceWarningResponseIEValue {
				sealed := s41.WriteReplaceWarningResponseIEValue{}
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(120)
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldRowBroadcastCompletedAreaList(&sealed) = new(s41.BroadcastCompletedAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.WriteReplaceWarningResponseIEValue {
				sealed := s41.WriteReplaceWarningResponseIEValue{}
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s41.BridgeWriteReplaceWarningResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s26.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("X2TNLConfigurationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s48.X2TNLConfigurationInfoExtIEsValue)(nil))
		selectedAssert(&s48.X2TNLConfigurationInfoExtIEsValue{})
		opaque := func() s48.X2TNLConfigurationInfoExtIEsValue {
			sealed := s48.X2TNLConfigurationInfoExtIEsValue{}
			*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.X2TNLConfigurationInfoExtIEsValue {
				sealed := s48.X2TNLConfigurationInfoExtIEsValue{}
				*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(153)
				*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBX2ExtendedTransportLayerAddresses(&sealed) = new(s18.ENBX2ExtTLAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.X2TNLConfigurationInfoExtIEsValue {
				sealed := s48.X2TNLConfigurationInfoExtIEsValue{}
				*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(193)
				*s48.BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBIndirectX2TransportLayerAddresses(&sealed) = new(s00.ENBIndirectX2TransportLayerAddresses)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	if unions != 318 {
		t.Fatalf("union coverage %d", unions)
	}
	t.Logf("Selected coverage: %d unions, %d rows, 0 untested rows", unions, rows)
}
