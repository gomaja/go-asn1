// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s04 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s04"
	s05 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
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
		selectedAssert((*s02.AdditionalGUTIExtIEsValue)(nil))
		selectedAssert(&s02.AdditionalGUTIExtIEsValue{})
		opaque := func() s02.AdditionalGUTIExtIEsValue {
			sealed := s02.AdditionalGUTIExtIEsValue{}
			*s02.BridgeAdditionalGUTIExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeAdditionalGUTIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AllocationAndRetentionPriorityExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.AllocationAndRetentionPriorityExtIEsValue)(nil))
		selectedAssert(&s02.AllocationAndRetentionPriorityExtIEsValue{})
		opaque := func() s02.AllocationAndRetentionPriorityExtIEsValue {
			sealed := s02.AllocationAndRetentionPriorityExtIEsValue{}
			*s02.BridgeAllocationAndRetentionPriorityExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeAllocationAndRetentionPriorityExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AssistanceDataForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.AssistanceDataForPagingExtIEsValue)(nil))
		selectedAssert(&s02.AssistanceDataForPagingExtIEsValue{})
		opaque := func() s02.AssistanceDataForPagingExtIEsValue {
			sealed := s02.AssistanceDataForPagingExtIEsValue{}
			*s02.BridgeAssistanceDataForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeAssistanceDataForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("AssistanceDataForRecommendedCellsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.AssistanceDataForRecommendedCellsExtIEsValue)(nil))
		selectedAssert(&s02.AssistanceDataForRecommendedCellsExtIEsValue{})
		opaque := func() s02.AssistanceDataForRecommendedCellsExtIEsValue {
			sealed := s02.AssistanceDataForRecommendedCellsExtIEsValue{}
			*s02.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToDLDiscardingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.BearersSubjectToDLDiscardingItemExtIEsValue)(nil))
		selectedAssert(&s02.BearersSubjectToDLDiscardingItemExtIEsValue{})
		opaque := func() s02.BearersSubjectToDLDiscardingItemExtIEsValue {
			sealed := s02.BearersSubjectToDLDiscardingItemExtIEsValue{}
			*s02.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToDLDiscardingItemIEValue", func(t *testing.T) {
		selectedAssert((*s15.BearersSubjectToDLDiscardingItemIEValue)(nil))
		selectedAssert(&s15.BearersSubjectToDLDiscardingItemIEValue{})
		opaque := func() s15.BearersSubjectToDLDiscardingItemIEValue {
			sealed := s15.BearersSubjectToDLDiscardingItemIEValue{}
			*s15.BridgeBearersSubjectToDLDiscardingItemIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeBearersSubjectToDLDiscardingItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.BearersSubjectToDLDiscardingItemIEValue {
				sealed := s15.BearersSubjectToDLDiscardingItemIEValue{}
				*s15.BridgeBearersSubjectToDLDiscardingItemIEValueFieldId(&sealed) = s00.ProtocolIEID(351)
				*s15.BridgeBearersSubjectToDLDiscardingItemIEValueFieldRowBearersSubjectToDLDiscardingItem(&sealed) = new(s15.BearersSubjectToDLDiscardingItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToEarlyStatusTransferItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.BearersSubjectToEarlyStatusTransferItemExtIEsValue)(nil))
		selectedAssert(&s02.BearersSubjectToEarlyStatusTransferItemExtIEsValue{})
		opaque := func() s02.BearersSubjectToEarlyStatusTransferItemExtIEsValue {
			sealed := s02.BearersSubjectToEarlyStatusTransferItemExtIEsValue{}
			*s02.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("BearersSubjectToEarlyStatusTransferItemIEValue", func(t *testing.T) {
		selectedAssert((*s15.BearersSubjectToEarlyStatusTransferItemIEValue)(nil))
		selectedAssert(&s15.BearersSubjectToEarlyStatusTransferItemIEValue{})
		opaque := func() s15.BearersSubjectToEarlyStatusTransferItemIEValue {
			sealed := s15.BearersSubjectToEarlyStatusTransferItemIEValue{}
			*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.BearersSubjectToEarlyStatusTransferItemIEValue {
				sealed := s15.BearersSubjectToEarlyStatusTransferItemIEValue{}
				*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldId(&sealed) = s00.ProtocolIEID(322)
				*s15.BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldRowBearersSubjectToEarlyStatusTransferItem(&sealed) = new(s14.BearersSubjectToEarlyStatusTransferItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToStatusTransferItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s14.BearersSubjectToStatusTransferItemExtIEsValue)(nil))
		selectedAssert(&s14.BearersSubjectToStatusTransferItemExtIEsValue{})
		opaque := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
			sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
			*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(179)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(&sealed) = new(s14.COUNTValueExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(180)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(&sealed) = new(s14.COUNTValueExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(181)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(&sealed) = new(s00.ReceiveStatusOfULPDCPSDUsExtended)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(217)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(&sealed) = new(s14.COUNTvaluePDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(218)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(&sealed) = new(s14.COUNTvaluePDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s14.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s14.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(219)
				*s14.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(&sealed) = new(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BearersSubjectToStatusTransferItemIEValue", func(t *testing.T) {
		selectedAssert((*s21.BearersSubjectToStatusTransferItemIEValue)(nil))
		selectedAssert(&s21.BearersSubjectToStatusTransferItemIEValue{})
		opaque := func() s21.BearersSubjectToStatusTransferItemIEValue {
			sealed := s21.BearersSubjectToStatusTransferItemIEValue{}
			*s21.BridgeBearersSubjectToStatusTransferItemIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeBearersSubjectToStatusTransferItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.BearersSubjectToStatusTransferItemIEValue {
				sealed := s21.BearersSubjectToStatusTransferItemIEValue{}
				*s21.BridgeBearersSubjectToStatusTransferItemIEValueFieldId(&sealed) = s00.ProtocolIEID(89)
				*s21.BridgeBearersSubjectToStatusTransferItemIEValueFieldRowBearersSubjectToStatusTransferItem(&sealed) = new(s21.BearersSubjectToStatusTransferItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("BluetoothMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.BluetoothMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s02.BluetoothMeasurementConfigurationExtIEsValue{})
		opaque := func() s02.BluetoothMeasurementConfigurationExtIEsValue {
			sealed := s02.BluetoothMeasurementConfigurationExtIEsValue{}
			*s02.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeBluetoothMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CGIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.CGIExtIEsValue)(nil))
		selectedAssert(&s02.CGIExtIEsValue{})
		opaque := func() s02.CGIExtIEsValue {
			sealed := s02.CGIExtIEsValue{}
			*s02.BridgeCGIExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCGIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CNTypeRestrictionsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.CNTypeRestrictionsItemExtIEsValue)(nil))
		selectedAssert(&s02.CNTypeRestrictionsItemExtIEsValue{})
		opaque := func() s02.CNTypeRestrictionsItemExtIEsValue {
			sealed := s02.CNTypeRestrictionsItemExtIEsValue{}
			*s02.BridgeCNTypeRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCNTypeRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTValueExtendedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.COUNTValueExtendedExtIEsValue)(nil))
		selectedAssert(&s02.COUNTValueExtendedExtIEsValue{})
		opaque := func() s02.COUNTValueExtendedExtIEsValue {
			sealed := s02.COUNTValueExtendedExtIEsValue{}
			*s02.BridgeCOUNTValueExtendedExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCOUNTValueExtendedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTvalueExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.COUNTvalueExtIEsValue)(nil))
		selectedAssert(&s02.COUNTvalueExtIEsValue{})
		opaque := func() s02.COUNTvalueExtIEsValue {
			sealed := s02.COUNTvalueExtIEsValue{}
			*s02.BridgeCOUNTvalueExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCOUNTvalueExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("COUNTvaluePDCPSNlength18ExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.COUNTvaluePDCPSNlength18ExtIEsValue)(nil))
		selectedAssert(&s02.COUNTvaluePDCPSNlength18ExtIEsValue{})
		opaque := func() s02.COUNTvaluePDCPSNlength18ExtIEsValue {
			sealed := s02.COUNTvaluePDCPSNlength18ExtIEsValue{}
			*s02.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CSGIdListItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.CSGIdListItemExtIEsValue)(nil))
		selectedAssert(&s02.CSGIdListItemExtIEsValue{})
		opaque := func() s02.CSGIdListItemExtIEsValue {
			sealed := s02.CSGIdListItemExtIEsValue{}
			*s02.BridgeCSGIdListItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCSGIdListItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CSGMembershipInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.CSGMembershipInfoExtIEsValue)(nil))
		selectedAssert(&s02.CSGMembershipInfoExtIEsValue{})
		opaque := func() s02.CSGMembershipInfoExtIEsValue {
			sealed := s02.CSGMembershipInfoExtIEsValue{}
			*s02.BridgeCSGMembershipInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCSGMembershipInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("CancelledCellinEAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s02.CancelledCellinEAIItemExtIEsValue)(nil))
		selectedAssert(&s02.CancelledCellinEAIItemExtIEsValue{})
		opaque := func() s02.CancelledCellinEAIItemExtIEsValue {
			sealed := s02.CancelledCellinEAIItemExtIEsValue{}
			*s02.BridgeCancelledCellinEAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s02.BridgeCancelledCellinEAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
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
		selectedAssert((*s17.CellTrafficTraceIEValue)(nil))
		selectedAssert(&s17.CellTrafficTraceIEValue{})
		opaque := func() s17.CellTrafficTraceIEValue {
			sealed := s17.CellTrafficTraceIEValue{}
			*s17.BridgeCellTrafficTraceIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeCellTrafficTraceIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s17.BridgeCellTrafficTraceIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s17.BridgeCellTrafficTraceIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s17.BridgeCellTrafficTraceIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s17.BridgeCellTrafficTraceIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(131)
				*s17.BridgeCellTrafficTraceIEValueFieldRowTraceCollectionEntityIPAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s17.CellTrafficTraceIEValue {
				sealed := s17.CellTrafficTraceIEValue{}
				*s17.BridgeCellTrafficTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(166)
				*s17.BridgeCellTrafficTraceIEValueFieldRowPrivacyIndicator(&sealed) = new(s00.PrivacyIndicator)
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
		selectedAssert((*s31.ConnectionEstablishmentIndicationIEValue)(nil))
		selectedAssert(&s31.ConnectionEstablishmentIndicationIEValue{})
		opaque := func() s31.ConnectionEstablishmentIndicationIEValue {
			sealed := s31.ConnectionEstablishmentIndicationIEValue{}
			*s31.BridgeConnectionEstablishmentIndicationIEValueFieldIsOpaque(&sealed) = true
			*s31.BridgeConnectionEstablishmentIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(253)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowDLCPSecurityInformation(&sealed) = new(s15.DLCPSecurityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowEndIndication(&sealed) = new(s00.EndIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowUELevelQoSParameters(&sealed) = new(s18.ERABLevelQoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.ConnectionEstablishmentIndicationIEValue {
				sealed := s31.ConnectionEstablishmentIndicationIEValue{}
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s31.BridgeConnectionEstablishmentIndicationIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
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
		selectedAssert((*s03.DAPSResponseInfoItemExtIEsValue)(nil))
		selectedAssert(&s03.DAPSResponseInfoItemExtIEsValue{})
		opaque := func() s03.DAPSResponseInfoItemExtIEsValue {
			sealed := s03.DAPSResponseInfoItemExtIEsValue{}
			*s03.BridgeDAPSResponseInfoItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeDAPSResponseInfoItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DAPSResponseInfoListIEValue", func(t *testing.T) {
		selectedAssert((*s14.DAPSResponseInfoListIEValue)(nil))
		selectedAssert(&s14.DAPSResponseInfoListIEValue{})
		opaque := func() s14.DAPSResponseInfoListIEValue {
			sealed := s14.DAPSResponseInfoListIEValue{}
			*s14.BridgeDAPSResponseInfoListIEValueFieldIsOpaque(&sealed) = true
			*s14.BridgeDAPSResponseInfoListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s14.DAPSResponseInfoListIEValue {
				sealed := s14.DAPSResponseInfoListIEValue{}
				*s14.BridgeDAPSResponseInfoListIEValueFieldId(&sealed) = s00.ProtocolIEID(319)
				*s14.BridgeDAPSResponseInfoListIEValueFieldRowDAPSResponseInfoItem(&sealed) = new(s14.DAPSResponseInfoItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DLCPSecurityInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.DLCPSecurityInformationExtIEsValue)(nil))
		selectedAssert(&s03.DLCPSecurityInformationExtIEsValue{})
		opaque := func() s03.DLCPSecurityInformationExtIEsValue {
			sealed := s03.DLCPSecurityInformationExtIEsValue{}
			*s03.BridgeDLCPSecurityInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeDLCPSecurityInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("DeactivateTraceIEValue", func(t *testing.T) {
		selectedAssert((*s08.DeactivateTraceIEValue)(nil))
		selectedAssert(&s08.DeactivateTraceIEValue{})
		opaque := func() s08.DeactivateTraceIEValue {
			sealed := s08.DeactivateTraceIEValue{}
			*s08.BridgeDeactivateTraceIEValueFieldIsOpaque(&sealed) = true
			*s08.BridgeDeactivateTraceIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.DeactivateTraceIEValue {
				sealed := s08.DeactivateTraceIEValue{}
				*s08.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s08.BridgeDeactivateTraceIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DeactivateTraceIEValue {
				sealed := s08.DeactivateTraceIEValue{}
				*s08.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s08.BridgeDeactivateTraceIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DeactivateTraceIEValue {
				sealed := s08.DeactivateTraceIEValue{}
				*s08.BridgeDeactivateTraceIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s08.BridgeDeactivateTraceIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkNASTransportIEValue", func(t *testing.T) {
		selectedAssert((*s42.DownlinkNASTransportIEValue)(nil))
		selectedAssert(&s42.DownlinkNASTransportIEValue{})
		opaque := func() s42.DownlinkNASTransportIEValue {
			sealed := s42.DownlinkNASTransportIEValue{}
			*s42.BridgeDownlinkNASTransportIEValueFieldIsOpaque(&sealed) = true
			*s42.BridgeDownlinkNASTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowHandoverRestrictionList(&sealed) = new(s42.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(249)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowDLNASPDUDeliveryAckRequest(&sealed) = new(s00.DLNASPDUDeliveryAckRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(275)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowUECapabilityInfoRequest(&sealed) = new(s00.UECapabilityInfoRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(280)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowEndIndication(&sealed) = new(s00.EndIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.DownlinkNASTransportIEValue {
				sealed := s42.DownlinkNASTransportIEValue{}
				*s42.BridgeDownlinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s42.BridgeDownlinkNASTransportIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkNonUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s08.DownlinkNonUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s08.DownlinkNonUEAssociatedLPPaTransportIEValue{})
		opaque := func() s08.DownlinkNonUEAssociatedLPPaTransportIEValue {
			sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValue{}
			*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.DownlinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DownlinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkNonUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkS1cdma2000tunnellingIEValue", func(t *testing.T) {
		selectedAssert((*s40.DownlinkS1cdma2000tunnellingIEValue)(nil))
		selectedAssert(&s40.DownlinkS1cdma2000tunnellingIEValue{})
		opaque := func() s40.DownlinkS1cdma2000tunnellingIEValue {
			sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
			*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(12)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowERABSubjecttoDataForwardingList(&sealed) = new(s17.ERABSubjecttoDataForwardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(83)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000HOStatus(&sealed) = new(s00.Cdma2000HOStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = new(s00.Cdma2000RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.DownlinkS1cdma2000tunnellingIEValue {
				sealed := s40.DownlinkS1cdma2000tunnellingIEValue{}
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
				*s40.BridgeDownlinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = new(s00.Cdma2000PDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("DownlinkUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s08.DownlinkUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s08.DownlinkUEAssociatedLPPaTransportIEValue{})
		opaque := func() s08.DownlinkUEAssociatedLPPaTransportIEValue {
			sealed := s08.DownlinkUEAssociatedLPPaTransportIEValue{}
			*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.DownlinkUEAssociatedLPPaTransportIEValue {
				sealed := s08.DownlinkUEAssociatedLPPaTransportIEValue{}
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBCPRelocationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s37.ENBCPRelocationIndicationIEValue)(nil))
		selectedAssert(&s37.ENBCPRelocationIndicationIEValue{})
		opaque := func() s37.ENBCPRelocationIndicationIEValue {
			sealed := s37.ENBCPRelocationIndicationIEValue{}
			*s37.BridgeENBCPRelocationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeENBCPRelocationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowSTMSI(&sealed) = new(s28.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(254)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowULCPSecurityInformation(&sealed) = new(s37.ULCPSecurityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBCPRelocationIndicationIEValue {
				sealed := s37.ENBCPRelocationIndicationIEValue{}
				*s37.BridgeENBCPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s37.BridgeENBCPRelocationIndicationIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s51.ENBConfigurationTransferIEValue)(nil))
		selectedAssert(&s51.ENBConfigurationTransferIEValue{})
		opaque := func() s51.ENBConfigurationTransferIEValue {
			sealed := s51.ENBConfigurationTransferIEValue{}
			*s51.BridgeENBConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			*s51.BridgeENBConfigurationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.ENBConfigurationTransferIEValue {
				sealed := s51.ENBConfigurationTransferIEValue{}
				*s51.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(129)
				*s51.BridgeENBConfigurationTransferIEValueFieldRowSONConfigurationTransferECT(&sealed) = new(s51.SONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.ENBConfigurationTransferIEValue {
				sealed := s51.ENBConfigurationTransferIEValue{}
				*s51.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(294)
				*s51.BridgeENBConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferECT(&sealed) = new(s51.ENDCSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.ENBConfigurationTransferIEValue {
				sealed := s51.ENBConfigurationTransferIEValue{}
				*s51.BridgeENBConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(310)
				*s51.BridgeENBConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferECT(&sealed) = new(s00.IntersystemSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s22.ENBConfigurationUpdateAcknowledgeIEValue)(nil))
		selectedAssert(&s22.ENBConfigurationUpdateAcknowledgeIEValue{})
		opaque := func() s22.ENBConfigurationUpdateAcknowledgeIEValue {
			sealed := s22.ENBConfigurationUpdateAcknowledgeIEValue{}
			*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.ENBConfigurationUpdateAcknowledgeIEValue {
				sealed := s22.ENBConfigurationUpdateAcknowledgeIEValue{}
				*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeENBConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateFailureIEValue", func(t *testing.T) {
		selectedAssert((*s22.ENBConfigurationUpdateFailureIEValue)(nil))
		selectedAssert(&s22.ENBConfigurationUpdateFailureIEValue{})
		opaque := func() s22.ENBConfigurationUpdateFailureIEValue {
			sealed := s22.ENBConfigurationUpdateFailureIEValue{}
			*s22.BridgeENBConfigurationUpdateFailureIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeENBConfigurationUpdateFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.ENBConfigurationUpdateFailureIEValue {
				sealed := s22.ENBConfigurationUpdateFailureIEValue{}
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.ENBConfigurationUpdateFailureIEValue {
				sealed := s22.ENBConfigurationUpdateFailureIEValue{}
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.ENBConfigurationUpdateFailureIEValue {
				sealed := s22.ENBConfigurationUpdateFailureIEValue{}
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeENBConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBConfigurationUpdateIEValue", func(t *testing.T) {
		selectedAssert((*s43.ENBConfigurationUpdateIEValue)(nil))
		selectedAssert(&s43.ENBConfigurationUpdateIEValue{})
		opaque := func() s43.ENBConfigurationUpdateIEValue {
			sealed := s43.ENBConfigurationUpdateIEValue{}
			*s43.BridgeENBConfigurationUpdateIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeENBConfigurationUpdateIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(60)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowENBname(&sealed) = new(s00.ENBname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(64)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowSupportedTAs(&sealed) = new(s31.SupportedTAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowCSGIdList(&sealed) = new(s14.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(137)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowDefaultPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(234)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowNBIoTDefaultPagingDRX(&sealed) = new(s00.NBIoTDefaultPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(292)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToAddList(&sealed) = new(s31.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.ENBConfigurationUpdateIEValue {
				sealed := s43.ENBConfigurationUpdateIEValue{}
				*s43.BridgeENBConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(293)
				*s43.BridgeENBConfigurationUpdateIEValueFieldRowConnectedengNBToRemoveList(&sealed) = new(s31.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBDirectInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s33.ENBDirectInformationTransferIEValue)(nil))
		selectedAssert(&s33.ENBDirectInformationTransferIEValue{})
		opaque := func() s33.ENBDirectInformationTransferIEValue {
			sealed := s33.ENBDirectInformationTransferIEValue{}
			*s33.BridgeENBDirectInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s33.BridgeENBDirectInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s33.ENBDirectInformationTransferIEValue {
				sealed := s33.ENBDirectInformationTransferIEValue{}
				*s33.BridgeENBDirectInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(121)
				*s33.BridgeENBDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeEDT(&sealed) = new(s33.InterSystemInformationTransferType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBEarlyStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s37.ENBEarlyStatusTransferIEValue)(nil))
		selectedAssert(&s37.ENBEarlyStatusTransferIEValue{})
		opaque := func() s37.ENBEarlyStatusTransferIEValue {
			sealed := s37.ENBEarlyStatusTransferIEValue{}
			*s37.BridgeENBEarlyStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeENBEarlyStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ENBEarlyStatusTransferIEValue {
				sealed := s37.ENBEarlyStatusTransferIEValue{}
				*s37.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s37.BridgeENBEarlyStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBEarlyStatusTransferIEValue {
				sealed := s37.ENBEarlyStatusTransferIEValue{}
				*s37.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s37.BridgeENBEarlyStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.ENBEarlyStatusTransferIEValue {
				sealed := s37.ENBEarlyStatusTransferIEValue{}
				*s37.BridgeENBEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(321)
				*s37.BridgeENBEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(&sealed) = new(s37.ENBEarlyStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBEarlyStatusTransferTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue{})
		opaque := func() s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue {
			sealed := s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue{}
			*s37.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s37.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue {
				sealed := s37.ENBEarlyStatusTransferTransparentContainerExtIEsValue{}
				*s37.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(352)
				*s37.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldRowBearersSubjectToDLDiscardingList(&sealed) = new(s15.BearersSubjectToDLDiscardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s21.ENBStatusTransferIEValue)(nil))
		selectedAssert(&s21.ENBStatusTransferIEValue{})
		opaque := func() s21.ENBStatusTransferIEValue {
			sealed := s21.ENBStatusTransferIEValue{}
			*s21.BridgeENBStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeENBStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.ENBStatusTransferIEValue {
				sealed := s21.ENBStatusTransferIEValue{}
				*s21.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s21.BridgeENBStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.ENBStatusTransferIEValue {
				sealed := s21.ENBStatusTransferIEValue{}
				*s21.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s21.BridgeENBStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.ENBStatusTransferIEValue {
				sealed := s21.ENBStatusTransferIEValue{}
				*s21.BridgeENBStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(90)
				*s21.BridgeENBStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(&sealed) = new(s21.ENBStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ENBStatusTransferTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENBStatusTransferTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s03.ENBStatusTransferTransparentContainerExtIEsValue{})
		opaque := func() s03.ENBStatusTransferTransparentContainerExtIEsValue {
			sealed := s03.ENBStatusTransferTransparentContainerExtIEsValue{}
			*s03.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENBStatusTransferTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENBX2ExtTLAExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENBX2ExtTLAExtIEsValue)(nil))
		selectedAssert(&s03.ENBX2ExtTLAExtIEsValue{})
		opaque := func() s03.ENBX2ExtTLAExtIEsValue {
			sealed := s03.ENBX2ExtTLAExtIEsValue{}
			*s03.BridgeENBX2ExtTLAExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENBX2ExtTLAExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONConfigurationTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENDCSONConfigurationTransferExtIEsValue)(nil))
		selectedAssert(&s03.ENDCSONConfigurationTransferExtIEsValue{})
		opaque := func() s03.ENDCSONConfigurationTransferExtIEsValue {
			sealed := s03.ENDCSONConfigurationTransferExtIEsValue{}
			*s03.BridgeENDCSONConfigurationTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENDCSONConfigurationTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONeNBIdentificationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENDCSONeNBIdentificationExtIEsValue)(nil))
		selectedAssert(&s03.ENDCSONeNBIdentificationExtIEsValue{})
		opaque := func() s03.ENDCSONeNBIdentificationExtIEsValue {
			sealed := s03.ENDCSONeNBIdentificationExtIEsValue{}
			*s03.BridgeENDCSONeNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENDCSONeNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCSONengNBIdentificationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENDCSONengNBIdentificationExtIEsValue)(nil))
		selectedAssert(&s03.ENDCSONengNBIdentificationExtIEsValue{})
		opaque := func() s03.ENDCSONengNBIdentificationExtIEsValue {
			sealed := s03.ENDCSONengNBIdentificationExtIEsValue{}
			*s03.BridgeENDCSONengNBIdentificationExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENDCSONengNBIdentificationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCTransferTypeReplyExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENDCTransferTypeReplyExtIEsValue)(nil))
		selectedAssert(&s03.ENDCTransferTypeReplyExtIEsValue{})
		opaque := func() s03.ENDCTransferTypeReplyExtIEsValue {
			sealed := s03.ENDCTransferTypeReplyExtIEsValue{}
			*s03.BridgeENDCTransferTypeReplyExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENDCTransferTypeReplyExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ENDCTransferTypeRequestExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ENDCTransferTypeRequestExtIEsValue)(nil))
		selectedAssert(&s03.ENDCTransferTypeRequestExtIEsValue{})
		opaque := func() s03.ENDCTransferTypeRequestExtIEsValue {
			sealed := s03.ENDCTransferTypeRequestExtIEsValue{}
			*s03.BridgeENDCTransferTypeRequestExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeENDCTransferTypeRequestExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABAdmittedItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABAdmittedItemExtIEsValue)(nil))
		selectedAssert(&s03.ERABAdmittedItemExtIEsValue{})
		opaque := func() s03.ERABAdmittedItemExtIEsValue {
			sealed := s03.ERABAdmittedItemExtIEsValue{}
			*s03.BridgeERABAdmittedItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABAdmittedItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABAdmittedItemIEValue", func(t *testing.T) {
		selectedAssert((*s15.ERABAdmittedItemIEValue)(nil))
		selectedAssert(&s15.ERABAdmittedItemIEValue{})
		opaque := func() s15.ERABAdmittedItemIEValue {
			sealed := s15.ERABAdmittedItemIEValue{}
			*s15.BridgeERABAdmittedItemIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeERABAdmittedItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.ERABAdmittedItemIEValue {
				sealed := s15.ERABAdmittedItemIEValue{}
				*s15.BridgeERABAdmittedItemIEValueFieldId(&sealed) = s00.ProtocolIEID(20)
				*s15.BridgeERABAdmittedItemIEValueFieldRowERABAdmittedItem(&sealed) = new(s15.ERABAdmittedItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABDataForwardingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABDataForwardingItemExtIEsValue)(nil))
		selectedAssert(&s03.ERABDataForwardingItemExtIEsValue{})
		opaque := func() s03.ERABDataForwardingItemExtIEsValue {
			sealed := s03.ERABDataForwardingItemExtIEsValue{}
			*s03.BridgeERABDataForwardingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABDataForwardingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABDataForwardingItemIEValue", func(t *testing.T) {
		selectedAssert((*s15.ERABDataForwardingItemIEValue)(nil))
		selectedAssert(&s15.ERABDataForwardingItemIEValue{})
		opaque := func() s15.ERABDataForwardingItemIEValue {
			sealed := s15.ERABDataForwardingItemIEValue{}
			*s15.BridgeERABDataForwardingItemIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeERABDataForwardingItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.ERABDataForwardingItemIEValue {
				sealed := s15.ERABDataForwardingItemIEValue{}
				*s15.BridgeERABDataForwardingItemIEValueFieldId(&sealed) = s00.ProtocolIEID(14)
				*s15.BridgeERABDataForwardingItemIEValueFieldRowERABDataForwardingItem(&sealed) = new(s15.ERABDataForwardingItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToResumeItemResumeReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABFailedToResumeItemResumeReqExtIEsValue)(nil))
		selectedAssert(&s03.ERABFailedToResumeItemResumeReqExtIEsValue{})
		opaque := func() s03.ERABFailedToResumeItemResumeReqExtIEsValue {
			sealed := s03.ERABFailedToResumeItemResumeReqExtIEsValue{}
			*s03.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABFailedToResumeItemResumeReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedToResumeItemResumeReqIEValue", func(t *testing.T) {
		selectedAssert((*s15.ERABFailedToResumeItemResumeReqIEValue)(nil))
		selectedAssert(&s15.ERABFailedToResumeItemResumeReqIEValue{})
		opaque := func() s15.ERABFailedToResumeItemResumeReqIEValue {
			sealed := s15.ERABFailedToResumeItemResumeReqIEValue{}
			*s15.BridgeERABFailedToResumeItemResumeReqIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeERABFailedToResumeItemResumeReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.ERABFailedToResumeItemResumeReqIEValue {
				sealed := s15.ERABFailedToResumeItemResumeReqIEValue{}
				*s15.BridgeERABFailedToResumeItemResumeReqIEValueFieldId(&sealed) = s00.ProtocolIEID(236)
				*s15.BridgeERABFailedToResumeItemResumeReqIEValueFieldRowERABFailedToResumeItemResumeReq(&sealed) = new(s15.ERABFailedToResumeItemResumeReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToResumeItemResumeResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABFailedToResumeItemResumeResExtIEsValue)(nil))
		selectedAssert(&s03.ERABFailedToResumeItemResumeResExtIEsValue{})
		opaque := func() s03.ERABFailedToResumeItemResumeResExtIEsValue {
			sealed := s03.ERABFailedToResumeItemResumeResExtIEsValue{}
			*s03.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABFailedToResumeItemResumeResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedToResumeItemResumeResIEValue", func(t *testing.T) {
		selectedAssert((*s15.ERABFailedToResumeItemResumeResIEValue)(nil))
		selectedAssert(&s15.ERABFailedToResumeItemResumeResIEValue{})
		opaque := func() s15.ERABFailedToResumeItemResumeResIEValue {
			sealed := s15.ERABFailedToResumeItemResumeResIEValue{}
			*s15.BridgeERABFailedToResumeItemResumeResIEValueFieldIsOpaque(&sealed) = true
			*s15.BridgeERABFailedToResumeItemResumeResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s15.ERABFailedToResumeItemResumeResIEValue {
				sealed := s15.ERABFailedToResumeItemResumeResIEValue{}
				*s15.BridgeERABFailedToResumeItemResumeResIEValueFieldId(&sealed) = s00.ProtocolIEID(238)
				*s15.BridgeERABFailedToResumeItemResumeResIEValueFieldRowERABFailedToResumeItemResumeRes(&sealed) = new(s15.ERABFailedToResumeItemResumeRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABFailedToSetupItemHOReqAckExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABFailedToSetupItemHOReqAckExtIEsValue)(nil))
		selectedAssert(&s03.ERABFailedToSetupItemHOReqAckExtIEsValue{})
		opaque := func() s03.ERABFailedToSetupItemHOReqAckExtIEsValue {
			sealed := s03.ERABFailedToSetupItemHOReqAckExtIEsValue{}
			*s03.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABFailedToSetupItemHOReqAckExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABFailedtoSetupItemHOReqAckIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABFailedtoSetupItemHOReqAckIEValue)(nil))
		selectedAssert(&s16.ERABFailedtoSetupItemHOReqAckIEValue{})
		opaque := func() s16.ERABFailedtoSetupItemHOReqAckIEValue {
			sealed := s16.ERABFailedtoSetupItemHOReqAckIEValue{}
			*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABFailedtoSetupItemHOReqAckIEValue {
				sealed := s16.ERABFailedtoSetupItemHOReqAckIEValue{}
				*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldId(&sealed) = s00.ProtocolIEID(21)
				*s16.BridgeERABFailedtoSetupItemHOReqAckIEValueFieldRowERABFailedtoSetupItemHOReqAck(&sealed) = new(s16.ERABFailedToSetupItemHOReqAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABInformationListIEValue", func(t *testing.T) {
		selectedAssert((*s29.ERABInformationListIEValue)(nil))
		selectedAssert(&s29.ERABInformationListIEValue{})
		opaque := func() s29.ERABInformationListIEValue {
			sealed := s29.ERABInformationListIEValue{}
			*s29.BridgeERABInformationListIEValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABInformationListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABInformationListIEValue {
				sealed := s29.ERABInformationListIEValue{}
				*s29.BridgeERABInformationListIEValueFieldId(&sealed) = s00.ProtocolIEID(78)
				*s29.BridgeERABInformationListIEValueFieldRowERABInformationListItem(&sealed) = new(s29.ERABInformationListItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABInformationListItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s28.ERABInformationListItemExtIEsValue)(nil))
		selectedAssert(&s28.ERABInformationListItemExtIEsValue{})
		opaque := func() s28.ERABInformationListItemExtIEsValue {
			sealed := s28.ERABInformationListItemExtIEsValue{}
			*s28.BridgeERABInformationListItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s28.BridgeERABInformationListItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(317)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowDAPSRequestInfo(&sealed) = new(s14.DAPSRequestInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(328)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSecurityIndication(&sealed) = new(s28.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABInformationListItemExtIEsValue {
				sealed := s28.ERABInformationListItemExtIEsValue{}
				*s28.BridgeERABInformationListItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(340)
				*s28.BridgeERABInformationListItemExtIEsValueFieldRowSourceNodeTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABItemExtIEsValue)(nil))
		selectedAssert(&s03.ERABItemExtIEsValue{})
		opaque := func() s03.ERABItemExtIEsValue {
			sealed := s03.ERABItemExtIEsValue{}
			*s03.BridgeERABItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABItemIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABItemIEValue)(nil))
		selectedAssert(&s16.ERABItemIEValue{})
		opaque := func() s16.ERABItemIEValue {
			sealed := s16.ERABItemIEValue{}
			*s16.BridgeERABItemIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABItemIEValue {
				sealed := s16.ERABItemIEValue{}
				*s16.BridgeERABItemIEValueFieldId(&sealed) = s00.ProtocolIEID(35)
				*s16.BridgeERABItemIEValueFieldRowERABItem(&sealed) = new(s16.ERABItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModificationConfirmIEValue", func(t *testing.T) {
		selectedAssert((*s39.ERABModificationConfirmIEValue)(nil))
		selectedAssert(&s39.ERABModificationConfirmIEValue{})
		opaque := func() s39.ERABModificationConfirmIEValue {
			sealed := s39.ERABModificationConfirmIEValue{}
			*s39.BridgeERABModificationConfirmIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeERABModificationConfirmIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s39.BridgeERABModificationConfirmIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s39.BridgeERABModificationConfirmIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(203)
				*s39.BridgeERABModificationConfirmIEValueFieldRowERABModifyListBearerModConf(&sealed) = new(s16.ERABModifyListBearerModConf)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(205)
				*s39.BridgeERABModificationConfirmIEValueFieldRowERABFailedToModifyListBearerModConf(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(210)
				*s39.BridgeERABModificationConfirmIEValueFieldRowERABToBeReleasedListBearerModConf(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s39.BridgeERABModificationConfirmIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABModificationConfirmIEValue {
				sealed := s39.ERABModificationConfirmIEValue{}
				*s39.BridgeERABModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s39.BridgeERABModificationConfirmIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModificationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s44.ERABModificationIndicationIEValue)(nil))
		selectedAssert(&s44.ERABModificationIndicationIEValue{})
		opaque := func() s44.ERABModificationIndicationIEValue {
			sealed := s44.ERABModificationIndicationIEValue{}
			*s44.BridgeERABModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s44.BridgeERABModificationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s44.BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s44.BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(199)
				*s44.BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(&sealed) = new(s17.ERABToBeModifiedListBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(201)
				*s44.BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(&sealed) = new(s16.ERABNotToBeModifiedListBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s44.BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = new(s14.CSGMembershipInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s44.BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s35.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s44.BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ERABModificationIndicationIEValue {
				sealed := s44.ERABModificationIndicationIEValue{}
				*s44.BridgeERABModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s44.BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyItemBearerModConfExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABModifyItemBearerModConfExtIEsValue)(nil))
		selectedAssert(&s03.ERABModifyItemBearerModConfExtIEsValue{})
		opaque := func() s03.ERABModifyItemBearerModConfExtIEsValue {
			sealed := s03.ERABModifyItemBearerModConfExtIEsValue{}
			*s03.BridgeERABModifyItemBearerModConfExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABModifyItemBearerModConfExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABModifyItemBearerModConfIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABModifyItemBearerModConfIEValue)(nil))
		selectedAssert(&s16.ERABModifyItemBearerModConfIEValue{})
		opaque := func() s16.ERABModifyItemBearerModConfIEValue {
			sealed := s16.ERABModifyItemBearerModConfIEValue{}
			*s16.BridgeERABModifyItemBearerModConfIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABModifyItemBearerModConfIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABModifyItemBearerModConfIEValue {
				sealed := s16.ERABModifyItemBearerModConfIEValue{}
				*s16.BridgeERABModifyItemBearerModConfIEValueFieldId(&sealed) = s00.ProtocolIEID(204)
				*s16.BridgeERABModifyItemBearerModConfIEValueFieldRowERABModifyItemBearerModConf(&sealed) = new(s16.ERABModifyItemBearerModConf)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyItemBearerModResExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABModifyItemBearerModResExtIEsValue)(nil))
		selectedAssert(&s03.ERABModifyItemBearerModResExtIEsValue{})
		opaque := func() s03.ERABModifyItemBearerModResExtIEsValue {
			sealed := s03.ERABModifyItemBearerModResExtIEsValue{}
			*s03.BridgeERABModifyItemBearerModResExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABModifyItemBearerModResExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABModifyItemBearerModResIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABModifyItemBearerModResIEValue)(nil))
		selectedAssert(&s16.ERABModifyItemBearerModResIEValue{})
		opaque := func() s16.ERABModifyItemBearerModResIEValue {
			sealed := s16.ERABModifyItemBearerModResIEValue{}
			*s16.BridgeERABModifyItemBearerModResIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABModifyItemBearerModResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABModifyItemBearerModResIEValue {
				sealed := s16.ERABModifyItemBearerModResIEValue{}
				*s16.BridgeERABModifyItemBearerModResIEValueFieldId(&sealed) = s00.ProtocolIEID(37)
				*s16.BridgeERABModifyItemBearerModResIEValueFieldRowERABModifyItemBearerModRes(&sealed) = new(s16.ERABModifyItemBearerModRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyRequestIEValue", func(t *testing.T) {
		selectedAssert((*s40.ERABModifyRequestIEValue)(nil))
		selectedAssert(&s40.ERABModifyRequestIEValue{})
		opaque := func() s40.ERABModifyRequestIEValue {
			sealed := s40.ERABModifyRequestIEValue{}
			*s40.BridgeERABModifyRequestIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeERABModifyRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.ERABModifyRequestIEValue {
				sealed := s40.ERABModifyRequestIEValue{}
				*s40.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeERABModifyRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABModifyRequestIEValue {
				sealed := s40.ERABModifyRequestIEValue{}
				*s40.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeERABModifyRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABModifyRequestIEValue {
				sealed := s40.ERABModifyRequestIEValue{}
				*s40.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s40.BridgeERABModifyRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABModifyRequestIEValue {
				sealed := s40.ERABModifyRequestIEValue{}
				*s40.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(30)
				*s40.BridgeERABModifyRequestIEValueFieldRowERABToBeModifiedListBearerModReq(&sealed) = new(s25.ERABToBeModifiedListBearerModReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABModifyRequestIEValue {
				sealed := s40.ERABModifyRequestIEValue{}
				*s40.BridgeERABModifyRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(268)
				*s40.BridgeERABModifyRequestIEValueFieldRowSecondaryRATDataUsageRequest(&sealed) = new(s00.SecondaryRATDataUsageRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABModifyResponseIEValue", func(t *testing.T) {
		selectedAssert((*s45.ERABModifyResponseIEValue)(nil))
		selectedAssert(&s45.ERABModifyResponseIEValue{})
		opaque := func() s45.ERABModifyResponseIEValue {
			sealed := s45.ERABModifyResponseIEValue{}
			*s45.BridgeERABModifyResponseIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeERABModifyResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeERABModifyResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeERABModifyResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(31)
				*s45.BridgeERABModifyResponseIEValueFieldRowERABModifyListBearerModRes(&sealed) = new(s16.ERABModifyListBearerModRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(32)
				*s45.BridgeERABModifyResponseIEValueFieldRowERABFailedToModifyList(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s45.BridgeERABModifyResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeERABModifyResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABModifyResponseIEValue {
				sealed := s45.ERABModifyResponseIEValue{}
				*s45.BridgeERABModifyResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeERABModifyResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABNotToBeModifiedItemBearerModIndExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABNotToBeModifiedItemBearerModIndExtIEsValue)(nil))
		selectedAssert(&s03.ERABNotToBeModifiedItemBearerModIndExtIEsValue{})
		opaque := func() s03.ERABNotToBeModifiedItemBearerModIndExtIEsValue {
			sealed := s03.ERABNotToBeModifiedItemBearerModIndExtIEsValue{}
			*s03.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABNotToBeModifiedItemBearerModIndIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABNotToBeModifiedItemBearerModIndIEValue)(nil))
		selectedAssert(&s16.ERABNotToBeModifiedItemBearerModIndIEValue{})
		opaque := func() s16.ERABNotToBeModifiedItemBearerModIndIEValue {
			sealed := s16.ERABNotToBeModifiedItemBearerModIndIEValue{}
			*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABNotToBeModifiedItemBearerModIndIEValue {
				sealed := s16.ERABNotToBeModifiedItemBearerModIndIEValue{}
				*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldId(&sealed) = s00.ProtocolIEID(202)
				*s16.BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldRowERABNotToBeModifiedItemBearerModInd(&sealed) = new(s16.ERABNotToBeModifiedItemBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABQoSParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s08.ERABQoSParametersExtIEsValue)(nil))
		selectedAssert(&s08.ERABQoSParametersExtIEsValue{})
		opaque := func() s08.ERABQoSParametersExtIEsValue {
			sealed := s08.ERABQoSParametersExtIEsValue{}
			*s08.BridgeERABQoSParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s08.BridgeERABQoSParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s08.ERABQoSParametersExtIEsValue {
				sealed := s08.ERABQoSParametersExtIEsValue{}
				*s08.BridgeERABQoSParametersExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(273)
				*s08.BridgeERABQoSParametersExtIEsValueFieldRowDownlinkPacketLossRate(&sealed) = new(s00.PacketLossRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s08.ERABQoSParametersExtIEsValue {
				sealed := s08.ERABQoSParametersExtIEsValue{}
				*s08.BridgeERABQoSParametersExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(274)
				*s08.BridgeERABQoSParametersExtIEsValueFieldRowUplinkPacketLossRate(&sealed) = new(s00.PacketLossRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseCommandIEValue", func(t *testing.T) {
		selectedAssert((*s39.ERABReleaseCommandIEValue)(nil))
		selectedAssert(&s39.ERABReleaseCommandIEValue{})
		opaque := func() s39.ERABReleaseCommandIEValue {
			sealed := s39.ERABReleaseCommandIEValue{}
			*s39.BridgeERABReleaseCommandIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeERABReleaseCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.ERABReleaseCommandIEValue {
				sealed := s39.ERABReleaseCommandIEValue{}
				*s39.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s39.BridgeERABReleaseCommandIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABReleaseCommandIEValue {
				sealed := s39.ERABReleaseCommandIEValue{}
				*s39.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s39.BridgeERABReleaseCommandIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABReleaseCommandIEValue {
				sealed := s39.ERABReleaseCommandIEValue{}
				*s39.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s39.BridgeERABReleaseCommandIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABReleaseCommandIEValue {
				sealed := s39.ERABReleaseCommandIEValue{}
				*s39.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
				*s39.BridgeERABReleaseCommandIEValueFieldRowERABToBeReleasedList(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.ERABReleaseCommandIEValue {
				sealed := s39.ERABReleaseCommandIEValue{}
				*s39.BridgeERABReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s39.BridgeERABReleaseCommandIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s45.ERABReleaseIndicationIEValue)(nil))
		selectedAssert(&s45.ERABReleaseIndicationIEValue{})
		opaque := func() s45.ERABReleaseIndicationIEValue {
			sealed := s45.ERABReleaseIndicationIEValue{}
			*s45.BridgeERABReleaseIndicationIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeERABReleaseIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.ERABReleaseIndicationIEValue {
				sealed := s45.ERABReleaseIndicationIEValue{}
				*s45.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeERABReleaseIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseIndicationIEValue {
				sealed := s45.ERABReleaseIndicationIEValue{}
				*s45.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeERABReleaseIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseIndicationIEValue {
				sealed := s45.ERABReleaseIndicationIEValue{}
				*s45.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(110)
				*s45.BridgeERABReleaseIndicationIEValueFieldRowERABReleasedList(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseIndicationIEValue {
				sealed := s45.ERABReleaseIndicationIEValue{}
				*s45.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeERABReleaseIndicationIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseIndicationIEValue {
				sealed := s45.ERABReleaseIndicationIEValue{}
				*s45.BridgeERABReleaseIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeERABReleaseIndicationIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseItemBearerRelCompExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABReleaseItemBearerRelCompExtIEsValue)(nil))
		selectedAssert(&s03.ERABReleaseItemBearerRelCompExtIEsValue{})
		opaque := func() s03.ERABReleaseItemBearerRelCompExtIEsValue {
			sealed := s03.ERABReleaseItemBearerRelCompExtIEsValue{}
			*s03.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABReleaseItemBearerRelCompExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABReleaseItemBearerRelCompIEValue", func(t *testing.T) {
		selectedAssert((*s16.ERABReleaseItemBearerRelCompIEValue)(nil))
		selectedAssert(&s16.ERABReleaseItemBearerRelCompIEValue{})
		opaque := func() s16.ERABReleaseItemBearerRelCompIEValue {
			sealed := s16.ERABReleaseItemBearerRelCompIEValue{}
			*s16.BridgeERABReleaseItemBearerRelCompIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABReleaseItemBearerRelCompIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABReleaseItemBearerRelCompIEValue {
				sealed := s16.ERABReleaseItemBearerRelCompIEValue{}
				*s16.BridgeERABReleaseItemBearerRelCompIEValueFieldId(&sealed) = s00.ProtocolIEID(15)
				*s16.BridgeERABReleaseItemBearerRelCompIEValueFieldRowERABReleaseItemBearerRelComp(&sealed) = new(s16.ERABReleaseItemBearerRelComp)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABReleaseResponseIEValue", func(t *testing.T) {
		selectedAssert((*s45.ERABReleaseResponseIEValue)(nil))
		selectedAssert(&s45.ERABReleaseResponseIEValue{})
		opaque := func() s45.ERABReleaseResponseIEValue {
			sealed := s45.ERABReleaseResponseIEValue{}
			*s45.BridgeERABReleaseResponseIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeERABReleaseResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeERABReleaseResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeERABReleaseResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(69)
				*s45.BridgeERABReleaseResponseIEValueFieldRowERABReleaseListBearerRelComp(&sealed) = new(s16.ERABReleaseListBearerRelComp)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(34)
				*s45.BridgeERABReleaseResponseIEValueFieldRowERABFailedToReleaseList(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s45.BridgeERABReleaseResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeERABReleaseResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABReleaseResponseIEValue {
				sealed := s45.ERABReleaseResponseIEValue{}
				*s45.BridgeERABReleaseResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeERABReleaseResponseIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSecurityResultItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s03.ERABSecurityResultItemExtIEsValue)(nil))
		selectedAssert(&s03.ERABSecurityResultItemExtIEsValue{})
		opaque := func() s03.ERABSecurityResultItemExtIEsValue {
			sealed := s03.ERABSecurityResultItemExtIEsValue{}
			*s03.BridgeERABSecurityResultItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s03.BridgeERABSecurityResultItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ERABSecurityResultListIEValue", func(t *testing.T) {
		selectedAssert((*s30.ERABSecurityResultListIEValue)(nil))
		selectedAssert(&s30.ERABSecurityResultListIEValue{})
		opaque := func() s30.ERABSecurityResultListIEValue {
			sealed := s30.ERABSecurityResultListIEValue{}
			*s30.BridgeERABSecurityResultListIEValueFieldIsOpaque(&sealed) = true
			*s30.BridgeERABSecurityResultListIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s30.ERABSecurityResultListIEValue {
				sealed := s30.ERABSecurityResultListIEValue{}
				*s30.BridgeERABSecurityResultListIEValueFieldId(&sealed) = s00.ProtocolIEID(334)
				*s30.BridgeERABSecurityResultListIEValueFieldRowERABSecurityResultItem(&sealed) = new(s30.ERABSecurityResultItem)
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
		selectedAssert((*s16.ERABSetupItemBearerSUResIEValue)(nil))
		selectedAssert(&s16.ERABSetupItemBearerSUResIEValue{})
		opaque := func() s16.ERABSetupItemBearerSUResIEValue {
			sealed := s16.ERABSetupItemBearerSUResIEValue{}
			*s16.BridgeERABSetupItemBearerSUResIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABSetupItemBearerSUResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABSetupItemBearerSUResIEValue {
				sealed := s16.ERABSetupItemBearerSUResIEValue{}
				*s16.BridgeERABSetupItemBearerSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(39)
				*s16.BridgeERABSetupItemBearerSUResIEValueFieldRowERABSetupItemBearerSURes(&sealed) = new(s16.ERABSetupItemBearerSURes)
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
		selectedAssert((*s16.ERABSetupItemCtxtSUResIEValue)(nil))
		selectedAssert(&s16.ERABSetupItemCtxtSUResIEValue{})
		opaque := func() s16.ERABSetupItemCtxtSUResIEValue {
			sealed := s16.ERABSetupItemCtxtSUResIEValue{}
			*s16.BridgeERABSetupItemCtxtSUResIEValueFieldIsOpaque(&sealed) = true
			*s16.BridgeERABSetupItemCtxtSUResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s16.ERABSetupItemCtxtSUResIEValue {
				sealed := s16.ERABSetupItemCtxtSUResIEValue{}
				*s16.BridgeERABSetupItemCtxtSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(50)
				*s16.BridgeERABSetupItemCtxtSUResIEValueFieldRowERABSetupItemCtxtSURes(&sealed) = new(s16.ERABSetupItemCtxtSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s40.ERABSetupRequestIEValue)(nil))
		selectedAssert(&s40.ERABSetupRequestIEValue{})
		opaque := func() s40.ERABSetupRequestIEValue {
			sealed := s40.ERABSetupRequestIEValue{}
			*s40.BridgeERABSetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeERABSetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.ERABSetupRequestIEValue {
				sealed := s40.ERABSetupRequestIEValue{}
				*s40.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeERABSetupRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABSetupRequestIEValue {
				sealed := s40.ERABSetupRequestIEValue{}
				*s40.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeERABSetupRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABSetupRequestIEValue {
				sealed := s40.ERABSetupRequestIEValue{}
				*s40.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s40.BridgeERABSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.ERABSetupRequestIEValue {
				sealed := s40.ERABSetupRequestIEValue{}
				*s40.BridgeERABSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(16)
				*s40.BridgeERABSetupRequestIEValueFieldRowERABToBeSetupListBearerSUReq(&sealed) = new(s29.ERABToBeSetupListBearerSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABSetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s45.ERABSetupResponseIEValue)(nil))
		selectedAssert(&s45.ERABSetupResponseIEValue{})
		opaque := func() s45.ERABSetupResponseIEValue {
			sealed := s45.ERABSetupResponseIEValue{}
			*s45.BridgeERABSetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeERABSetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeERABSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeERABSetupResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(28)
				*s45.BridgeERABSetupResponseIEValueFieldRowERABSetupListBearerSURes(&sealed) = new(s17.ERABSetupListBearerSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(29)
				*s45.BridgeERABSetupResponseIEValueFieldRowERABFailedToSetupListBearerSURes(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s45.BridgeERABSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.ERABSetupResponseIEValue {
				sealed := s45.ERABSetupResponseIEValue{}
				*s45.BridgeERABSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeERABSetupResponseIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
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
		selectedAssert((*s17.ERABToBeModifiedItemBearerModIndIEValue)(nil))
		selectedAssert(&s17.ERABToBeModifiedItemBearerModIndIEValue{})
		opaque := func() s17.ERABToBeModifiedItemBearerModIndIEValue {
			sealed := s17.ERABToBeModifiedItemBearerModIndIEValue{}
			*s17.BridgeERABToBeModifiedItemBearerModIndIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeERABToBeModifiedItemBearerModIndIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.ERABToBeModifiedItemBearerModIndIEValue {
				sealed := s17.ERABToBeModifiedItemBearerModIndIEValue{}
				*s17.BridgeERABToBeModifiedItemBearerModIndIEValueFieldId(&sealed) = s00.ProtocolIEID(200)
				*s17.BridgeERABToBeModifiedItemBearerModIndIEValueFieldRowERABToBeModifiedItemBearerModInd(&sealed) = new(s17.ERABToBeModifiedItemBearerModInd)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeModifiedItemBearerModReqIEValue", func(t *testing.T) {
		selectedAssert((*s25.ERABToBeModifiedItemBearerModReqIEValue)(nil))
		selectedAssert(&s25.ERABToBeModifiedItemBearerModReqIEValue{})
		opaque := func() s25.ERABToBeModifiedItemBearerModReqIEValue {
			sealed := s25.ERABToBeModifiedItemBearerModReqIEValue{}
			*s25.BridgeERABToBeModifiedItemBearerModReqIEValueFieldIsOpaque(&sealed) = true
			*s25.BridgeERABToBeModifiedItemBearerModReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s25.ERABToBeModifiedItemBearerModReqIEValue {
				sealed := s25.ERABToBeModifiedItemBearerModReqIEValue{}
				*s25.BridgeERABToBeModifiedItemBearerModReqIEValueFieldId(&sealed) = s00.ProtocolIEID(36)
				*s25.BridgeERABToBeModifiedItemBearerModReqIEValueFieldRowERABToBeModifiedItemBearerModReq(&sealed) = new(s25.ERABToBeModifiedItemBearerModReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeModifyItemBearerModReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s21.ERABToBeModifyItemBearerModReqExtIEsValue)(nil))
		selectedAssert(&s21.ERABToBeModifyItemBearerModReqExtIEsValue{})
		opaque := func() s21.ERABToBeModifyItemBearerModReqExtIEsValue {
			sealed := s21.ERABToBeModifyItemBearerModReqExtIEsValue{}
			*s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.ERABToBeModifyItemBearerModReqExtIEsValue {
				sealed := s21.ERABToBeModifyItemBearerModReqExtIEsValue{}
				*s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(185)
				*s21.BridgeERABToBeModifyItemBearerModReqExtIEsValueFieldRowTransportInformation(&sealed) = new(s21.TransportInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemBearerSUReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s28.ERABToBeSetupItemBearerSUReqExtIEsValue)(nil))
		selectedAssert(&s28.ERABToBeSetupItemBearerSUReqExtIEsValue{})
		opaque := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
			sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ERABToBeSetupItemBearerSUReqExtIEsValue {
				sealed := s28.ERABToBeSetupItemBearerSUReqExtIEsValue{}
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s28.BridgeERABToBeSetupItemBearerSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s28.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemBearerSUReqIEValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeSetupItemBearerSUReqIEValue)(nil))
		selectedAssert(&s29.ERABToBeSetupItemBearerSUReqIEValue{})
		opaque := func() s29.ERABToBeSetupItemBearerSUReqIEValue {
			sealed := s29.ERABToBeSetupItemBearerSUReqIEValue{}
			*s29.BridgeERABToBeSetupItemBearerSUReqIEValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeSetupItemBearerSUReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeSetupItemBearerSUReqIEValue {
				sealed := s29.ERABToBeSetupItemBearerSUReqIEValue{}
				*s29.BridgeERABToBeSetupItemBearerSUReqIEValueFieldId(&sealed) = s00.ProtocolIEID(17)
				*s29.BridgeERABToBeSetupItemBearerSUReqIEValueFieldRowERABToBeSetupItemBearerSUReq(&sealed) = new(s29.ERABToBeSetupItemBearerSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemCtxtSUReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeSetupItemCtxtSUReqExtIEsValue)(nil))
		selectedAssert(&s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{})
		opaque := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
			sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
			*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(156)
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(183)
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSIPTOCorrelationID(&sealed) = new(s00.CorrelationID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s28.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemCtxtSUReqIEValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeSetupItemCtxtSUReqIEValue)(nil))
		selectedAssert(&s29.ERABToBeSetupItemCtxtSUReqIEValue{})
		opaque := func() s29.ERABToBeSetupItemCtxtSUReqIEValue {
			sealed := s29.ERABToBeSetupItemCtxtSUReqIEValue{}
			*s29.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeSetupItemCtxtSUReqIEValue {
				sealed := s29.ERABToBeSetupItemCtxtSUReqIEValue{}
				*s29.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldId(&sealed) = s00.ProtocolIEID(52)
				*s29.BridgeERABToBeSetupItemCtxtSUReqIEValueFieldRowERABToBeSetupItemCtxtSUReq(&sealed) = new(s29.ERABToBeSetupItemCtxtSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemHOReqExtIEsValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeSetupItemHOReqExtIEsValue)(nil))
		selectedAssert(&s29.ERABToBeSetupItemHOReqExtIEsValue{})
		opaque := func() s29.ERABToBeSetupItemHOReqExtIEsValue {
			sealed := s29.ERABToBeSetupItemHOReqExtIEsValue{}
			*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemHOReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(143)
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowDataForwardingNotPossible(&sealed) = new(s00.DataForwardingNotPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemHOReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(233)
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowBearerType(&sealed) = new(s00.BearerType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemHOReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(305)
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowEthernetType(&sealed) = new(s00.EthernetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s29.ERABToBeSetupItemHOReqExtIEsValue {
				sealed := s29.ERABToBeSetupItemHOReqExtIEsValue{}
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s29.BridgeERABToBeSetupItemHOReqExtIEsValueFieldRowSecurityIndication(&sealed) = new(s28.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSetupItemHOReqIEValue", func(t *testing.T) {
		selectedAssert((*s30.ERABToBeSetupItemHOReqIEValue)(nil))
		selectedAssert(&s30.ERABToBeSetupItemHOReqIEValue{})
		opaque := func() s30.ERABToBeSetupItemHOReqIEValue {
			sealed := s30.ERABToBeSetupItemHOReqIEValue{}
			*s30.BridgeERABToBeSetupItemHOReqIEValueFieldIsOpaque(&sealed) = true
			*s30.BridgeERABToBeSetupItemHOReqIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s30.ERABToBeSetupItemHOReqIEValue {
				sealed := s30.ERABToBeSetupItemHOReqIEValue{}
				*s30.BridgeERABToBeSetupItemHOReqIEValueFieldId(&sealed) = s00.ProtocolIEID(27)
				*s30.BridgeERABToBeSetupItemHOReqIEValueFieldRowERABToBeSetupItemHOReq(&sealed) = new(s29.ERABToBeSetupItemHOReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSwitchedDLItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s29.ERABToBeSwitchedDLItemExtIEsValue)(nil))
		selectedAssert(&s29.ERABToBeSwitchedDLItemExtIEsValue{})
		opaque := func() s29.ERABToBeSwitchedDLItemExtIEsValue {
			sealed := s29.ERABToBeSwitchedDLItemExtIEsValue{}
			*s29.BridgeERABToBeSwitchedDLItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeSwitchedDLItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeSwitchedDLItemExtIEsValue {
				sealed := s29.ERABToBeSwitchedDLItemExtIEsValue{}
				*s29.BridgeERABToBeSwitchedDLItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(332)
				*s29.BridgeERABToBeSwitchedDLItemExtIEsValueFieldRowSecurityIndication(&sealed) = new(s28.SecurityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ERABToBeSwitchedDLItemIEValue", func(t *testing.T) {
		selectedAssert((*s30.ERABToBeSwitchedDLItemIEValue)(nil))
		selectedAssert(&s30.ERABToBeSwitchedDLItemIEValue{})
		opaque := func() s30.ERABToBeSwitchedDLItemIEValue {
			sealed := s30.ERABToBeSwitchedDLItemIEValue{}
			*s30.BridgeERABToBeSwitchedDLItemIEValueFieldIsOpaque(&sealed) = true
			*s30.BridgeERABToBeSwitchedDLItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s30.ERABToBeSwitchedDLItemIEValue {
				sealed := s30.ERABToBeSwitchedDLItemIEValue{}
				*s30.BridgeERABToBeSwitchedDLItemIEValueFieldId(&sealed) = s00.ProtocolIEID(23)
				*s30.BridgeERABToBeSwitchedDLItemIEValueFieldRowERABToBeSwitchedDLItem(&sealed) = new(s30.ERABToBeSwitchedDLItem)
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
		selectedAssert((*s17.ERABToBeSwitchedULItemIEValue)(nil))
		selectedAssert(&s17.ERABToBeSwitchedULItemIEValue{})
		opaque := func() s17.ERABToBeSwitchedULItemIEValue {
			sealed := s17.ERABToBeSwitchedULItemIEValue{}
			*s17.BridgeERABToBeSwitchedULItemIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeERABToBeSwitchedULItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.ERABToBeSwitchedULItemIEValue {
				sealed := s17.ERABToBeSwitchedULItemIEValue{}
				*s17.BridgeERABToBeSwitchedULItemIEValueFieldId(&sealed) = s00.ProtocolIEID(94)
				*s17.BridgeERABToBeSwitchedULItemIEValueFieldRowERABToBeSwitchedULItem(&sealed) = new(s17.ERABToBeSwitchedULItem)
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
		selectedAssert((*s29.ERABToBeUpdatedItemIEValue)(nil))
		selectedAssert(&s29.ERABToBeUpdatedItemIEValue{})
		opaque := func() s29.ERABToBeUpdatedItemIEValue {
			sealed := s29.ERABToBeUpdatedItemIEValue{}
			*s29.BridgeERABToBeUpdatedItemIEValueFieldIsOpaque(&sealed) = true
			*s29.BridgeERABToBeUpdatedItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s29.ERABToBeUpdatedItemIEValue {
				sealed := s29.ERABToBeUpdatedItemIEValue{}
				*s29.BridgeERABToBeUpdatedItemIEValueFieldId(&sealed) = s00.ProtocolIEID(342)
				*s29.BridgeERABToBeUpdatedItemIEValueFieldRowERABToBeUpdatedItem(&sealed) = new(s29.ERABToBeUpdatedItem)
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
		selectedAssert((*s17.ERABUsageReportItemIEValue)(nil))
		selectedAssert(&s17.ERABUsageReportItemIEValue{})
		opaque := func() s17.ERABUsageReportItemIEValue {
			sealed := s17.ERABUsageReportItemIEValue{}
			*s17.BridgeERABUsageReportItemIEValueFieldIsOpaque(&sealed) = true
			*s17.BridgeERABUsageReportItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s17.ERABUsageReportItemIEValue {
				sealed := s17.ERABUsageReportItemIEValue{}
				*s17.BridgeERABUsageReportItemIEValueFieldId(&sealed) = s00.ProtocolIEID(267)
				*s17.BridgeERABUsageReportItemIEValueFieldRowERABUsageReportItem(&sealed) = new(s17.ERABUsageReportItem)
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
		selectedAssert((*s28.ErrorIndicationIEValue)(nil))
		selectedAssert(&s28.ErrorIndicationIEValue{})
		opaque := func() s28.ErrorIndicationIEValue {
			sealed := s28.ErrorIndicationIEValue{}
			*s28.BridgeErrorIndicationIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeErrorIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.ErrorIndicationIEValue {
				sealed := s28.ErrorIndicationIEValue{}
				*s28.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s28.BridgeErrorIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ErrorIndicationIEValue {
				sealed := s28.ErrorIndicationIEValue{}
				*s28.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s28.BridgeErrorIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ErrorIndicationIEValue {
				sealed := s28.ErrorIndicationIEValue{}
				*s28.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s28.BridgeErrorIndicationIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ErrorIndicationIEValue {
				sealed := s28.ErrorIndicationIEValue{}
				*s28.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s28.BridgeErrorIndicationIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.ErrorIndicationIEValue {
				sealed := s28.ErrorIndicationIEValue{}
				*s28.BridgeErrorIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s28.BridgeErrorIndicationIEValueFieldRowSTMSI(&sealed) = new(s28.STMSI)
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
		selectedAssert((*s04.ExpectedUEActivityBehaviourExtIEsValue)(nil))
		selectedAssert(&s04.ExpectedUEActivityBehaviourExtIEsValue{})
		opaque := func() s04.ExpectedUEActivityBehaviourExtIEsValue {
			sealed := s04.ExpectedUEActivityBehaviourExtIEsValue{}
			*s04.BridgeExpectedUEActivityBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeExpectedUEActivityBehaviourExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ExpectedUEBehaviourExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ExpectedUEBehaviourExtIEsValue)(nil))
		selectedAssert(&s04.ExpectedUEBehaviourExtIEsValue{})
		opaque := func() s04.ExpectedUEBehaviourExtIEsValue {
			sealed := s04.ExpectedUEBehaviourExtIEsValue{}
			*s04.BridgeExpectedUEBehaviourExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeExpectedUEBehaviourExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("FiveGSTAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.FiveGSTAIExtIEsValue)(nil))
		selectedAssert(&s04.FiveGSTAIExtIEsValue{})
		opaque := func() s04.FiveGSTAIExtIEsValue {
			sealed := s04.FiveGSTAIExtIEsValue{}
			*s04.BridgeFiveGSTAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeFiveGSTAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ForbiddenLAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ForbiddenLAsItemExtIEsValue)(nil))
		selectedAssert(&s04.ForbiddenLAsItemExtIEsValue{})
		opaque := func() s04.ForbiddenLAsItemExtIEsValue {
			sealed := s04.ForbiddenLAsItemExtIEsValue{}
			*s04.BridgeForbiddenLAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeForbiddenLAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ForbiddenTAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ForbiddenTAsItemExtIEsValue)(nil))
		selectedAssert(&s04.ForbiddenTAsItemExtIEsValue{})
		opaque := func() s04.ForbiddenTAsItemExtIEsValue {
			sealed := s04.ForbiddenTAsItemExtIEsValue{}
			*s04.BridgeForbiddenTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeForbiddenTAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GBRQosInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GBRQosInformationExtIEsValue)(nil))
		selectedAssert(&s04.GBRQosInformationExtIEsValue{})
		opaque := func() s04.GBRQosInformationExtIEsValue {
			sealed := s04.GBRQosInformationExtIEsValue{}
			*s04.BridgeGBRQosInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGBRQosInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s04.GBRQosInformationExtIEsValue {
				sealed := s04.GBRQosInformationExtIEsValue{}
				*s04.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(255)
				*s04.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s04.GBRQosInformationExtIEsValue {
				sealed := s04.GBRQosInformationExtIEsValue{}
				*s04.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(256)
				*s04.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABMaximumBitrateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s04.GBRQosInformationExtIEsValue {
				sealed := s04.GBRQosInformationExtIEsValue{}
				*s04.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(257)
				*s04.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s04.GBRQosInformationExtIEsValue {
				sealed := s04.GBRQosInformationExtIEsValue{}
				*s04.BridgeGBRQosInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(258)
				*s04.BridgeGBRQosInformationExtIEsValueFieldRowExtendedERABGuaranteedBitrateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("GERANCellIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GERANCellIDExtIEsValue)(nil))
		selectedAssert(&s04.GERANCellIDExtIEsValue{})
		opaque := func() s04.GERANCellIDExtIEsValue {
			sealed := s04.GERANCellIDExtIEsValue{}
			*s04.BridgeGERANCellIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGERANCellIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GNBExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GNBExtIEsValue)(nil))
		selectedAssert(&s04.GNBExtIEsValue{})
		opaque := func() s04.GNBExtIEsValue {
			sealed := s04.GNBExtIEsValue{}
			*s04.BridgeGNBExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGNBExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GUMMEIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GUMMEIExtIEsValue)(nil))
		selectedAssert(&s04.GUMMEIExtIEsValue{})
		opaque := func() s04.GUMMEIExtIEsValue {
			sealed := s04.GUMMEIExtIEsValue{}
			*s04.BridgeGUMMEIExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGUMMEIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalENBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GlobalENBIDExtIEsValue)(nil))
		selectedAssert(&s04.GlobalENBIDExtIEsValue{})
		opaque := func() s04.GlobalENBIDExtIEsValue {
			sealed := s04.GlobalENBIDExtIEsValue{}
			*s04.BridgeGlobalENBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGlobalENBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalEnGNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GlobalEnGNBIDExtIEsValue)(nil))
		selectedAssert(&s04.GlobalEnGNBIDExtIEsValue{})
		opaque := func() s04.GlobalEnGNBIDExtIEsValue {
			sealed := s04.GlobalEnGNBIDExtIEsValue{}
			*s04.BridgeGlobalEnGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGlobalEnGNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("GlobalGNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.GlobalGNBIDExtIEsValue)(nil))
		selectedAssert(&s04.GlobalGNBIDExtIEsValue{})
		opaque := func() s04.GlobalGNBIDExtIEsValue {
			sealed := s04.GlobalGNBIDExtIEsValue{}
			*s04.BridgeGlobalGNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeGlobalGNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("HandoverCancelAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s22.HandoverCancelAcknowledgeIEValue)(nil))
		selectedAssert(&s22.HandoverCancelAcknowledgeIEValue{})
		opaque := func() s22.HandoverCancelAcknowledgeIEValue {
			sealed := s22.HandoverCancelAcknowledgeIEValue{}
			*s22.BridgeHandoverCancelAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeHandoverCancelAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.HandoverCancelAcknowledgeIEValue {
				sealed := s22.HandoverCancelAcknowledgeIEValue{}
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverCancelAcknowledgeIEValue {
				sealed := s22.HandoverCancelAcknowledgeIEValue{}
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverCancelAcknowledgeIEValue {
				sealed := s22.HandoverCancelAcknowledgeIEValue{}
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeHandoverCancelAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverCancelIEValue", func(t *testing.T) {
		selectedAssert((*s18.HandoverCancelIEValue)(nil))
		selectedAssert(&s18.HandoverCancelIEValue{})
		opaque := func() s18.HandoverCancelIEValue {
			sealed := s18.HandoverCancelIEValue{}
			*s18.BridgeHandoverCancelIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeHandoverCancelIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.HandoverCancelIEValue {
				sealed := s18.HandoverCancelIEValue{}
				*s18.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s18.BridgeHandoverCancelIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s18.HandoverCancelIEValue {
				sealed := s18.HandoverCancelIEValue{}
				*s18.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s18.BridgeHandoverCancelIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s18.HandoverCancelIEValue {
				sealed := s18.HandoverCancelIEValue{}
				*s18.BridgeHandoverCancelIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s18.BridgeHandoverCancelIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverCommandIEValue", func(t *testing.T) {
		selectedAssert((*s40.HandoverCommandIEValue)(nil))
		selectedAssert(&s40.HandoverCommandIEValue{})
		opaque := func() s40.HandoverCommandIEValue {
			sealed := s40.HandoverCommandIEValue{}
			*s40.BridgeHandoverCommandIEValueFieldIsOpaque(&sealed) = true
			*s40.BridgeHandoverCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s40.BridgeHandoverCommandIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s40.BridgeHandoverCommandIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s40.BridgeHandoverCommandIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(135)
				*s40.BridgeHandoverCommandIEValueFieldRowNASSecurityParametersfromEUTRAN(&sealed) = new(s00.NASSecurityParametersfromEUTRAN)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(12)
				*s40.BridgeHandoverCommandIEValueFieldRowERABSubjecttoDataForwardingList(&sealed) = new(s17.ERABSubjecttoDataForwardingList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(13)
				*s40.BridgeHandoverCommandIEValueFieldRowERABtoReleaseListHOCmd(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(123)
				*s40.BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainer(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(139)
				*s40.BridgeHandoverCommandIEValueFieldRowTargetToSourceTransparentContainerSecondary(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s40.HandoverCommandIEValue {
				sealed := s40.HandoverCommandIEValue{}
				*s40.BridgeHandoverCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s40.BridgeHandoverCommandIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverFailureIEValue", func(t *testing.T) {
		selectedAssert((*s22.HandoverFailureIEValue)(nil))
		selectedAssert(&s22.HandoverFailureIEValue{})
		opaque := func() s22.HandoverFailureIEValue {
			sealed := s22.HandoverFailureIEValue{}
			*s22.BridgeHandoverFailureIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeHandoverFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.HandoverFailureIEValue {
				sealed := s22.HandoverFailureIEValue{}
				*s22.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeHandoverFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverFailureIEValue {
				sealed := s22.HandoverFailureIEValue{}
				*s22.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeHandoverFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverFailureIEValue {
				sealed := s22.HandoverFailureIEValue{}
				*s22.BridgeHandoverFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeHandoverFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverNotifyIEValue", func(t *testing.T) {
		selectedAssert((*s35.HandoverNotifyIEValue)(nil))
		selectedAssert(&s35.HandoverNotifyIEValue{})
		opaque := func() s35.HandoverNotifyIEValue {
			sealed := s35.HandoverNotifyIEValue{}
			*s35.BridgeHandoverNotifyIEValueFieldIsOpaque(&sealed) = true
			*s35.BridgeHandoverNotifyIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s35.BridgeHandoverNotifyIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s35.BridgeHandoverNotifyIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s35.BridgeHandoverNotifyIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s35.BridgeHandoverNotifyIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s35.BridgeHandoverNotifyIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s35.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s35.BridgeHandoverNotifyIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s35.BridgeHandoverNotifyIEValueFieldRowPSCellInformation(&sealed) = new(s20.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(320)
				*s35.BridgeHandoverNotifyIEValueFieldRowNotifySourceeNB(&sealed) = new(s00.NotifySourceeNB)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.HandoverNotifyIEValue {
				sealed := s35.HandoverNotifyIEValue{}
				*s35.BridgeHandoverNotifyIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s35.BridgeHandoverNotifyIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverPreparationFailureIEValue", func(t *testing.T) {
		selectedAssert((*s22.HandoverPreparationFailureIEValue)(nil))
		selectedAssert(&s22.HandoverPreparationFailureIEValue{})
		opaque := func() s22.HandoverPreparationFailureIEValue {
			sealed := s22.HandoverPreparationFailureIEValue{}
			*s22.BridgeHandoverPreparationFailureIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeHandoverPreparationFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.HandoverPreparationFailureIEValue {
				sealed := s22.HandoverPreparationFailureIEValue{}
				*s22.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeHandoverPreparationFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverPreparationFailureIEValue {
				sealed := s22.HandoverPreparationFailureIEValue{}
				*s22.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s22.BridgeHandoverPreparationFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverPreparationFailureIEValue {
				sealed := s22.HandoverPreparationFailureIEValue{}
				*s22.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeHandoverPreparationFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.HandoverPreparationFailureIEValue {
				sealed := s22.HandoverPreparationFailureIEValue{}
				*s22.BridgeHandoverPreparationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeHandoverPreparationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequestAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s39.HandoverRequestAcknowledgeIEValue)(nil))
		selectedAssert(&s39.HandoverRequestAcknowledgeIEValue{})
		opaque := func() s39.HandoverRequestAcknowledgeIEValue {
			sealed := s39.HandoverRequestAcknowledgeIEValue{}
			*s39.BridgeHandoverRequestAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeHandoverRequestAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(18)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowERABAdmittedList(&sealed) = new(s15.ERABAdmittedList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(19)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowERABFailedToSetupListHOReqAck(&sealed) = new(s16.ERABFailedtoSetupListHOReqAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(123)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowTargetToSourceTransparentContainer(&sealed) = new(s00.TargetToSourceTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.HandoverRequestAcknowledgeIEValue {
				sealed := s39.HandoverRequestAcknowledgeIEValue{}
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
				*s39.BridgeHandoverRequestAcknowledgeIEValueFieldRowCEModeBSupportIndicator(&sealed) = new(s00.CEModeBSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequestIEValue", func(t *testing.T) {
		selectedAssert((*s48.HandoverRequestIEValue)(nil))
		selectedAssert(&s48.HandoverRequestIEValue{})
		opaque := func() s48.HandoverRequestIEValue {
			sealed := s48.HandoverRequestIEValue{}
			*s48.BridgeHandoverRequestIEValueFieldIsOpaque(&sealed) = true
			*s48.BridgeHandoverRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s48.BridgeHandoverRequestIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s48.BridgeHandoverRequestIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s48.BridgeHandoverRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(53)
				*s48.BridgeHandoverRequestIEValueFieldRowERABToBeSetupListHOReq(&sealed) = new(s30.ERABToBeSetupListHOReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
				*s48.BridgeHandoverRequestIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s48.BridgeHandoverRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s37.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s48.BridgeHandoverRequestIEValueFieldRowHandoverRestrictionList(&sealed) = new(s42.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s48.BridgeHandoverRequestIEValueFieldRowTraceActivation(&sealed) = new(s47.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s48.BridgeHandoverRequestIEValueFieldRowRequestType(&sealed) = new(s26.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s48.BridgeHandoverRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s48.BridgeHandoverRequestIEValueFieldRowSecurityContext(&sealed) = new(s28.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(136)
				*s48.BridgeHandoverRequestIEValueFieldRowNASSecurityParameterstoEUTRAN(&sealed) = new(s00.NASSecurityParameterstoEUTRAN)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s48.BridgeHandoverRequestIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s48.BridgeHandoverRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s48.BridgeHandoverRequestIEValueFieldRowGUMMEIID(&sealed) = new(s18.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
				*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = new(s00.ManagementBasedMDTAllowed)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
				*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s48.BridgeHandoverRequestIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
				*s48.BridgeHandoverRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = new(s18.ExpectedUEBehaviour)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s48.BridgeHandoverRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s20.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s48.BridgeHandoverRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s48.BridgeHandoverRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s46.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s48.BridgeHandoverRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s37.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s48.BridgeHandoverRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s48.BridgeHandoverRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s48.BridgeHandoverRequestIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s48.BridgeHandoverRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s48.BridgeHandoverRequestIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s48.BridgeHandoverRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s48.BridgeHandoverRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s48.BridgeHandoverRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s48.BridgeHandoverRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s19.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s48.BridgeHandoverRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s19.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s48.BridgeHandoverRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s24.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s48.BridgeHandoverRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s48.BridgeHandoverRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRequiredIEValue", func(t *testing.T) {
		selectedAssert((*s34.HandoverRequiredIEValue)(nil))
		selectedAssert(&s34.HandoverRequiredIEValue{})
		opaque := func() s34.HandoverRequiredIEValue {
			sealed := s34.HandoverRequiredIEValue{}
			*s34.BridgeHandoverRequiredIEValueFieldIsOpaque(&sealed) = true
			*s34.BridgeHandoverRequiredIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s34.BridgeHandoverRequiredIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s34.BridgeHandoverRequiredIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s34.BridgeHandoverRequiredIEValueFieldRowHandoverType(&sealed) = new(s00.HandoverType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s34.BridgeHandoverRequiredIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(4)
				*s34.BridgeHandoverRequiredIEValueFieldRowTargetID(&sealed) = new(s34.TargetID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s34.BridgeHandoverRequiredIEValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(125)
				*s34.BridgeHandoverRequiredIEValueFieldRowSRVCCHOIndication(&sealed) = new(s00.SRVCCHOIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
				*s34.BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(138)
				*s34.BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainerSecondary(&sealed) = new(s00.SourceToTargetTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(132)
				*s34.BridgeHandoverRequiredIEValueFieldRowMSClassmark2(&sealed) = new(s00.MSClassmark2)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(133)
				*s34.BridgeHandoverRequiredIEValueFieldRowMSClassmark3(&sealed) = new(s00.MSClassmark3)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s34.BridgeHandoverRequiredIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s34.BridgeHandoverRequiredIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.HandoverRequiredIEValue {
				sealed := s34.HandoverRequiredIEValue{}
				*s34.BridgeHandoverRequiredIEValueFieldId(&sealed) = s00.ProtocolIEID(150)
				*s34.BridgeHandoverRequiredIEValueFieldRowPSServiceNotAvailable(&sealed) = new(s00.PSServiceNotAvailable)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverRestrictionListExtIEsValue", func(t *testing.T) {
		selectedAssert((*s42.HandoverRestrictionListExtIEsValue)(nil))
		selectedAssert(&s42.HandoverRestrictionListExtIEsValue{})
		opaque := func() s42.HandoverRestrictionListExtIEsValue {
			sealed := s42.HandoverRestrictionListExtIEsValue{}
			*s42.BridgeHandoverRestrictionListExtIEsValueFieldIsOpaque(&sealed) = true
			*s42.BridgeHandoverRestrictionListExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(261)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictioninEPSasSecondaryRAT(&sealed) = new(s00.NRrestrictioninEPSasSecondaryRAT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(270)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowUnlicensedSpectrumRestriction(&sealed) = new(s00.UnlicensedSpectrumRestriction)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(282)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowCNTypeRestrictions(&sealed) = new(s14.CNTypeRestrictions)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(287)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictionin5GS(&sealed) = new(s00.NRrestrictionin5GS)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(290)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowLastNGRANPLMNIdentity(&sealed) = new(s00.PLMNidentity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.HandoverRestrictionListExtIEsValue {
				sealed := s42.HandoverRestrictionListExtIEsValue{}
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(336)
				*s42.BridgeHandoverRestrictionListExtIEsValueFieldRowRATRestrictions(&sealed) = new(s20.RATRestrictions)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("HandoverSuccessIEValue", func(t *testing.T) {
		selectedAssert((*s09.HandoverSuccessIEValue)(nil))
		selectedAssert(&s09.HandoverSuccessIEValue{})
		opaque := func() s09.HandoverSuccessIEValue {
			sealed := s09.HandoverSuccessIEValue{}
			*s09.BridgeHandoverSuccessIEValueFieldIsOpaque(&sealed) = true
			*s09.BridgeHandoverSuccessIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s09.HandoverSuccessIEValue {
				sealed := s09.HandoverSuccessIEValue{}
				*s09.BridgeHandoverSuccessIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s09.BridgeHandoverSuccessIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s09.HandoverSuccessIEValue {
				sealed := s09.HandoverSuccessIEValue{}
				*s09.BridgeHandoverSuccessIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s09.BridgeHandoverSuccessIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ImmediateMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s47.ImmediateMDTExtIEsValue)(nil))
		selectedAssert(&s47.ImmediateMDTExtIEsValue{})
		opaque := func() s47.ImmediateMDTExtIEsValue {
			sealed := s47.ImmediateMDTExtIEsValue{}
			*s47.BridgeImmediateMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s47.BridgeImmediateMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(171)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowM3Configuration(&sealed) = new(s19.M3Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(172)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowM4Configuration(&sealed) = new(s19.M4Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(173)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowM5Configuration(&sealed) = new(s19.M5Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(174)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowMDTLocationInfo(&sealed) = new(s00.MDTLocationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(220)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowM6Configuration(&sealed) = new(s19.M6Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(221)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowM7Configuration(&sealed) = new(s19.M7Configuration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(284)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(&sealed) = new(s14.BluetoothMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(285)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowWLANMeasurementConfiguration(&sealed) = new(s47.WLANMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.ImmediateMDTExtIEsValue {
				sealed := s47.ImmediateMDTExtIEsValue{}
				*s47.BridgeImmediateMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(345)
				*s47.BridgeImmediateMDTExtIEsValueFieldRowSensorMeasurementConfiguration(&sealed) = new(s30.SensorMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InformationForCECapableUEsExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.InformationForCECapableUEsExtIEsValue)(nil))
		selectedAssert(&s04.InformationForCECapableUEsExtIEsValue{})
		opaque := func() s04.InformationForCECapableUEsExtIEsValue {
			sealed := s04.InformationForCECapableUEsExtIEsValue{}
			*s04.BridgeInformationForCECapableUEsExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeInformationForCECapableUEsExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InformationOnRecommendedCellsAndENBsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue)(nil))
		selectedAssert(&s04.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue{})
		opaque := func() s04.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue {
			sealed := s04.InformationOnRecommendedCellsAndENBsForPagingExtIEsValue{}
			*s04.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InitialContextSetupFailureIEValue", func(t *testing.T) {
		selectedAssert((*s22.InitialContextSetupFailureIEValue)(nil))
		selectedAssert(&s22.InitialContextSetupFailureIEValue{})
		opaque := func() s22.InitialContextSetupFailureIEValue {
			sealed := s22.InitialContextSetupFailureIEValue{}
			*s22.BridgeInitialContextSetupFailureIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeInitialContextSetupFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.InitialContextSetupFailureIEValue {
				sealed := s22.InitialContextSetupFailureIEValue{}
				*s22.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s22.BridgeInitialContextSetupFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.InitialContextSetupFailureIEValue {
				sealed := s22.InitialContextSetupFailureIEValue{}
				*s22.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s22.BridgeInitialContextSetupFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.InitialContextSetupFailureIEValue {
				sealed := s22.InitialContextSetupFailureIEValue{}
				*s22.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s22.BridgeInitialContextSetupFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s22.InitialContextSetupFailureIEValue {
				sealed := s22.InitialContextSetupFailureIEValue{}
				*s22.BridgeInitialContextSetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeInitialContextSetupFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialContextSetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s48.InitialContextSetupRequestIEValue)(nil))
		selectedAssert(&s48.InitialContextSetupRequestIEValue{})
		opaque := func() s48.InitialContextSetupRequestIEValue {
			sealed := s48.InitialContextSetupRequestIEValue{}
			*s48.BridgeInitialContextSetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s48.BridgeInitialContextSetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(24)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowERABToBeSetupListCtxtSUReq(&sealed) = new(s29.ERABToBeSetupListCtxtSUReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s37.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowSecurityKey(&sealed) = new(s00.SecurityKey)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowTraceActivation(&sealed) = new(s47.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowHandoverRestrictionList(&sealed) = new(s42.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowCSFallbackIndicator(&sealed) = new(s00.CSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowRegisteredLAI(&sealed) = new(s18.LAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowGUMMEIID(&sealed) = new(s18.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = new(s00.ManagementBasedMDTAllowed)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = new(s00.AdditionalCSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = new(s18.ExpectedUEBehaviour)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s20.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s46.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s37.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s19.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s19.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s24.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(354)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowCoarseUELocation(&sealed) = new(s00.CoarseUELocation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.InitialContextSetupRequestIEValue {
				sealed := s48.InitialContextSetupRequestIEValue{}
				*s48.BridgeInitialContextSetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s48.BridgeInitialContextSetupRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialContextSetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s39.InitialContextSetupResponseIEValue)(nil))
		selectedAssert(&s39.InitialContextSetupResponseIEValue{})
		opaque := func() s39.InitialContextSetupResponseIEValue {
			sealed := s39.InitialContextSetupResponseIEValue{}
			*s39.BridgeInitialContextSetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s39.BridgeInitialContextSetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.InitialContextSetupResponseIEValue {
				sealed := s39.InitialContextSetupResponseIEValue{}
				*s39.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s39.BridgeInitialContextSetupResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.InitialContextSetupResponseIEValue {
				sealed := s39.InitialContextSetupResponseIEValue{}
				*s39.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s39.BridgeInitialContextSetupResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.InitialContextSetupResponseIEValue {
				sealed := s39.InitialContextSetupResponseIEValue{}
				*s39.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(51)
				*s39.BridgeInitialContextSetupResponseIEValueFieldRowERABSetupListCtxtSURes(&sealed) = new(s17.ERABSetupListCtxtSURes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.InitialContextSetupResponseIEValue {
				sealed := s39.InitialContextSetupResponseIEValue{}
				*s39.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(48)
				*s39.BridgeInitialContextSetupResponseIEValueFieldRowERABFailedToSetupListCtxtSURes(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.InitialContextSetupResponseIEValue {
				sealed := s39.InitialContextSetupResponseIEValue{}
				*s39.BridgeInitialContextSetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s39.BridgeInitialContextSetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitialUEMessageIEValue", func(t *testing.T) {
		selectedAssert((*s35.InitialUEMessageIEValue)(nil))
		selectedAssert(&s35.InitialUEMessageIEValue{})
		opaque := func() s35.InitialUEMessageIEValue {
			sealed := s35.InitialUEMessageIEValue{}
			*s35.BridgeInitialUEMessageIEValueFieldIsOpaque(&sealed) = true
			*s35.BridgeInitialUEMessageIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s35.BridgeInitialUEMessageIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s35.BridgeInitialUEMessageIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s35.BridgeInitialUEMessageIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s35.BridgeInitialUEMessageIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(134)
				*s35.BridgeInitialUEMessageIEValueFieldRowRRCEstablishmentCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s35.BridgeInitialUEMessageIEValueFieldRowSTMSI(&sealed) = new(s28.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s35.BridgeInitialUEMessageIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIID(&sealed) = new(s18.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s35.BridgeInitialUEMessageIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
				*s35.BridgeInitialUEMessageIEValueFieldRowGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(160)
				*s35.BridgeInitialUEMessageIEValueFieldRowRelayNodeIndicator(&sealed) = new(s00.RelayNodeIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIType(&sealed) = new(s00.GUMMEIType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s35.BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s35.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
				*s35.BridgeInitialUEMessageIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s35.BridgeInitialUEMessageIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s35.BridgeInitialUEMessageIEValueFieldRowMMEGroupID(&sealed) = new(s00.MMEGroupID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s35.BridgeInitialUEMessageIEValueFieldRowUEUsageType(&sealed) = new(s00.UEUsageType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
				*s35.BridgeInitialUEMessageIEValueFieldRowCEModeBSupportIndicator(&sealed) = new(s00.CEModeBSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(246)
				*s35.BridgeInitialUEMessageIEValueFieldRowDCNID(&sealed) = new(s00.DCNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(250)
				*s35.BridgeInitialUEMessageIEValueFieldRowCoverageLevel(&sealed) = new(s00.CoverageLevel)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
				*s35.BridgeInitialUEMessageIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = new(s00.UEApplicationLayerMeasurementCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(281)
				*s35.BridgeInitialUEMessageIEValueFieldRowEDTSession(&sealed) = new(s00.EDTSession)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(302)
				*s35.BridgeInitialUEMessageIEValueFieldRowIABNodeIndication(&sealed) = new(s00.IABNodeIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s35.BridgeInitialUEMessageIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(353)
				*s35.BridgeInitialUEMessageIEValueFieldRowCoarseUELocationRequested(&sealed) = new(s00.CoarseUELocationRequested)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InitiatingValue", func(t *testing.T) {
		selectedAssert((*s51.InitiatingValue)(nil))
		selectedAssert(&s51.InitiatingValue{})
		opaque := func() s51.InitiatingValue {
			sealed := s51.InitiatingValue{}
			*s51.BridgeInitiatingValueFieldIsOpaque(&sealed) = true
			*s51.BridgeInitiatingValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s51.BridgeInitiatingValueFieldBodyHandoverRequired(&sealed) = new(s34.HandoverRequired)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s51.BridgeInitiatingValueFieldBodyHandoverRequest(&sealed) = new(s49.HandoverRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(2)
				*s51.BridgeInitiatingValueFieldBodyHandoverNotify(&sealed) = new(s35.HandoverNotify)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s51.BridgeInitiatingValueFieldBodyPathSwitchRequest(&sealed) = new(s41.PathSwitchRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s51.BridgeInitiatingValueFieldBodyHandoverCancel(&sealed) = new(s25.HandoverCancel)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s51.BridgeInitiatingValueFieldBodyERABSetupRequest(&sealed) = new(s40.ERABSetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s51.BridgeInitiatingValueFieldBodyERABModifyRequest(&sealed) = new(s40.ERABModifyRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s51.BridgeInitiatingValueFieldBodyERABReleaseCommand(&sealed) = new(s39.ERABReleaseCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(8)
				*s51.BridgeInitiatingValueFieldBodyERABReleaseIndication(&sealed) = new(s46.ERABReleaseIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s51.BridgeInitiatingValueFieldBodyInitialContextSetupRequest(&sealed) = new(s49.InitialContextSetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(10)
				*s51.BridgeInitiatingValueFieldBodyPaging(&sealed) = new(s49.Paging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(11)
				*s51.BridgeInitiatingValueFieldBodyDownlinkNASTransport(&sealed) = new(s42.DownlinkNASTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(12)
				*s51.BridgeInitiatingValueFieldBodyInitialUEMessage(&sealed) = new(s35.InitialUEMessage)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(13)
				*s51.BridgeInitiatingValueFieldBodyUplinkNASTransport(&sealed) = new(s44.UplinkNASTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s51.BridgeInitiatingValueFieldBodyReset(&sealed) = new(s36.Reset)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(15)
				*s51.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = new(s28.ErrorIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(16)
				*s51.BridgeInitiatingValueFieldBodyNASNonDeliveryIndication(&sealed) = new(s25.NASNonDeliveryIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s51.BridgeInitiatingValueFieldBodyS1SetupRequest(&sealed) = new(s44.S1SetupRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(18)
				*s51.BridgeInitiatingValueFieldBodyUEContextReleaseRequest(&sealed) = new(s43.UEContextReleaseRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(19)
				*s51.BridgeInitiatingValueFieldBodyDownlinkS1cdma2000tunnelling(&sealed) = new(s40.DownlinkS1cdma2000tunnelling)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(20)
				*s51.BridgeInitiatingValueFieldBodyUplinkS1cdma2000tunnelling(&sealed) = new(s44.UplinkS1cdma2000tunnelling)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s51.BridgeInitiatingValueFieldBodyUEContextModificationRequest(&sealed) = new(s47.UEContextModificationRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(22)
				*s51.BridgeInitiatingValueFieldBodyUECapabilityInfoIndication(&sealed) = new(s36.UECapabilityInfoIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s51.BridgeInitiatingValueFieldBodyUEContextReleaseCommand(&sealed) = new(s37.UEContextReleaseCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(24)
				*s51.BridgeInitiatingValueFieldBodyENBStatusTransfer(&sealed) = new(s24.ENBStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(25)
				*s51.BridgeInitiatingValueFieldBodyMMEStatusTransfer(&sealed) = new(s25.MMEStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(26)
				*s51.BridgeInitiatingValueFieldBodyDeactivateTrace(&sealed) = new(s15.DeactivateTrace)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(27)
				*s51.BridgeInitiatingValueFieldBodyTraceStart(&sealed) = new(s49.TraceStart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(28)
				*s51.BridgeInitiatingValueFieldBodyTraceFailureIndication(&sealed) = new(s35.TraceFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s51.BridgeInitiatingValueFieldBodyENBConfigurationUpdate(&sealed) = new(s43.ENBConfigurationUpdate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s51.BridgeInitiatingValueFieldBodyMMEConfigurationUpdate(&sealed) = new(s43.MMEConfigurationUpdate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(31)
				*s51.BridgeInitiatingValueFieldBodyLocationReportingControl(&sealed) = new(s26.LocationReportingControl)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(32)
				*s51.BridgeInitiatingValueFieldBodyLocationReportingFailureIndication(&sealed) = new(s25.LocationReportingFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(33)
				*s51.BridgeInitiatingValueFieldBodyLocationReport(&sealed) = new(s33.LocationReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(34)
				*s51.BridgeInitiatingValueFieldBodyOverloadStart(&sealed) = new(s41.OverloadStart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(35)
				*s51.BridgeInitiatingValueFieldBodyOverloadStop(&sealed) = new(s41.OverloadStop)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s51.BridgeInitiatingValueFieldBodyWriteReplaceWarningRequest(&sealed) = new(s50.WriteReplaceWarningRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(37)
				*s51.BridgeInitiatingValueFieldBodyENBDirectInformationTransfer(&sealed) = new(s34.ENBDirectInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(38)
				*s51.BridgeInitiatingValueFieldBodyMMEDirectInformationTransfer(&sealed) = new(s34.MMEDirectInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(39)
				*s51.BridgeInitiatingValueFieldBodyPrivateMessage(&sealed) = new(s26.PrivateMessage)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(40)
				*s51.BridgeInitiatingValueFieldBodyENBConfigurationTransfer(&sealed) = new(s51.ENBConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(41)
				*s51.BridgeInitiatingValueFieldBodyMMEConfigurationTransfer(&sealed) = new(s51.MMEConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(42)
				*s51.BridgeInitiatingValueFieldBodyCellTrafficTrace(&sealed) = new(s21.CellTrafficTrace)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(43)
				*s51.BridgeInitiatingValueFieldBodyKillRequest(&sealed) = new(s33.KillRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(44)
				*s51.BridgeInitiatingValueFieldBodyDownlinkUEAssociatedLPPaTransport(&sealed) = new(s15.DownlinkUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(45)
				*s51.BridgeInitiatingValueFieldBodyUplinkUEAssociatedLPPaTransport(&sealed) = new(s44.UplinkUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(46)
				*s51.BridgeInitiatingValueFieldBodyDownlinkNonUEAssociatedLPPaTransport(&sealed) = new(s15.DownlinkNonUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(47)
				*s51.BridgeInitiatingValueFieldBodyUplinkNonUEAssociatedLPPaTransport(&sealed) = new(s44.UplinkNonUEAssociatedLPPaTransport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s51.BridgeInitiatingValueFieldBodyUERadioCapabilityMatchRequest(&sealed) = new(s36.UERadioCapabilityMatchRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(49)
				*s51.BridgeInitiatingValueFieldBodyPWSRestartIndication(&sealed) = new(s44.PWSRestartIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(50)
				*s51.BridgeInitiatingValueFieldBodyERABModificationIndication(&sealed) = new(s46.ERABModificationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(51)
				*s51.BridgeInitiatingValueFieldBodyPWSFailureIndication(&sealed) = new(s42.PWSFailureIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(52)
				*s51.BridgeInitiatingValueFieldBodyRerouteNASRequest(&sealed) = new(s26.RerouteNASRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s51.BridgeInitiatingValueFieldBodyUEContextModificationIndication(&sealed) = new(s36.UEContextModificationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(54)
				*s51.BridgeInitiatingValueFieldBodyConnectionEstablishmentIndication(&sealed) = new(s31.ConnectionEstablishmentIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s51.BridgeInitiatingValueFieldBodyUEContextSuspendRequest(&sealed) = new(s46.UEContextSuspendRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s51.BridgeInitiatingValueFieldBodyUEContextResumeRequest(&sealed) = new(s38.UEContextResumeRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(57)
				*s51.BridgeInitiatingValueFieldBodyNASDeliveryIndication(&sealed) = new(s19.NASDeliveryIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(58)
				*s51.BridgeInitiatingValueFieldBodyRetrieveUEInformation(&sealed) = new(s28.RetrieveUEInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(59)
				*s51.BridgeInitiatingValueFieldBodyUEInformationTransfer(&sealed) = new(s36.UEInformationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(60)
				*s51.BridgeInitiatingValueFieldBodyENBCPRelocationIndication(&sealed) = new(s37.ENBCPRelocationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(61)
				*s51.BridgeInitiatingValueFieldBodyMMECPRelocationIndication(&sealed) = new(s19.MMECPRelocationIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(62)
				*s51.BridgeInitiatingValueFieldBodySecondaryRATDataUsageReport(&sealed) = new(s46.SecondaryRATDataUsageReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s51.BridgeInitiatingValueFieldBodyUERadioCapabilityIDMappingRequest(&sealed) = new(s36.UERadioCapabilityIDMappingRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(64)
				*s51.BridgeInitiatingValueFieldBodyHandoverSuccess(&sealed) = new(s18.HandoverSuccess)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(65)
				*s51.BridgeInitiatingValueFieldBodyENBEarlyStatusTransfer(&sealed) = new(s38.ENBEarlyStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(66)
				*s51.BridgeInitiatingValueFieldBodyMMEEarlyStatusTransfer(&sealed) = new(s38.MMEEarlyStatusTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.InitiatingValue {
				sealed := s51.InitiatingValue{}
				*s51.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s51.BridgeInitiatingValueFieldBodyS1RemovalRequest(&sealed) = new(s26.S1RemovalRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("InterSystemMeasurementItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.InterSystemMeasurementItemExtIEsValue)(nil))
		selectedAssert(&s04.InterSystemMeasurementItemExtIEsValue{})
		opaque := func() s04.InterSystemMeasurementItemExtIEsValue {
			sealed := s04.InterSystemMeasurementItemExtIEsValue{}
			*s04.BridgeInterSystemMeasurementItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeInterSystemMeasurementItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("InterSystemMeasurementParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.InterSystemMeasurementParametersExtIEsValue)(nil))
		selectedAssert(&s04.InterSystemMeasurementParametersExtIEsValue{})
		opaque := func() s04.InterSystemMeasurementParametersExtIEsValue {
			sealed := s04.InterSystemMeasurementParametersExtIEsValue{}
			*s04.BridgeInterSystemMeasurementParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeInterSystemMeasurementParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("IntersystemMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.IntersystemMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s04.IntersystemMeasurementConfigurationExtIEsValue{})
		opaque := func() s04.IntersystemMeasurementConfigurationExtIEsValue {
			sealed := s04.IntersystemMeasurementConfigurationExtIEsValue{}
			*s04.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeIntersystemMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("KillRequestIEValue", func(t *testing.T) {
		selectedAssert((*s33.KillRequestIEValue)(nil))
		selectedAssert(&s33.KillRequestIEValue{})
		opaque := func() s33.KillRequestIEValue {
			sealed := s33.KillRequestIEValue{}
			*s33.BridgeKillRequestIEValueFieldIsOpaque(&sealed) = true
			*s33.BridgeKillRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s33.KillRequestIEValue {
				sealed := s33.KillRequestIEValue{}
				*s33.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s33.BridgeKillRequestIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.KillRequestIEValue {
				sealed := s33.KillRequestIEValue{}
				*s33.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s33.BridgeKillRequestIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.KillRequestIEValue {
				sealed := s33.KillRequestIEValue{}
				*s33.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(113)
				*s33.BridgeKillRequestIEValueFieldRowWarningAreaList(&sealed) = new(s32.WarningAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.KillRequestIEValue {
				sealed := s33.KillRequestIEValue{}
				*s33.BridgeKillRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(191)
				*s33.BridgeKillRequestIEValueFieldRowKillAllWarningMessages(&sealed) = new(s00.KillAllWarningMessages)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("KillResponseIEValue", func(t *testing.T) {
		selectedAssert((*s32.KillResponseIEValue)(nil))
		selectedAssert(&s32.KillResponseIEValue{})
		opaque := func() s32.KillResponseIEValue {
			sealed := s32.KillResponseIEValue{}
			*s32.BridgeKillResponseIEValueFieldIsOpaque(&sealed) = true
			*s32.BridgeKillResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s32.KillResponseIEValue {
				sealed := s32.KillResponseIEValue{}
				*s32.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s32.BridgeKillResponseIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.KillResponseIEValue {
				sealed := s32.KillResponseIEValue{}
				*s32.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s32.BridgeKillResponseIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.KillResponseIEValue {
				sealed := s32.KillResponseIEValue{}
				*s32.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(141)
				*s32.BridgeKillResponseIEValueFieldRowBroadcastCancelledAreaList(&sealed) = new(s32.BroadcastCancelledAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.KillResponseIEValue {
				sealed := s32.KillResponseIEValue{}
				*s32.BridgeKillResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s32.BridgeKillResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.LAIExtIEsValue)(nil))
		selectedAssert(&s04.LAIExtIEsValue{})
		opaque := func() s04.LAIExtIEsValue {
			sealed := s04.LAIExtIEsValue{}
			*s04.BridgeLAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeLAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LTENTNTAIInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.LTENTNTAIInformationExtIEsValue)(nil))
		selectedAssert(&s04.LTENTNTAIInformationExtIEsValue{})
		opaque := func() s04.LTENTNTAIInformationExtIEsValue {
			sealed := s04.LTENTNTAIInformationExtIEsValue{}
			*s04.BridgeLTENTNTAIInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeLTENTNTAIInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LastVisitedEUTRANCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s41.LastVisitedEUTRANCellInformationExtIEsValue)(nil))
		selectedAssert(&s41.LastVisitedEUTRANCellInformationExtIEsValue{})
		opaque := func() s41.LastVisitedEUTRANCellInformationExtIEsValue {
			sealed := s41.LastVisitedEUTRANCellInformationExtIEsValue{}
			*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s41.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(167)
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowTimeUEStayedInCellEnhancedGranularity(&sealed) = new(s00.TimeUEStayedInCellEnhancedGranularity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s41.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(168)
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowHOCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.LastVisitedEUTRANCellInformationExtIEsValue {
				sealed := s41.LastVisitedEUTRANCellInformationExtIEsValue{}
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(329)
				*s41.BridgeLastVisitedEUTRANCellInformationExtIEsValueFieldRowLastVisitedPSCellList(&sealed) = new(s20.LastVisitedPSCellList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LastVisitedPSCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.LastVisitedPSCellInformationExtIEsValue)(nil))
		selectedAssert(&s04.LastVisitedPSCellInformationExtIEsValue{})
		opaque := func() s04.LastVisitedPSCellInformationExtIEsValue {
			sealed := s04.LastVisitedPSCellInformationExtIEsValue{}
			*s04.BridgeLastVisitedPSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeLastVisitedPSCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ListeningSubframePatternExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.ListeningSubframePatternExtIEsValue)(nil))
		selectedAssert(&s04.ListeningSubframePatternExtIEsValue{})
		opaque := func() s04.ListeningSubframePatternExtIEsValue {
			sealed := s04.ListeningSubframePatternExtIEsValue{}
			*s04.BridgeListeningSubframePatternExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeListeningSubframePatternExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LocationReportIEValue", func(t *testing.T) {
		selectedAssert((*s31.LocationReportIEValue)(nil))
		selectedAssert(&s31.LocationReportIEValue{})
		opaque := func() s31.LocationReportIEValue {
			sealed := s31.LocationReportIEValue{}
			*s31.BridgeLocationReportIEValueFieldIsOpaque(&sealed) = true
			*s31.BridgeLocationReportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s31.BridgeLocationReportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s31.BridgeLocationReportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s31.BridgeLocationReportIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s31.BridgeLocationReportIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s31.BridgeLocationReportIEValueFieldRowRequestType(&sealed) = new(s26.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s31.BridgeLocationReportIEValueFieldRowPSCellInformation(&sealed) = new(s20.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.LocationReportIEValue {
				sealed := s31.LocationReportIEValue{}
				*s31.BridgeLocationReportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s31.BridgeLocationReportIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LocationReportingControlIEValue", func(t *testing.T) {
		selectedAssert((*s26.LocationReportingControlIEValue)(nil))
		selectedAssert(&s26.LocationReportingControlIEValue{})
		opaque := func() s26.LocationReportingControlIEValue {
			sealed := s26.LocationReportingControlIEValue{}
			*s26.BridgeLocationReportingControlIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeLocationReportingControlIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.LocationReportingControlIEValue {
				sealed := s26.LocationReportingControlIEValue{}
				*s26.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s26.BridgeLocationReportingControlIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.LocationReportingControlIEValue {
				sealed := s26.LocationReportingControlIEValue{}
				*s26.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s26.BridgeLocationReportingControlIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s26.LocationReportingControlIEValue {
				sealed := s26.LocationReportingControlIEValue{}
				*s26.BridgeLocationReportingControlIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s26.BridgeLocationReportingControlIEValueFieldRowRequestType(&sealed) = new(s26.RequestType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LocationReportingFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s18.LocationReportingFailureIndicationIEValue)(nil))
		selectedAssert(&s18.LocationReportingFailureIndicationIEValue{})
		opaque := func() s18.LocationReportingFailureIndicationIEValue {
			sealed := s18.LocationReportingFailureIndicationIEValue{}
			*s18.BridgeLocationReportingFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s18.BridgeLocationReportingFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s18.LocationReportingFailureIndicationIEValue {
				sealed := s18.LocationReportingFailureIndicationIEValue{}
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s18.LocationReportingFailureIndicationIEValue {
				sealed := s18.LocationReportingFailureIndicationIEValue{}
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s18.LocationReportingFailureIndicationIEValue {
				sealed := s18.LocationReportingFailureIndicationIEValue{}
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s18.BridgeLocationReportingFailureIndicationIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("LoggedMBSFNMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.LoggedMBSFNMDTExtIEsValue)(nil))
		selectedAssert(&s04.LoggedMBSFNMDTExtIEsValue{})
		opaque := func() s04.LoggedMBSFNMDTExtIEsValue {
			sealed := s04.LoggedMBSFNMDTExtIEsValue{}
			*s04.BridgeLoggedMBSFNMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeLoggedMBSFNMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("LoggedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s47.LoggedMDTExtIEsValue)(nil))
		selectedAssert(&s47.LoggedMDTExtIEsValue{})
		opaque := func() s47.LoggedMDTExtIEsValue {
			sealed := s47.LoggedMDTExtIEsValue{}
			*s47.BridgeLoggedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s47.BridgeLoggedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.LoggedMDTExtIEsValue {
				sealed := s47.LoggedMDTExtIEsValue{}
				*s47.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(284)
				*s47.BridgeLoggedMDTExtIEsValueFieldRowBluetoothMeasurementConfiguration(&sealed) = new(s14.BluetoothMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.LoggedMDTExtIEsValue {
				sealed := s47.LoggedMDTExtIEsValue{}
				*s47.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(285)
				*s47.BridgeLoggedMDTExtIEsValueFieldRowWLANMeasurementConfiguration(&sealed) = new(s47.WLANMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.LoggedMDTExtIEsValue {
				sealed := s47.LoggedMDTExtIEsValue{}
				*s47.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(344)
				*s47.BridgeLoggedMDTExtIEsValueFieldRowLoggedMDTTrigger(&sealed) = new(s19.LoggedMDTTrigger)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.LoggedMDTExtIEsValue {
				sealed := s47.LoggedMDTExtIEsValue{}
				*s47.BridgeLoggedMDTExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(345)
				*s47.BridgeLoggedMDTExtIEsValueFieldRowSensorMeasurementConfiguration(&sealed) = new(s30.SensorMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("M1PeriodicReportingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.M1PeriodicReportingExtIEsValue)(nil))
		selectedAssert(&s04.M1PeriodicReportingExtIEsValue{})
		opaque := func() s04.M1PeriodicReportingExtIEsValue {
			sealed := s04.M1PeriodicReportingExtIEsValue{}
			*s04.BridgeM1PeriodicReportingExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeM1PeriodicReportingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("M1ThresholdEventA2ExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.M1ThresholdEventA2ExtIEsValue)(nil))
		selectedAssert(&s04.M1ThresholdEventA2ExtIEsValue{})
		opaque := func() s04.M1ThresholdEventA2ExtIEsValue {
			sealed := s04.M1ThresholdEventA2ExtIEsValue{}
			*s04.BridgeM1ThresholdEventA2ExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeM1ThresholdEventA2ExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("M3ConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s04.M3ConfigurationExtIEsValue)(nil))
		selectedAssert(&s04.M3ConfigurationExtIEsValue{})
		opaque := func() s04.M3ConfigurationExtIEsValue {
			sealed := s04.M3ConfigurationExtIEsValue{}
			*s04.BridgeM3ConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s04.BridgeM3ConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
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
		selectedAssert((*s42.MDTConfigurationExtIEsValue)(nil))
		selectedAssert(&s42.MDTConfigurationExtIEsValue{})
		opaque := func() s42.MDTConfigurationExtIEsValue {
			sealed := s42.MDTConfigurationExtIEsValue{}
			*s42.BridgeMDTConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s42.BridgeMDTConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.MDTConfigurationExtIEsValue {
				sealed := s42.MDTConfigurationExtIEsValue{}
				*s42.BridgeMDTConfigurationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(178)
				*s42.BridgeMDTConfigurationExtIEsValueFieldRowSignallingBasedMDTPLMNList(&sealed) = new(s00.MDTPLMNList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MDTModeExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s24.MDTModeExtensionIEIEValue)(nil))
		selectedAssert(&s24.MDTModeExtensionIEIEValue{})
		opaque := func() s24.MDTModeExtensionIEIEValue {
			sealed := s24.MDTModeExtensionIEIEValue{}
			*s24.BridgeMDTModeExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeMDTModeExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.MDTModeExtensionIEIEValue {
				sealed := s24.MDTModeExtensionIEIEValue{}
				*s24.BridgeMDTModeExtensionIEIEValueFieldId(&sealed) = s00.ProtocolIEID(197)
				*s24.BridgeMDTModeExtensionIEIEValueFieldRowLoggedMBSFNMDT(&sealed) = new(s24.LoggedMBSFNMDT)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMECPRelocationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s10.MMECPRelocationIndicationIEValue)(nil))
		selectedAssert(&s10.MMECPRelocationIndicationIEValue{})
		opaque := func() s10.MMECPRelocationIndicationIEValue {
			sealed := s10.MMECPRelocationIndicationIEValue{}
			*s10.BridgeMMECPRelocationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s10.BridgeMMECPRelocationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s10.MMECPRelocationIndicationIEValue {
				sealed := s10.MMECPRelocationIndicationIEValue{}
				*s10.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s10.BridgeMMECPRelocationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s10.MMECPRelocationIndicationIEValue {
				sealed := s10.MMECPRelocationIndicationIEValue{}
				*s10.BridgeMMECPRelocationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s10.BridgeMMECPRelocationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s51.MMEConfigurationTransferIEValue)(nil))
		selectedAssert(&s51.MMEConfigurationTransferIEValue{})
		opaque := func() s51.MMEConfigurationTransferIEValue {
			sealed := s51.MMEConfigurationTransferIEValue{}
			*s51.BridgeMMEConfigurationTransferIEValueFieldIsOpaque(&sealed) = true
			*s51.BridgeMMEConfigurationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s51.MMEConfigurationTransferIEValue {
				sealed := s51.MMEConfigurationTransferIEValue{}
				*s51.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(130)
				*s51.BridgeMMEConfigurationTransferIEValueFieldRowSONConfigurationTransferMCT(&sealed) = new(s51.SONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.MMEConfigurationTransferIEValue {
				sealed := s51.MMEConfigurationTransferIEValue{}
				*s51.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(295)
				*s51.BridgeMMEConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferMCT(&sealed) = new(s51.ENDCSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s51.MMEConfigurationTransferIEValue {
				sealed := s51.MMEConfigurationTransferIEValue{}
				*s51.BridgeMMEConfigurationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(309)
				*s51.BridgeMMEConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferMCT(&sealed) = new(s00.IntersystemSONConfigurationTransfer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s22.MMEConfigurationUpdateAcknowledgeIEValue)(nil))
		selectedAssert(&s22.MMEConfigurationUpdateAcknowledgeIEValue{})
		opaque := func() s22.MMEConfigurationUpdateAcknowledgeIEValue {
			sealed := s22.MMEConfigurationUpdateAcknowledgeIEValue{}
			*s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s22.MMEConfigurationUpdateAcknowledgeIEValue {
				sealed := s22.MMEConfigurationUpdateAcknowledgeIEValue{}
				*s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s22.BridgeMMEConfigurationUpdateAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.MMEConfigurationUpdateFailureIEValue)(nil))
		selectedAssert(&s23.MMEConfigurationUpdateFailureIEValue{})
		opaque := func() s23.MMEConfigurationUpdateFailureIEValue {
			sealed := s23.MMEConfigurationUpdateFailureIEValue{}
			*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.MMEConfigurationUpdateFailureIEValue {
				sealed := s23.MMEConfigurationUpdateFailureIEValue{}
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.MMEConfigurationUpdateFailureIEValue {
				sealed := s23.MMEConfigurationUpdateFailureIEValue{}
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.MMEConfigurationUpdateFailureIEValue {
				sealed := s23.MMEConfigurationUpdateFailureIEValue{}
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeMMEConfigurationUpdateFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEConfigurationUpdateIEValue", func(t *testing.T) {
		selectedAssert((*s43.MMEConfigurationUpdateIEValue)(nil))
		selectedAssert(&s43.MMEConfigurationUpdateIEValue{})
		opaque := func() s43.MMEConfigurationUpdateIEValue {
			sealed := s43.MMEConfigurationUpdateIEValue{}
			*s43.BridgeMMEConfigurationUpdateIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeMMEConfigurationUpdateIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedGUMMEIs(&sealed) = new(s30.ServedGUMMEIs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowRelativeMMECapacity(&sealed) = new(s00.RelativeMMECapacity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.MMEConfigurationUpdateIEValue {
				sealed := s43.MMEConfigurationUpdateIEValue{}
				*s43.BridgeMMEConfigurationUpdateIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s43.BridgeMMEConfigurationUpdateIEValueFieldRowServedDCNs(&sealed) = new(s30.ServedDCNs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEDirectInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s34.MMEDirectInformationTransferIEValue)(nil))
		selectedAssert(&s34.MMEDirectInformationTransferIEValue{})
		opaque := func() s34.MMEDirectInformationTransferIEValue {
			sealed := s34.MMEDirectInformationTransferIEValue{}
			*s34.BridgeMMEDirectInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s34.BridgeMMEDirectInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s34.MMEDirectInformationTransferIEValue {
				sealed := s34.MMEDirectInformationTransferIEValue{}
				*s34.BridgeMMEDirectInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(122)
				*s34.BridgeMMEDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeMDT(&sealed) = new(s33.InterSystemInformationTransferType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEEarlyStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s37.MMEEarlyStatusTransferIEValue)(nil))
		selectedAssert(&s37.MMEEarlyStatusTransferIEValue{})
		opaque := func() s37.MMEEarlyStatusTransferIEValue {
			sealed := s37.MMEEarlyStatusTransferIEValue{}
			*s37.BridgeMMEEarlyStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeMMEEarlyStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.MMEEarlyStatusTransferIEValue {
				sealed := s37.MMEEarlyStatusTransferIEValue{}
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.MMEEarlyStatusTransferIEValue {
				sealed := s37.MMEEarlyStatusTransferIEValue{}
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.MMEEarlyStatusTransferIEValue {
				sealed := s37.MMEEarlyStatusTransferIEValue{}
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(321)
				*s37.BridgeMMEEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(&sealed) = new(s37.ENBEarlyStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MMEStatusTransferIEValue", func(t *testing.T) {
		selectedAssert((*s21.MMEStatusTransferIEValue)(nil))
		selectedAssert(&s21.MMEStatusTransferIEValue{})
		opaque := func() s21.MMEStatusTransferIEValue {
			sealed := s21.MMEStatusTransferIEValue{}
			*s21.BridgeMMEStatusTransferIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeMMEStatusTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.MMEStatusTransferIEValue {
				sealed := s21.MMEStatusTransferIEValue{}
				*s21.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s21.BridgeMMEStatusTransferIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.MMEStatusTransferIEValue {
				sealed := s21.MMEStatusTransferIEValue{}
				*s21.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s21.BridgeMMEStatusTransferIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.MMEStatusTransferIEValue {
				sealed := s21.MMEStatusTransferIEValue{}
				*s21.BridgeMMEStatusTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(90)
				*s21.BridgeMMEStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(&sealed) = new(s21.ENBStatusTransferTransparentContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("MeasurementThresholdL1LoggedMDTExtIEValue", func(t *testing.T) {
		selectedAssert((*s05.MeasurementThresholdL1LoggedMDTExtIEValue)(nil))
		selectedAssert(&s05.MeasurementThresholdL1LoggedMDTExtIEValue{})
		opaque := func() s05.MeasurementThresholdL1LoggedMDTExtIEValue {
			sealed := s05.MeasurementThresholdL1LoggedMDTExtIEValue{}
			*s05.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldIsOpaque(&sealed) = true
			*s05.BridgeMeasurementThresholdL1LoggedMDTExtIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("MutingPatternInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.MutingPatternInformationExtIEsValue)(nil))
		selectedAssert(&s05.MutingPatternInformationExtIEsValue{})
		opaque := func() s05.MutingPatternInformationExtIEsValue {
			sealed := s05.MutingPatternInformationExtIEsValue{}
			*s05.BridgeMutingPatternInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeMutingPatternInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NASDeliveryIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s10.NASDeliveryIndicationIEValue)(nil))
		selectedAssert(&s10.NASDeliveryIndicationIEValue{})
		opaque := func() s10.NASDeliveryIndicationIEValue {
			sealed := s10.NASDeliveryIndicationIEValue{}
			*s10.BridgeNASDeliveryIndicationIEValueFieldIsOpaque(&sealed) = true
			*s10.BridgeNASDeliveryIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s10.NASDeliveryIndicationIEValue {
				sealed := s10.NASDeliveryIndicationIEValue{}
				*s10.BridgeNASDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s10.BridgeNASDeliveryIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s10.NASDeliveryIndicationIEValue {
				sealed := s10.NASDeliveryIndicationIEValue{}
				*s10.BridgeNASDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s10.BridgeNASDeliveryIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("NASNonDeliveryIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s19.NASNonDeliveryIndicationIEValue)(nil))
		selectedAssert(&s19.NASNonDeliveryIndicationIEValue{})
		opaque := func() s19.NASNonDeliveryIndicationIEValue {
			sealed := s19.NASNonDeliveryIndicationIEValue{}
			*s19.BridgeNASNonDeliveryIndicationIEValueFieldIsOpaque(&sealed) = true
			*s19.BridgeNASNonDeliveryIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s19.NASNonDeliveryIndicationIEValue {
				sealed := s19.NASNonDeliveryIndicationIEValue{}
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s19.NASNonDeliveryIndicationIEValue {
				sealed := s19.NASNonDeliveryIndicationIEValue{}
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s19.NASNonDeliveryIndicationIEValue {
				sealed := s19.NASNonDeliveryIndicationIEValue{}
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s19.NASNonDeliveryIndicationIEValue {
				sealed := s19.NASNonDeliveryIndicationIEValue{}
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s19.BridgeNASNonDeliveryIndicationIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("NBIoTPagingEDRXInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NBIoTPagingEDRXInformationExtIEsValue)(nil))
		selectedAssert(&s05.NBIoTPagingEDRXInformationExtIEsValue{})
		opaque := func() s05.NBIoTPagingEDRXInformationExtIEsValue {
			sealed := s05.NBIoTPagingEDRXInformationExtIEsValue{}
			*s05.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNBIoTPagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NGENBExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NGENBExtIEsValue)(nil))
		selectedAssert(&s05.NGENBExtIEsValue{})
		opaque := func() s05.NGENBExtIEsValue {
			sealed := s05.NGENBExtIEsValue{}
			*s05.BridgeNGENBExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNGENBExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRCGIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NRCGIExtIEsValue)(nil))
		selectedAssert(&s05.NRCGIExtIEsValue{})
		opaque := func() s05.NRCGIExtIEsValue {
			sealed := s05.NRCGIExtIEsValue{}
			*s05.BridgeNRCGIExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNRCGIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRUESecurityCapabilitiesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NRUESecurityCapabilitiesExtIEsValue)(nil))
		selectedAssert(&s05.NRUESecurityCapabilitiesExtIEsValue{})
		opaque := func() s05.NRUESecurityCapabilitiesExtIEsValue {
			sealed := s05.NRUESecurityCapabilitiesExtIEsValue{}
			*s05.BridgeNRUESecurityCapabilitiesExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNRUESecurityCapabilitiesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRUESidelinkAggregateMaximumBitrateExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue)(nil))
		selectedAssert(&s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue{})
		opaque := func() s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue {
			sealed := s05.NRUESidelinkAggregateMaximumBitrateExtIEsValue{}
			*s05.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("NRV2XServicesAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.NRV2XServicesAuthorizedExtIEsValue)(nil))
		selectedAssert(&s05.NRV2XServicesAuthorizedExtIEsValue{})
		opaque := func() s05.NRV2XServicesAuthorizedExtIEsValue {
			sealed := s05.NRV2XServicesAuthorizedExtIEsValue{}
			*s05.BridgeNRV2XServicesAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeNRV2XServicesAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("OverloadStartIEValue", func(t *testing.T) {
		selectedAssert((*s41.OverloadStartIEValue)(nil))
		selectedAssert(&s41.OverloadStartIEValue{})
		opaque := func() s41.OverloadStartIEValue {
			sealed := s41.OverloadStartIEValue{}
			*s41.BridgeOverloadStartIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeOverloadStartIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.OverloadStartIEValue {
				sealed := s41.OverloadStartIEValue{}
				*s41.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(101)
				*s41.BridgeOverloadStartIEValueFieldRowOverloadResponse(&sealed) = new(s20.OverloadResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.OverloadStartIEValue {
				sealed := s41.OverloadStartIEValue{}
				*s41.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(154)
				*s41.BridgeOverloadStartIEValueFieldRowGUMMEIList(&sealed) = new(s18.GUMMEIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.OverloadStartIEValue {
				sealed := s41.OverloadStartIEValue{}
				*s41.BridgeOverloadStartIEValueFieldId(&sealed) = s00.ProtocolIEID(161)
				*s41.BridgeOverloadStartIEValueFieldRowTrafficLoadReductionIndication(&sealed) = new(s00.TrafficLoadReductionIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("OverloadStopIEValue", func(t *testing.T) {
		selectedAssert((*s41.OverloadStopIEValue)(nil))
		selectedAssert(&s41.OverloadStopIEValue{})
		opaque := func() s41.OverloadStopIEValue {
			sealed := s41.OverloadStopIEValue{}
			*s41.BridgeOverloadStopIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgeOverloadStopIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.OverloadStopIEValue {
				sealed := s41.OverloadStopIEValue{}
				*s41.BridgeOverloadStopIEValueFieldId(&sealed) = s00.ProtocolIEID(154)
				*s41.BridgeOverloadStopIEValueFieldRowGUMMEIList(&sealed) = new(s18.GUMMEIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PC5FlowBitRatesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PC5FlowBitRatesExtIEsValue)(nil))
		selectedAssert(&s05.PC5FlowBitRatesExtIEsValue{})
		opaque := func() s05.PC5FlowBitRatesExtIEsValue {
			sealed := s05.PC5FlowBitRatesExtIEsValue{}
			*s05.BridgePC5FlowBitRatesExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePC5FlowBitRatesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PC5QoSFlowItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PC5QoSFlowItemExtIEsValue)(nil))
		selectedAssert(&s05.PC5QoSFlowItemExtIEsValue{})
		opaque := func() s05.PC5QoSFlowItemExtIEsValue {
			sealed := s05.PC5QoSFlowItemExtIEsValue{}
			*s05.BridgePC5QoSFlowItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePC5QoSFlowItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PC5QoSParametersExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PC5QoSParametersExtIEsValue)(nil))
		selectedAssert(&s05.PC5QoSParametersExtIEsValue{})
		opaque := func() s05.PC5QoSParametersExtIEsValue {
			sealed := s05.PC5QoSParametersExtIEsValue{}
			*s05.BridgePC5QoSParametersExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePC5QoSParametersExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PLMNAreaBasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PLMNAreaBasedQMCExtIEsValue)(nil))
		selectedAssert(&s05.PLMNAreaBasedQMCExtIEsValue{})
		opaque := func() s05.PLMNAreaBasedQMCExtIEsValue {
			sealed := s05.PLMNAreaBasedQMCExtIEsValue{}
			*s05.BridgePLMNAreaBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePLMNAreaBasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PSCellInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PSCellInformationExtIEsValue)(nil))
		selectedAssert(&s05.PSCellInformationExtIEsValue{})
		opaque := func() s05.PSCellInformationExtIEsValue {
			sealed := s05.PSCellInformationExtIEsValue{}
			*s05.BridgePSCellInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePSCellInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PWSFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s42.PWSFailureIndicationIEValue)(nil))
		selectedAssert(&s42.PWSFailureIndicationIEValue{})
		opaque := func() s42.PWSFailureIndicationIEValue {
			sealed := s42.PWSFailureIndicationIEValue{}
			*s42.BridgePWSFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s42.BridgePWSFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s42.PWSFailureIndicationIEValue {
				sealed := s42.PWSFailureIndicationIEValue{}
				*s42.BridgePWSFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(222)
				*s42.BridgePWSFailureIndicationIEValueFieldRowPWSfailedECGIList(&sealed) = new(s20.PWSfailedECGIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s42.PWSFailureIndicationIEValue {
				sealed := s42.PWSFailureIndicationIEValue{}
				*s42.BridgePWSFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s42.BridgePWSFailureIndicationIEValueFieldRowGlobalENBID(&sealed) = new(s18.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PWSRestartIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s44.PWSRestartIndicationIEValue)(nil))
		selectedAssert(&s44.PWSRestartIndicationIEValue{})
		opaque := func() s44.PWSRestartIndicationIEValue {
			sealed := s44.PWSRestartIndicationIEValue{}
			*s44.BridgePWSRestartIndicationIEValueFieldIsOpaque(&sealed) = true
			*s44.BridgePWSRestartIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.PWSRestartIndicationIEValue {
				sealed := s44.PWSRestartIndicationIEValue{}
				*s44.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(182)
				*s44.BridgePWSRestartIndicationIEValueFieldRowECGIListForRestart(&sealed) = new(s17.ECGIListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.PWSRestartIndicationIEValue {
				sealed := s44.PWSRestartIndicationIEValue{}
				*s44.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s44.BridgePWSRestartIndicationIEValueFieldRowGlobalENBID(&sealed) = new(s18.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.PWSRestartIndicationIEValue {
				sealed := s44.PWSRestartIndicationIEValue{}
				*s44.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(188)
				*s44.BridgePWSRestartIndicationIEValueFieldRowTAIListForRestart(&sealed) = new(s32.TAIListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.PWSRestartIndicationIEValue {
				sealed := s44.PWSRestartIndicationIEValue{}
				*s44.BridgePWSRestartIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(190)
				*s44.BridgePWSRestartIndicationIEValueFieldRowEmergencyAreaIDListForRestart(&sealed) = new(s00.EmergencyAreaIDListForRestart)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PagingAttemptInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PagingAttemptInformationExtIEsValue)(nil))
		selectedAssert(&s05.PagingAttemptInformationExtIEsValue{})
		opaque := func() s05.PagingAttemptInformationExtIEsValue {
			sealed := s05.PagingAttemptInformationExtIEsValue{}
			*s05.BridgePagingAttemptInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePagingAttemptInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PagingEDRXInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.PagingEDRXInformationExtIEsValue)(nil))
		selectedAssert(&s05.PagingEDRXInformationExtIEsValue{})
		opaque := func() s05.PagingEDRXInformationExtIEsValue {
			sealed := s05.PagingEDRXInformationExtIEsValue{}
			*s05.BridgePagingEDRXInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgePagingEDRXInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("PagingIEValue", func(t *testing.T) {
		selectedAssert((*s49.PagingIEValue)(nil))
		selectedAssert(&s49.PagingIEValue{})
		opaque := func() s49.PagingIEValue {
			sealed := s49.PagingIEValue{}
			*s49.BridgePagingIEValueFieldIsOpaque(&sealed) = true
			*s49.BridgePagingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(80)
				*s49.BridgePagingIEValueFieldRowUEIdentityIndexValue(&sealed) = new(s00.UEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(43)
				*s49.BridgePagingIEValueFieldRowUEPagingID(&sealed) = new(s28.UEPagingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(44)
				*s49.BridgePagingIEValueFieldRowPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(109)
				*s49.BridgePagingIEValueFieldRowCNDomain(&sealed) = new(s00.CNDomain)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(46)
				*s49.BridgePagingIEValueFieldRowTAIList(&sealed) = new(s33.TAIList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s49.BridgePagingIEValueFieldRowCSGIdList(&sealed) = new(s14.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(151)
				*s49.BridgePagingIEValueFieldRowPagingPriority(&sealed) = new(s00.PagingPriority)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(198)
				*s49.BridgePagingIEValueFieldRowUERadioCapabilityForPaging(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(211)
				*s49.BridgePagingIEValueFieldRowAssistanceDataForPaging(&sealed) = new(s26.AssistanceDataForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(227)
				*s49.BridgePagingIEValueFieldRowPagingEDRXInformation(&sealed) = new(s20.PagingEDRXInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(231)
				*s49.BridgePagingIEValueFieldRowExtendedUEIdentityIndexValue(&sealed) = new(s00.ExtendedUEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(239)
				*s49.BridgePagingIEValueFieldRowNBIoTPagingEDRXInformation(&sealed) = new(s19.NBIoTPagingEDRXInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(244)
				*s49.BridgePagingIEValueFieldRowNBIoTUEIdentityIndexValue(&sealed) = new(s00.NBIoTUEIdentityIndexValue)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s49.BridgePagingIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s49.BridgePagingIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(304)
				*s49.BridgePagingIEValueFieldRowDataSize(&sealed) = new(s00.DataSize)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(323)
				*s49.BridgePagingIEValueFieldRowWUSAssistanceInformation(&sealed) = new(s49.WUSAssistanceInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(324)
				*s49.BridgePagingIEValueFieldRowNBIoTPagingDRX(&sealed) = new(s00.NBIoTPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s49.PagingIEValue {
				sealed := s49.PagingIEValue{}
				*s49.BridgePagingIEValueFieldId(&sealed) = s00.ProtocolIEID(331)
				*s49.BridgePagingIEValueFieldRowPagingCause(&sealed) = new(s00.PagingCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s46.PathSwitchRequestAcknowledgeIEValue)(nil))
		selectedAssert(&s46.PathSwitchRequestAcknowledgeIEValue{})
		opaque := func() s46.PathSwitchRequestAcknowledgeIEValue {
			sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
			*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(95)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(&sealed) = new(s17.ERABToBeSwitchedULList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(33)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(&sealed) = new(s16.ERABList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(&sealed) = new(s28.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(&sealed) = new(s20.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = new(s00.UEUserPlaneCIoTSupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s46.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s37.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(&sealed) = new(s00.EnhancedCoverageRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(&sealed) = new(s00.CEModeBRestricted)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(&sealed) = new(s42.HandoverRestrictionList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s19.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s19.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(&sealed) = new(s24.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(&sealed) = new(s37.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(341)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(&sealed) = new(s29.ERABToBeUpdatedList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.PathSwitchRequestAcknowledgeIEValue {
				sealed := s46.PathSwitchRequestAcknowledgeIEValue{}
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s46.BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.PathSwitchRequestFailureIEValue)(nil))
		selectedAssert(&s23.PathSwitchRequestFailureIEValue{})
		opaque := func() s23.PathSwitchRequestFailureIEValue {
			sealed := s23.PathSwitchRequestFailureIEValue{}
			*s23.BridgePathSwitchRequestFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgePathSwitchRequestFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.PathSwitchRequestFailureIEValue {
				sealed := s23.PathSwitchRequestFailureIEValue{}
				*s23.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgePathSwitchRequestFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.PathSwitchRequestFailureIEValue {
				sealed := s23.PathSwitchRequestFailureIEValue{}
				*s23.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgePathSwitchRequestFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.PathSwitchRequestFailureIEValue {
				sealed := s23.PathSwitchRequestFailureIEValue{}
				*s23.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgePathSwitchRequestFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.PathSwitchRequestFailureIEValue {
				sealed := s23.PathSwitchRequestFailureIEValue{}
				*s23.BridgePathSwitchRequestFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgePathSwitchRequestFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PathSwitchRequestIEValue", func(t *testing.T) {
		selectedAssert((*s41.PathSwitchRequestIEValue)(nil))
		selectedAssert(&s41.PathSwitchRequestIEValue{})
		opaque := func() s41.PathSwitchRequestIEValue {
			sealed := s41.PathSwitchRequestIEValue{}
			*s41.BridgePathSwitchRequestIEValueFieldIsOpaque(&sealed) = true
			*s41.BridgePathSwitchRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s41.BridgePathSwitchRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(22)
				*s41.BridgePathSwitchRequestIEValueFieldRowERABToBeSwitchedDLList(&sealed) = new(s30.ERABToBeSwitchedDLList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(88)
				*s41.BridgePathSwitchRequestIEValueFieldRowSourceMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s41.BridgePathSwitchRequestIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s41.BridgePathSwitchRequestIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s41.BridgePathSwitchRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s37.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s41.BridgePathSwitchRequestIEValueFieldRowCSGId(&sealed) = new(s00.CSGId)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s41.BridgePathSwitchRequestIEValueFieldRowCellAccessMode(&sealed) = new(s00.CellAccessMode)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(157)
				*s41.BridgePathSwitchRequestIEValueFieldRowSourceMMEGUMMEI(&sealed) = new(s18.GUMMEI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s41.BridgePathSwitchRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s41.BridgePathSwitchRequestIEValueFieldRowTunnelInformationForBBF(&sealed) = new(s35.TunnelInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s41.BridgePathSwitchRequestIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(245)
				*s41.BridgePathSwitchRequestIEValueFieldRowRRCResumeCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s41.BridgePathSwitchRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s41.BridgePathSwitchRequestIEValueFieldRowPSCellInformation(&sealed) = new(s20.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s41.PathSwitchRequestIEValue {
				sealed := s41.PathSwitchRequestIEValue{}
				*s41.BridgePathSwitchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s41.BridgePathSwitchRequestIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("PrivateMessageIEsValue", func(t *testing.T) {
		selectedAssert((*s25.PrivateMessageIEsValue)(nil))
		selectedAssert(&s25.PrivateMessageIEsValue{})
		opaque := func() s25.PrivateMessageIEsValue {
			sealed := s25.PrivateMessageIEsValue{}
			*s25.BridgePrivateMessageIEsValueFieldValid(&sealed) = true
			*s25.BridgePrivateMessageIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ProSeAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ProSeAuthorizedExtIEsValue)(nil))
		selectedAssert(&s05.ProSeAuthorizedExtIEsValue{})
		opaque := func() s05.ProSeAuthorizedExtIEsValue {
			sealed := s05.ProSeAuthorizedExtIEsValue{}
			*s05.BridgeProSeAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeProSeAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.ProSeAuthorizedExtIEsValue {
				sealed := s05.ProSeAuthorizedExtIEsValue{}
				*s05.BridgeProSeAuthorizedExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(216)
				*s05.BridgeProSeAuthorizedExtIEsValueFieldRowProSeUEtoNetworkRelaying(&sealed) = new(s00.ProSeUEtoNetworkRelaying)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RATRestrictionsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RATRestrictionsItemExtIEsValue)(nil))
		selectedAssert(&s05.RATRestrictionsItemExtIEsValue{})
		opaque := func() s05.RATRestrictionsItemExtIEsValue {
			sealed := s05.RATRestrictionsItemExtIEsValue{}
			*s05.BridgeRATRestrictionsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRATRestrictionsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RIMTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RIMTransferExtIEsValue)(nil))
		selectedAssert(&s05.RIMTransferExtIEsValue{})
		opaque := func() s05.RIMTransferExtIEsValue {
			sealed := s05.RIMTransferExtIEsValue{}
			*s05.BridgeRIMTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRIMTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RLFReportInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RLFReportInformationExtIEsValue)(nil))
		selectedAssert(&s05.RLFReportInformationExtIEsValue{})
		opaque := func() s05.RLFReportInformationExtIEsValue {
			sealed := s05.RLFReportInformationExtIEsValue{}
			*s05.BridgeRLFReportInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRLFReportInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s05.RLFReportInformationExtIEsValue {
				sealed := s05.RLFReportInformationExtIEsValue{}
				*s05.BridgeRLFReportInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(313)
				*s05.BridgeRLFReportInformationExtIEsValueFieldRowNBIoTRLFReportContainer(&sealed) = new(s00.NBIoTRLFReportContainer)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedCellItemIEValue", func(t *testing.T) {
		selectedAssert((*s26.RecommendedCellItemIEValue)(nil))
		selectedAssert(&s26.RecommendedCellItemIEValue{})
		opaque := func() s26.RecommendedCellItemIEValue {
			sealed := s26.RecommendedCellItemIEValue{}
			*s26.BridgeRecommendedCellItemIEValueFieldIsOpaque(&sealed) = true
			*s26.BridgeRecommendedCellItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s26.RecommendedCellItemIEValue {
				sealed := s26.RecommendedCellItemIEValue{}
				*s26.BridgeRecommendedCellItemIEValueFieldId(&sealed) = s00.ProtocolIEID(214)
				*s26.BridgeRecommendedCellItemIEValueFieldRowRecommendedCellItem(&sealed) = new(s26.RecommendedCellItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedCellsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RecommendedCellsForPagingExtIEsValue)(nil))
		selectedAssert(&s05.RecommendedCellsForPagingExtIEsValue{})
		opaque := func() s05.RecommendedCellsForPagingExtIEsValue {
			sealed := s05.RecommendedCellsForPagingExtIEsValue{}
			*s05.BridgeRecommendedCellsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRecommendedCellsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedCellsForPagingItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RecommendedCellsForPagingItemExtIEsValue)(nil))
		selectedAssert(&s05.RecommendedCellsForPagingItemExtIEsValue{})
		opaque := func() s05.RecommendedCellsForPagingItemExtIEsValue {
			sealed := s05.RecommendedCellsForPagingItemExtIEsValue{}
			*s05.BridgeRecommendedCellsForPagingItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRecommendedCellsForPagingItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedENBItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RecommendedENBItemExtIEsValue)(nil))
		selectedAssert(&s05.RecommendedENBItemExtIEsValue{})
		opaque := func() s05.RecommendedENBItemExtIEsValue {
			sealed := s05.RecommendedENBItemExtIEsValue{}
			*s05.BridgeRecommendedENBItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRecommendedENBItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RecommendedENBItemIEValue", func(t *testing.T) {
		selectedAssert((*s32.RecommendedENBItemIEValue)(nil))
		selectedAssert(&s32.RecommendedENBItemIEValue{})
		opaque := func() s32.RecommendedENBItemIEValue {
			sealed := s32.RecommendedENBItemIEValue{}
			*s32.BridgeRecommendedENBItemIEValueFieldIsOpaque(&sealed) = true
			*s32.BridgeRecommendedENBItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s32.RecommendedENBItemIEValue {
				sealed := s32.RecommendedENBItemIEValue{}
				*s32.BridgeRecommendedENBItemIEValueFieldId(&sealed) = s00.ProtocolIEID(215)
				*s32.BridgeRecommendedENBItemIEValueFieldRowRecommendedENBItem(&sealed) = new(s32.RecommendedENBItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RecommendedENBsForPagingExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RecommendedENBsForPagingExtIEsValue)(nil))
		selectedAssert(&s05.RecommendedENBsForPagingExtIEsValue{})
		opaque := func() s05.RecommendedENBsForPagingExtIEsValue {
			sealed := s05.RecommendedENBsForPagingExtIEsValue{}
			*s05.BridgeRecommendedENBsForPagingExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRecommendedENBsForPagingExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RequestTypeExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.RequestTypeExtIEsValue)(nil))
		selectedAssert(&s06.RequestTypeExtIEsValue{})
		opaque := func() s06.RequestTypeExtIEsValue {
			sealed := s06.RequestTypeExtIEsValue{}
			*s06.BridgeRequestTypeExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeRequestTypeExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.RequestTypeExtIEsValue {
				sealed := s06.RequestTypeExtIEsValue{}
				*s06.BridgeRequestTypeExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(298)
				*s06.BridgeRequestTypeExtIEsValueFieldRowRequestTypeAdditionalInfo(&sealed) = new(s00.RequestTypeAdditionalInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RequestedTNLInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.RequestedTNLInfoExtIEsValue)(nil))
		selectedAssert(&s05.RequestedTNLInfoExtIEsValue{})
		opaque := func() s05.RequestedTNLInfoExtIEsValue {
			sealed := s05.RequestedTNLInfoExtIEsValue{}
			*s05.BridgeRequestedTNLInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeRequestedTNLInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("RerouteNASRequestIEValue", func(t *testing.T) {
		selectedAssert((*s20.RerouteNASRequestIEValue)(nil))
		selectedAssert(&s20.RerouteNASRequestIEValue{})
		opaque := func() s20.RerouteNASRequestIEValue {
			sealed := s20.RerouteNASRequestIEValue{}
			*s20.BridgeRerouteNASRequestIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeRerouteNASRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s20.BridgeRerouteNASRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s20.BridgeRerouteNASRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(225)
				*s20.BridgeRerouteNASRequestIEValueFieldRowS1Message(&sealed) = new([]byte)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s20.BridgeRerouteNASRequestIEValueFieldRowMMEGroupID(&sealed) = new(s00.MMEGroupID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(224)
				*s20.BridgeRerouteNASRequestIEValueFieldRowAdditionalGUTI(&sealed) = new(s18.AdditionalGUTI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.RerouteNASRequestIEValue {
				sealed := s20.RerouteNASRequestIEValue{}
				*s20.BridgeRerouteNASRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s20.BridgeRerouteNASRequestIEValueFieldRowUEUsageType(&sealed) = new(s00.UEUsageType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ResetAcknowledgeIEValue", func(t *testing.T) {
		selectedAssert((*s44.ResetAcknowledgeIEValue)(nil))
		selectedAssert(&s44.ResetAcknowledgeIEValue{})
		opaque := func() s44.ResetAcknowledgeIEValue {
			sealed := s44.ResetAcknowledgeIEValue{}
			*s44.BridgeResetAcknowledgeIEValueFieldIsOpaque(&sealed) = true
			*s44.BridgeResetAcknowledgeIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s44.ResetAcknowledgeIEValue {
				sealed := s44.ResetAcknowledgeIEValue{}
				*s44.BridgeResetAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(93)
				*s44.BridgeResetAcknowledgeIEValueFieldRowUEAssociatedLogicalS1ConnectionListResAck(&sealed) = new(s36.UEAssociatedLogicalS1ConnectionListResAck)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s44.ResetAcknowledgeIEValue {
				sealed := s44.ResetAcknowledgeIEValue{}
				*s44.BridgeResetAcknowledgeIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s44.BridgeResetAcknowledgeIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("ResetIEValue", func(t *testing.T) {
		selectedAssert((*s36.ResetIEValue)(nil))
		selectedAssert(&s36.ResetIEValue{})
		opaque := func() s36.ResetIEValue {
			sealed := s36.ResetIEValue{}
			*s36.BridgeResetIEValueFieldIsOpaque(&sealed) = true
			*s36.BridgeResetIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.ResetIEValue {
				sealed := s36.ResetIEValue{}
				*s36.BridgeResetIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s36.BridgeResetIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.ResetIEValue {
				sealed := s36.ResetIEValue{}
				*s36.BridgeResetIEValueFieldId(&sealed) = s00.ProtocolIEID(92)
				*s36.BridgeResetIEValueFieldRowResetType(&sealed) = new(s36.ResetType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("RetrieveUEInformationIEValue", func(t *testing.T) {
		selectedAssert((*s28.RetrieveUEInformationIEValue)(nil))
		selectedAssert(&s28.RetrieveUEInformationIEValue{})
		opaque := func() s28.RetrieveUEInformationIEValue {
			sealed := s28.RetrieveUEInformationIEValue{}
			*s28.BridgeRetrieveUEInformationIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeRetrieveUEInformationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.RetrieveUEInformationIEValue {
				sealed := s28.RetrieveUEInformationIEValue{}
				*s28.BridgeRetrieveUEInformationIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s28.BridgeRetrieveUEInformationIEValueFieldRowSTMSI(&sealed) = new(s28.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.S1RemovalFailureIEValue)(nil))
		selectedAssert(&s23.S1RemovalFailureIEValue{})
		opaque := func() s23.S1RemovalFailureIEValue {
			sealed := s23.S1RemovalFailureIEValue{}
			*s23.BridgeS1RemovalFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeS1RemovalFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.S1RemovalFailureIEValue {
				sealed := s23.S1RemovalFailureIEValue{}
				*s23.BridgeS1RemovalFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgeS1RemovalFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.S1RemovalFailureIEValue {
				sealed := s23.S1RemovalFailureIEValue{}
				*s23.BridgeS1RemovalFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeS1RemovalFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalRequestIEValue", func(t *testing.T) {
		selectedAssert((*s20.S1RemovalRequestIEValue)(nil))
		selectedAssert(&s20.S1RemovalRequestIEValue{})
		opaque := func() s20.S1RemovalRequestIEValue {
			sealed := s20.S1RemovalRequestIEValue{}
			*s20.BridgeS1RemovalRequestIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeS1RemovalRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.S1RemovalRequestIEValue {
				sealed := s20.S1RemovalRequestIEValue{}
				*s20.BridgeS1RemovalRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s20.BridgeS1RemovalRequestIEValueFieldRowGlobalENBID(&sealed) = new(s18.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1RemovalResponseIEValue", func(t *testing.T) {
		selectedAssert((*s23.S1RemovalResponseIEValue)(nil))
		selectedAssert(&s23.S1RemovalResponseIEValue{})
		opaque := func() s23.S1RemovalResponseIEValue {
			sealed := s23.S1RemovalResponseIEValue{}
			*s23.BridgeS1RemovalResponseIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeS1RemovalResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.S1RemovalResponseIEValue {
				sealed := s23.S1RemovalResponseIEValue{}
				*s23.BridgeS1RemovalResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s23.BridgeS1RemovalResponseIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.S1RemovalResponseIEValue {
				sealed := s23.S1RemovalResponseIEValue{}
				*s23.BridgeS1RemovalResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeS1RemovalResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.S1SetupFailureIEValue)(nil))
		selectedAssert(&s23.S1SetupFailureIEValue{})
		opaque := func() s23.S1SetupFailureIEValue {
			sealed := s23.S1SetupFailureIEValue{}
			*s23.BridgeS1SetupFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeS1SetupFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.S1SetupFailureIEValue {
				sealed := s23.S1SetupFailureIEValue{}
				*s23.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgeS1SetupFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.S1SetupFailureIEValue {
				sealed := s23.S1SetupFailureIEValue{}
				*s23.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(65)
				*s23.BridgeS1SetupFailureIEValueFieldRowTimeToWait(&sealed) = new(s00.TimeToWait)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.S1SetupFailureIEValue {
				sealed := s23.S1SetupFailureIEValue{}
				*s23.BridgeS1SetupFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeS1SetupFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupRequestIEValue", func(t *testing.T) {
		selectedAssert((*s43.S1SetupRequestIEValue)(nil))
		selectedAssert(&s43.S1SetupRequestIEValue{})
		opaque := func() s43.S1SetupRequestIEValue {
			sealed := s43.S1SetupRequestIEValue{}
			*s43.BridgeS1SetupRequestIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeS1SetupRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(59)
				*s43.BridgeS1SetupRequestIEValueFieldRowGlobalENBID(&sealed) = new(s18.GlobalENBID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(60)
				*s43.BridgeS1SetupRequestIEValueFieldRowENBname(&sealed) = new(s00.ENBname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(64)
				*s43.BridgeS1SetupRequestIEValueFieldRowSupportedTAs(&sealed) = new(s31.SupportedTAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(137)
				*s43.BridgeS1SetupRequestIEValueFieldRowDefaultPagingDRX(&sealed) = new(s00.PagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(128)
				*s43.BridgeS1SetupRequestIEValueFieldRowCSGIdList(&sealed) = new(s14.CSGIdList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(228)
				*s43.BridgeS1SetupRequestIEValueFieldRowUERetentionInformation(&sealed) = new(s00.UERetentionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(234)
				*s43.BridgeS1SetupRequestIEValueFieldRowNBIoTDefaultPagingDRX(&sealed) = new(s00.NBIoTDefaultPagingDRX)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupRequestIEValue {
				sealed := s43.S1SetupRequestIEValue{}
				*s43.BridgeS1SetupRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(291)
				*s43.BridgeS1SetupRequestIEValueFieldRowConnectedengNBList(&sealed) = new(s31.ConnectedengNBList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("S1SetupResponseIEValue", func(t *testing.T) {
		selectedAssert((*s43.S1SetupResponseIEValue)(nil))
		selectedAssert(&s43.S1SetupResponseIEValue{})
		opaque := func() s43.S1SetupResponseIEValue {
			sealed := s43.S1SetupResponseIEValue{}
			*s43.BridgeS1SetupResponseIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeS1SetupResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(61)
				*s43.BridgeS1SetupResponseIEValueFieldRowMMEname(&sealed) = new(s00.MMEname)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(105)
				*s43.BridgeS1SetupResponseIEValueFieldRowServedGUMMEIs(&sealed) = new(s30.ServedGUMMEIs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(87)
				*s43.BridgeS1SetupResponseIEValueFieldRowRelativeMMECapacity(&sealed) = new(s00.RelativeMMECapacity)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(163)
				*s43.BridgeS1SetupResponseIEValueFieldRowMMERelaySupportIndicator(&sealed) = new(s00.MMERelaySupportIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s43.BridgeS1SetupResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(228)
				*s43.BridgeS1SetupResponseIEValueFieldRowUERetentionInformation(&sealed) = new(s00.UERetentionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(247)
				*s43.BridgeS1SetupResponseIEValueFieldRowServedDCNs(&sealed) = new(s30.ServedDCNs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.S1SetupResponseIEValue {
				sealed := s43.S1SetupResponseIEValue{}
				*s43.BridgeS1SetupResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(303)
				*s43.BridgeS1SetupResponseIEValueFieldRowIABSupported(&sealed) = new(s00.IABSupported)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONConfigurationTransferExtIEsValue", func(t *testing.T) {
		selectedAssert((*s50.SONConfigurationTransferExtIEsValue)(nil))
		selectedAssert(&s50.SONConfigurationTransferExtIEsValue{})
		opaque := func() s50.SONConfigurationTransferExtIEsValue {
			sealed := s50.SONConfigurationTransferExtIEsValue{}
			*s50.BridgeSONConfigurationTransferExtIEsValueFieldIsOpaque(&sealed) = true
			*s50.BridgeSONConfigurationTransferExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.SONConfigurationTransferExtIEsValue {
				sealed := s50.SONConfigurationTransferExtIEsValue{}
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(152)
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldRowX2TNLConfigurationInfo(&sealed) = new(s50.X2TNLConfigurationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SONConfigurationTransferExtIEsValue {
				sealed := s50.SONConfigurationTransferExtIEsValue{}
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(209)
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldRowSynchronisationInformation(&sealed) = new(s31.SynchronisationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SONConfigurationTransferExtIEsValue {
				sealed := s50.SONConfigurationTransferExtIEsValue{}
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(356)
				*s50.BridgeSONConfigurationTransferExtIEsValueFieldRowRequestedTNLInfo(&sealed) = new(s26.RequestedTNLInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONInformationExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s20.SONInformationExtensionIEIEValue)(nil))
		selectedAssert(&s20.SONInformationExtensionIEIEValue{})
		opaque := func() s20.SONInformationExtensionIEIEValue {
			sealed := s20.SONInformationExtensionIEIEValue{}
			*s20.BridgeSONInformationExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeSONInformationExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.SONInformationExtensionIEIEValue {
				sealed := s20.SONInformationExtensionIEIEValue{}
				*s20.BridgeSONInformationExtensionIEIEValueFieldId(&sealed) = s00.ProtocolIEID(206)
				*s20.BridgeSONInformationExtensionIEIEValueFieldRowSONInformationReport(&sealed) = new(s20.SONInformationReport)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SONInformationReplyExtIEsValue", func(t *testing.T) {
		selectedAssert((*s34.SONInformationReplyExtIEsValue)(nil))
		selectedAssert(&s34.SONInformationReplyExtIEsValue{})
		opaque := func() s34.SONInformationReplyExtIEsValue {
			sealed := s34.SONInformationReplyExtIEsValue{}
			*s34.BridgeSONInformationReplyExtIEsValueFieldIsOpaque(&sealed) = true
			*s34.BridgeSONInformationReplyExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s34.SONInformationReplyExtIEsValue {
				sealed := s34.SONInformationReplyExtIEsValue{}
				*s34.BridgeSONInformationReplyExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(149)
				*s34.BridgeSONInformationReplyExtIEsValueFieldRowTimeSynchronisationInfo(&sealed) = new(s34.TimeSynchronisationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SONInformationReplyExtIEsValue {
				sealed := s34.SONInformationReplyExtIEsValue{}
				*s34.BridgeSONInformationReplyExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(208)
				*s34.BridgeSONInformationReplyExtIEsValueFieldRowMutingPatternInformation(&sealed) = new(s19.MutingPatternInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("STMSIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.STMSIExtIEsValue)(nil))
		selectedAssert(&s05.STMSIExtIEsValue{})
		opaque := func() s05.STMSIExtIEsValue {
			sealed := s05.STMSIExtIEsValue{}
			*s05.BridgeSTMSIExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSTMSIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ScheduledCommunicationTimeExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.ScheduledCommunicationTimeExtIEsValue)(nil))
		selectedAssert(&s05.ScheduledCommunicationTimeExtIEsValue{})
		opaque := func() s05.ScheduledCommunicationTimeExtIEsValue {
			sealed := s05.ScheduledCommunicationTimeExtIEsValue{}
			*s05.BridgeScheduledCommunicationTimeExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeScheduledCommunicationTimeExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecondaryRATDataUsageReportIEValue", func(t *testing.T) {
		selectedAssert((*s45.SecondaryRATDataUsageReportIEValue)(nil))
		selectedAssert(&s45.SecondaryRATDataUsageReportIEValue{})
		opaque := func() s45.SecondaryRATDataUsageReportIEValue {
			sealed := s45.SecondaryRATDataUsageReportIEValue{}
			*s45.BridgeSecondaryRATDataUsageReportIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeSecondaryRATDataUsageReportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(266)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowHandoverFlag(&sealed) = new(s00.HandoverFlag)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.SecondaryRATDataUsageReportIEValue {
				sealed := s45.SecondaryRATDataUsageReportIEValue{}
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s45.BridgeSecondaryRATDataUsageReportIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SecondaryRATDataUsageReportItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.SecondaryRATDataUsageReportItemExtIEsValue)(nil))
		selectedAssert(&s05.SecondaryRATDataUsageReportItemExtIEsValue{})
		opaque := func() s05.SecondaryRATDataUsageReportItemExtIEsValue {
			sealed := s05.SecondaryRATDataUsageReportItemExtIEsValue{}
			*s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSecondaryRATDataUsageReportItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecondaryRATDataUsageReportItemIEValue", func(t *testing.T) {
		selectedAssert((*s28.SecondaryRATDataUsageReportItemIEValue)(nil))
		selectedAssert(&s28.SecondaryRATDataUsageReportItemIEValue{})
		opaque := func() s28.SecondaryRATDataUsageReportItemIEValue {
			sealed := s28.SecondaryRATDataUsageReportItemIEValue{}
			*s28.BridgeSecondaryRATDataUsageReportItemIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeSecondaryRATDataUsageReportItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.SecondaryRATDataUsageReportItemIEValue {
				sealed := s28.SecondaryRATDataUsageReportItemIEValue{}
				*s28.BridgeSecondaryRATDataUsageReportItemIEValueFieldId(&sealed) = s00.ProtocolIEID(265)
				*s28.BridgeSecondaryRATDataUsageReportItemIEValueFieldRowSecondaryRATDataUsageReportItem(&sealed) = new(s28.SecondaryRATDataUsageReportItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SecurityContextExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.SecurityContextExtIEsValue)(nil))
		selectedAssert(&s05.SecurityContextExtIEsValue{})
		opaque := func() s05.SecurityContextExtIEsValue {
			sealed := s05.SecurityContextExtIEsValue{}
			*s05.BridgeSecurityContextExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSecurityContextExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecurityIndicationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.SecurityIndicationExtIEsValue)(nil))
		selectedAssert(&s05.SecurityIndicationExtIEsValue{})
		opaque := func() s05.SecurityIndicationExtIEsValue {
			sealed := s05.SecurityIndicationExtIEsValue{}
			*s05.BridgeSecurityIndicationExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSecurityIndicationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SecurityResultExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.SecurityResultExtIEsValue)(nil))
		selectedAssert(&s05.SecurityResultExtIEsValue{})
		opaque := func() s05.SecurityResultExtIEsValue {
			sealed := s05.SecurityResultExtIEsValue{}
			*s05.BridgeSecurityResultExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSecurityResultExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorMeasConfigNameItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s05.SensorMeasConfigNameItemExtIEsValue)(nil))
		selectedAssert(&s05.SensorMeasConfigNameItemExtIEsValue{})
		opaque := func() s05.SensorMeasConfigNameItemExtIEsValue {
			sealed := s05.SensorMeasConfigNameItemExtIEsValue{}
			*s05.BridgeSensorMeasConfigNameItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s05.BridgeSensorMeasConfigNameItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SensorMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s06.SensorMeasurementConfigurationExtIEsValue{})
		opaque := func() s06.SensorMeasurementConfigurationExtIEsValue {
			sealed := s06.SensorMeasurementConfigurationExtIEsValue{}
			*s06.BridgeSensorMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSensorMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SensorNameConfigExtIEValue", func(t *testing.T) {
		selectedAssert((*s06.SensorNameConfigExtIEValue)(nil))
		selectedAssert(&s06.SensorNameConfigExtIEValue{})
		opaque := func() s06.SensorNameConfigExtIEValue {
			sealed := s06.SensorNameConfigExtIEValue{}
			*s06.BridgeSensorNameConfigExtIEValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSensorNameConfigExtIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ServedDCNsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.ServedDCNsItemExtIEsValue)(nil))
		selectedAssert(&s06.ServedDCNsItemExtIEsValue{})
		opaque := func() s06.ServedDCNsItemExtIEsValue {
			sealed := s06.ServedDCNsItemExtIEsValue{}
			*s06.BridgeServedDCNsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeServedDCNsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ServedGUMMEIsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.ServedGUMMEIsItemExtIEsValue)(nil))
		selectedAssert(&s06.ServedGUMMEIsItemExtIEsValue{})
		opaque := func() s06.ServedGUMMEIsItemExtIEsValue {
			sealed := s06.ServedGUMMEIsItemExtIEsValue{}
			*s06.BridgeServedGUMMEIsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeServedGUMMEIsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.ServedGUMMEIsItemExtIEsValue {
				sealed := s06.ServedGUMMEIsItemExtIEsValue{}
				*s06.BridgeServedGUMMEIsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s06.BridgeServedGUMMEIsItemExtIEsValueFieldRowGUMMEIType(&sealed) = new(s00.GUMMEIType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SourceNgRanNodeIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SourceNgRanNodeIDExtIEsValue)(nil))
		selectedAssert(&s06.SourceNgRanNodeIDExtIEsValue{})
		opaque := func() s06.SourceNgRanNodeIDExtIEsValue {
			sealed := s06.SourceNgRanNodeIDExtIEsValue{}
			*s06.BridgeSourceNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSourceNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceNodeIDExtensionIEIEValue", func(t *testing.T) {
		selectedAssert((*s06.SourceNodeIDExtensionIEIEValue)(nil))
		selectedAssert(&s06.SourceNodeIDExtensionIEIEValue{})
		opaque := func() s06.SourceNodeIDExtensionIEIEValue {
			sealed := s06.SourceNodeIDExtensionIEIEValue{}
			*s06.BridgeSourceNodeIDExtensionIEIEValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSourceNodeIDExtensionIEIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceeNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SourceeNBIDExtIEsValue)(nil))
		selectedAssert(&s06.SourceeNBIDExtIEsValue{})
		opaque := func() s06.SourceeNBIDExtIEsValue {
			sealed := s06.SourceeNBIDExtIEsValue{}
			*s06.BridgeSourceeNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSourceeNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SourceeNBToTargeteNBTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{})
		opaque := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
			*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(175)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowMobilityInformation(&sealed) = new(s00.S1APIEsMobilityInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(194)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEHistoryInformationFromTheUE(&sealed) = new(s00.UEHistoryInformationFromTheUE)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(296)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIMSvoiceEPSfallbackfrom5G(&sealed) = new(s00.IMSvoiceEPSfallbackfrom5G)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(300)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowContextatSource(&sealed) = new(s19.ContextatSource)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(311)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIntersystemMeasurementConfiguration(&sealed) = new(s24.IntersystemMeasurementConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(312)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceNodeID(&sealed) = new(s30.SourceNodeID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(326)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowEmergencyIndicator(&sealed) = new(s00.EmergencyIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(337)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEContextReferenceatSourceeNB(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(343)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceSNID(&sealed) = new(s19.GlobalRANNODEID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue {
				sealed := s34.SourceeNBToTargeteNBTransparentContainerExtIEsValue{}
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(350)
				*s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowTimeBasedHandoverInformation(&sealed) = new(s34.TimeBasedHandoverInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SubscriptionBasedUEDifferentiationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue)(nil))
		selectedAssert(&s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue{})
		opaque := func() s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue {
			sealed := s06.SubscriptionBasedUEDifferentiationInfoExtIEsValue{}
			*s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("SuccessfulValue", func(t *testing.T) {
		selectedAssert((*s50.SuccessfulValue)(nil))
		selectedAssert(&s50.SuccessfulValue{})
		opaque := func() s50.SuccessfulValue {
			sealed := s50.SuccessfulValue{}
			*s50.BridgeSuccessfulValueFieldIsOpaque(&sealed) = true
			*s50.BridgeSuccessfulValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s50.BridgeSuccessfulValueFieldBodyHandoverCommand(&sealed) = new(s40.HandoverCommand)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s50.BridgeSuccessfulValueFieldBodyHandoverRequestAcknowledge(&sealed) = new(s39.HandoverRequestAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s50.BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(&sealed) = new(s47.PathSwitchRequestAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s50.BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(&sealed) = new(s25.HandoverCancelAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s50.BridgeSuccessfulValueFieldBodyERABSetupResponse(&sealed) = new(s46.ERABSetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s50.BridgeSuccessfulValueFieldBodyERABModifyResponse(&sealed) = new(s46.ERABModifyResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s50.BridgeSuccessfulValueFieldBodyERABReleaseResponse(&sealed) = new(s46.ERABReleaseResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s50.BridgeSuccessfulValueFieldBodyInitialContextSetupResponse(&sealed) = new(s40.InitialContextSetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(14)
				*s50.BridgeSuccessfulValueFieldBodyResetAcknowledge(&sealed) = new(s44.ResetAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s50.BridgeSuccessfulValueFieldBodyS1SetupResponse(&sealed) = new(s43.S1SetupResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s50.BridgeSuccessfulValueFieldBodyUEContextModificationResponse(&sealed) = new(s36.UEContextModificationResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(23)
				*s50.BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(&sealed) = new(s46.UEContextReleaseComplete)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s50.BridgeSuccessfulValueFieldBodyENBConfigurationUpdateAcknowledge(&sealed) = new(s24.ENBConfigurationUpdateAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s50.BridgeSuccessfulValueFieldBodyMMEConfigurationUpdateAcknowledge(&sealed) = new(s25.MMEConfigurationUpdateAcknowledge)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(36)
				*s50.BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(&sealed) = new(s50.WriteReplaceWarningResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(43)
				*s50.BridgeSuccessfulValueFieldBodyKillResponse(&sealed) = new(s33.KillResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(48)
				*s50.BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(&sealed) = new(s37.UERadioCapabilityMatchResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(50)
				*s50.BridgeSuccessfulValueFieldBodyERABModificationConfirm(&sealed) = new(s39.ERABModificationConfirm)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(53)
				*s50.BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(&sealed) = new(s36.UEContextModificationConfirm)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(55)
				*s50.BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(&sealed) = new(s36.UEContextSuspendResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s50.BridgeSuccessfulValueFieldBodyUEContextResumeResponse(&sealed) = new(s38.UEContextResumeResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(63)
				*s50.BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(&sealed) = new(s36.UERadioCapabilityIDMappingResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s50.SuccessfulValue {
				sealed := s50.SuccessfulValue{}
				*s50.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s50.BridgeSuccessfulValueFieldBodyS1RemovalResponse(&sealed) = new(s26.S1RemovalResponse)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SupportedTAsItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SupportedTAsItemExtIEsValue)(nil))
		selectedAssert(&s06.SupportedTAsItemExtIEsValue{})
		opaque := func() s06.SupportedTAsItemExtIEsValue {
			sealed := s06.SupportedTAsItemExtIEsValue{}
			*s06.BridgeSupportedTAsItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSupportedTAsItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.SupportedTAsItemExtIEsValue {
				sealed := s06.SupportedTAsItemExtIEsValue{}
				*s06.BridgeSupportedTAsItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(232)
				*s06.BridgeSupportedTAsItemExtIEsValueFieldRowRATType(&sealed) = new(s00.RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("SynchronisationInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.SynchronisationInformationExtIEsValue)(nil))
		selectedAssert(&s06.SynchronisationInformationExtIEsValue{})
		opaque := func() s06.SynchronisationInformationExtIEsValue {
			sealed := s06.SynchronisationInformationExtIEsValue{}
			*s06.BridgeSynchronisationInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeSynchronisationInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TABasedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TABasedMDTExtIEsValue)(nil))
		selectedAssert(&s06.TABasedMDTExtIEsValue{})
		opaque := func() s06.TABasedMDTExtIEsValue {
			sealed := s06.TABasedMDTExtIEsValue{}
			*s06.BridgeTABasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTABasedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TABasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TABasedQMCExtIEsValue)(nil))
		selectedAssert(&s06.TABasedQMCExtIEsValue{})
		opaque := func() s06.TABasedQMCExtIEsValue {
			sealed := s06.TABasedQMCExtIEsValue{}
			*s06.BridgeTABasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTABasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBasedMDTExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAIBasedMDTExtIEsValue)(nil))
		selectedAssert(&s06.TAIBasedMDTExtIEsValue{})
		opaque := func() s06.TAIBasedMDTExtIEsValue {
			sealed := s06.TAIBasedMDTExtIEsValue{}
			*s06.BridgeTAIBasedMDTExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAIBasedMDTExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBasedQMCExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAIBasedQMCExtIEsValue)(nil))
		selectedAssert(&s06.TAIBasedQMCExtIEsValue{})
		opaque := func() s06.TAIBasedQMCExtIEsValue {
			sealed := s06.TAIBasedQMCExtIEsValue{}
			*s06.BridgeTAIBasedQMCExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAIBasedQMCExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIBroadcastItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAIBroadcastItemExtIEsValue)(nil))
		selectedAssert(&s06.TAIBroadcastItemExtIEsValue{})
		opaque := func() s06.TAIBroadcastItemExtIEsValue {
			sealed := s06.TAIBroadcastItemExtIEsValue{}
			*s06.BridgeTAIBroadcastItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAIBroadcastItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAICancelledItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAICancelledItemExtIEsValue)(nil))
		selectedAssert(&s06.TAICancelledItemExtIEsValue{})
		opaque := func() s06.TAICancelledItemExtIEsValue {
			sealed := s06.TAICancelledItemExtIEsValue{}
			*s06.BridgeTAICancelledItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAICancelledItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAIExtIEsValue)(nil))
		selectedAssert(&s06.TAIExtIEsValue{})
		opaque := func() s06.TAIExtIEsValue {
			sealed := s06.TAIExtIEsValue{}
			*s06.BridgeTAIExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAIExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TAIItemExtIEsValue)(nil))
		selectedAssert(&s06.TAIItemExtIEsValue{})
		opaque := func() s06.TAIItemExtIEsValue {
			sealed := s06.TAIItemExtIEsValue{}
			*s06.BridgeTAIItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTAIItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TAIItemIEValue", func(t *testing.T) {
		selectedAssert((*s33.TAIItemIEValue)(nil))
		selectedAssert(&s33.TAIItemIEValue{})
		opaque := func() s33.TAIItemIEValue {
			sealed := s33.TAIItemIEValue{}
			*s33.BridgeTAIItemIEValueFieldIsOpaque(&sealed) = true
			*s33.BridgeTAIItemIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s33.TAIItemIEValue {
				sealed := s33.TAIItemIEValue{}
				*s33.BridgeTAIItemIEValueFieldId(&sealed) = s00.ProtocolIEID(47)
				*s33.BridgeTAIItemIEValueFieldRowTAIItem(&sealed) = new(s33.TAIItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TargetNgRanNodeIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TargetNgRanNodeIDExtIEsValue)(nil))
		selectedAssert(&s06.TargetNgRanNodeIDExtIEsValue{})
		opaque := func() s06.TargetNgRanNodeIDExtIEsValue {
			sealed := s06.TargetNgRanNodeIDExtIEsValue{}
			*s06.BridgeTargetNgRanNodeIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTargetNgRanNodeIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargetRNCIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TargetRNCIDExtIEsValue)(nil))
		selectedAssert(&s06.TargetRNCIDExtIEsValue{})
		opaque := func() s06.TargetRNCIDExtIEsValue {
			sealed := s06.TargetRNCIDExtIEsValue{}
			*s06.BridgeTargetRNCIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTargetRNCIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargeteNBIDExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TargeteNBIDExtIEsValue)(nil))
		selectedAssert(&s06.TargeteNBIDExtIEsValue{})
		opaque := func() s06.TargeteNBIDExtIEsValue {
			sealed := s06.TargeteNBIDExtIEsValue{}
			*s06.BridgeTargeteNBIDExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTargeteNBIDExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TargeteNBToSourceeNBTransparentContainerExtIEsValue", func(t *testing.T) {
		selectedAssert((*s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue)(nil))
		selectedAssert(&s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{})
		opaque := func() s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
			sealed := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
			*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldIsOpaque(&sealed) = true
			*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(318)
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDAPSResponseInfoList(&sealed) = new(s14.DAPSResponseInfoList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(330)
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowRACSIndication(&sealed) = new(s00.RACSIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(335)
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowERABSecurityResultList(&sealed) = new(s30.ERABSecurityResultList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue {
				sealed := s39.TargeteNBToSourceeNBTransparentContainerExtIEsValue{}
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(79)
				*s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(&sealed) = new(s00.DirectForwardingPathAvailability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TimeBasedHandoverInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TimeBasedHandoverInformationExtIEsValue)(nil))
		selectedAssert(&s06.TimeBasedHandoverInformationExtIEsValue{})
		opaque := func() s06.TimeBasedHandoverInformationExtIEsValue {
			sealed := s06.TimeBasedHandoverInformationExtIEsValue{}
			*s06.BridgeTimeBasedHandoverInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTimeBasedHandoverInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("TimeSynchronisationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TimeSynchronisationInfoExtIEsValue)(nil))
		selectedAssert(&s06.TimeSynchronisationInfoExtIEsValue{})
		opaque := func() s06.TimeSynchronisationInfoExtIEsValue {
			sealed := s06.TimeSynchronisationInfoExtIEsValue{}
			*s06.BridgeTimeSynchronisationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTimeSynchronisationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.TimeSynchronisationInfoExtIEsValue {
				sealed := s06.TimeSynchronisationInfoExtIEsValue{}
				*s06.BridgeTimeSynchronisationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(207)
				*s06.BridgeTimeSynchronisationInfoExtIEsValueFieldRowMutingAvailabilityIndication(&sealed) = new(s00.MutingAvailabilityIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceActivationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s47.TraceActivationExtIEsValue)(nil))
		selectedAssert(&s47.TraceActivationExtIEsValue{})
		opaque := func() s47.TraceActivationExtIEsValue {
			sealed := s47.TraceActivationExtIEsValue{}
			*s47.BridgeTraceActivationExtIEsValueFieldIsOpaque(&sealed) = true
			*s47.BridgeTraceActivationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s47.TraceActivationExtIEsValue {
				sealed := s47.TraceActivationExtIEsValue{}
				*s47.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(162)
				*s47.BridgeTraceActivationExtIEsValueFieldRowMDTConfiguration(&sealed) = new(s47.MDTConfiguration)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.TraceActivationExtIEsValue {
				sealed := s47.TraceActivationExtIEsValue{}
				*s47.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(262)
				*s47.BridgeTraceActivationExtIEsValueFieldRowUEAppLayerMeasConfig(&sealed) = new(s35.UEAppLayerMeasConfig)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.TraceActivationExtIEsValue {
				sealed := s47.TraceActivationExtIEsValue{}
				*s47.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(316)
				*s47.BridgeTraceActivationExtIEsValueFieldRowMDTConfigurationNR(&sealed) = new(s00.MDTConfigurationNR)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s47.TraceActivationExtIEsValue {
				sealed := s47.TraceActivationExtIEsValue{}
				*s47.BridgeTraceActivationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(325)
				*s47.BridgeTraceActivationExtIEsValueFieldRowTraceCollectionEntityURI(&sealed) = new(s00.URIAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceFailureIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s20.TraceFailureIndicationIEValue)(nil))
		selectedAssert(&s20.TraceFailureIndicationIEValue{})
		opaque := func() s20.TraceFailureIndicationIEValue {
			sealed := s20.TraceFailureIndicationIEValue{}
			*s20.BridgeTraceFailureIndicationIEValueFieldIsOpaque(&sealed) = true
			*s20.BridgeTraceFailureIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(86)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowEUTRANTraceID(&sealed) = new(s00.EUTRANTraceID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s20.TraceFailureIndicationIEValue {
				sealed := s20.TraceFailureIndicationIEValue{}
				*s20.BridgeTraceFailureIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s20.BridgeTraceFailureIndicationIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TraceStartIEValue", func(t *testing.T) {
		selectedAssert((*s48.TraceStartIEValue)(nil))
		selectedAssert(&s48.TraceStartIEValue{})
		opaque := func() s48.TraceStartIEValue {
			sealed := s48.TraceStartIEValue{}
			*s48.BridgeTraceStartIEValueFieldIsOpaque(&sealed) = true
			*s48.BridgeTraceStartIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s48.TraceStartIEValue {
				sealed := s48.TraceStartIEValue{}
				*s48.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeTraceStartIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.TraceStartIEValue {
				sealed := s48.TraceStartIEValue{}
				*s48.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s48.BridgeTraceStartIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s48.TraceStartIEValue {
				sealed := s48.TraceStartIEValue{}
				*s48.BridgeTraceStartIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s48.BridgeTraceStartIEValueFieldRowTraceActivation(&sealed) = new(s47.TraceActivation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("TunnelInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.TunnelInformationExtIEsValue)(nil))
		selectedAssert(&s06.TunnelInformationExtIEsValue{})
		opaque := func() s06.TunnelInformationExtIEsValue {
			sealed := s06.TunnelInformationExtIEsValue{}
			*s06.BridgeTunnelInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeTunnelInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UEAggregateMaximumBitratesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.UEAggregateMaximumBitratesExtIEsValue)(nil))
		selectedAssert(&s06.UEAggregateMaximumBitratesExtIEsValue{})
		opaque := func() s06.UEAggregateMaximumBitratesExtIEsValue {
			sealed := s06.UEAggregateMaximumBitratesExtIEsValue{}
			*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s06.UEAggregateMaximumBitratesExtIEsValue {
				sealed := s06.UEAggregateMaximumBitratesExtIEsValue{}
				*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(259)
				*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldRowExtendedUEaggregateMaximumBitRateDL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s06.UEAggregateMaximumBitratesExtIEsValue {
				sealed := s06.UEAggregateMaximumBitratesExtIEsValue{}
				*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(260)
				*s06.BridgeUEAggregateMaximumBitratesExtIEsValueFieldRowExtendedUEaggregateMaximumBitRateUL(&sealed) = new(s00.ExtendedBitRate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAppLayerMeasConfigExtIEsValue", func(t *testing.T) {
		selectedAssert((*s07.UEAppLayerMeasConfigExtIEsValue)(nil))
		selectedAssert(&s07.UEAppLayerMeasConfigExtIEsValue{})
		opaque := func() s07.UEAppLayerMeasConfigExtIEsValue {
			sealed := s07.UEAppLayerMeasConfigExtIEsValue{}
			*s07.BridgeUEAppLayerMeasConfigExtIEsValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUEAppLayerMeasConfigExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s07.UEAppLayerMeasConfigExtIEsValue {
				sealed := s07.UEAppLayerMeasConfigExtIEsValue{}
				*s07.BridgeUEAppLayerMeasConfigExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(276)
				*s07.BridgeUEAppLayerMeasConfigExtIEsValueFieldRowServiceType(&sealed) = new(s00.ServiceType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue)(nil))
		selectedAssert(&s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue{})
		opaque := func() s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue {
			sealed := s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue{}
			*s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemResAckIEValue", func(t *testing.T) {
		selectedAssert((*s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue)(nil))
		selectedAssert(&s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue{})
		opaque := func() s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue {
			sealed := s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue{}
			*s35.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldIsOpaque(&sealed) = true
			*s35.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue {
				sealed := s35.UEAssociatedLogicalS1ConnectionItemResAckIEValue{}
				*s35.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldId(&sealed) = s00.ProtocolIEID(91)
				*s35.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(&sealed) = new(s35.UEAssociatedLogicalS1ConnectionItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEAssociatedLogicalS1ConnectionItemResIEValue", func(t *testing.T) {
		selectedAssert((*s35.UEAssociatedLogicalS1ConnectionItemResIEValue)(nil))
		selectedAssert(&s35.UEAssociatedLogicalS1ConnectionItemResIEValue{})
		opaque := func() s35.UEAssociatedLogicalS1ConnectionItemResIEValue {
			sealed := s35.UEAssociatedLogicalS1ConnectionItemResIEValue{}
			*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldIsOpaque(&sealed) = true
			*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s35.UEAssociatedLogicalS1ConnectionItemResIEValue {
				sealed := s35.UEAssociatedLogicalS1ConnectionItemResIEValue{}
				*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldId(&sealed) = s00.ProtocolIEID(91)
				*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(&sealed) = new(s35.UEAssociatedLogicalS1ConnectionItem)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UECapabilityInfoIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s12.UECapabilityInfoIndicationIEValue)(nil))
		selectedAssert(&s12.UECapabilityInfoIndicationIEValue{})
		opaque := func() s12.UECapabilityInfoIndicationIEValue {
			sealed := s12.UECapabilityInfoIndicationIEValue{}
			*s12.BridgeUECapabilityInfoIndicationIEValueFieldIsOpaque(&sealed) = true
			*s12.BridgeUECapabilityInfoIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(198)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityForPaging(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = new(s00.UEApplicationLayerMeasurementCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(272)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowLTEMIndication(&sealed) = new(s00.LTEMIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(315)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityNRFormat(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UECapabilityInfoIndicationIEValue {
				sealed := s12.UECapabilityInfoIndicationIEValue{}
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(327)
				*s12.BridgeUECapabilityInfoIndicationIEValueFieldRowUERadioCapabilityForPagingNRFormat(&sealed) = new(s00.UERadioCapabilityForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationConfirmIEValue", func(t *testing.T) {
		selectedAssert((*s23.UEContextModificationConfirmIEValue)(nil))
		selectedAssert(&s23.UEContextModificationConfirmIEValue{})
		opaque := func() s23.UEContextModificationConfirmIEValue {
			sealed := s23.UEContextModificationConfirmIEValue{}
			*s23.BridgeUEContextModificationConfirmIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeUEContextModificationConfirmIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.UEContextModificationConfirmIEValue {
				sealed := s23.UEContextModificationConfirmIEValue{}
				*s23.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeUEContextModificationConfirmIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationConfirmIEValue {
				sealed := s23.UEContextModificationConfirmIEValue{}
				*s23.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeUEContextModificationConfirmIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationConfirmIEValue {
				sealed := s23.UEContextModificationConfirmIEValue{}
				*s23.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s23.BridgeUEContextModificationConfirmIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationConfirmIEValue {
				sealed := s23.UEContextModificationConfirmIEValue{}
				*s23.BridgeUEContextModificationConfirmIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeUEContextModificationConfirmIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.UEContextModificationFailureIEValue)(nil))
		selectedAssert(&s23.UEContextModificationFailureIEValue{})
		opaque := func() s23.UEContextModificationFailureIEValue {
			sealed := s23.UEContextModificationFailureIEValue{}
			*s23.BridgeUEContextModificationFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeUEContextModificationFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.UEContextModificationFailureIEValue {
				sealed := s23.UEContextModificationFailureIEValue{}
				*s23.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeUEContextModificationFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationFailureIEValue {
				sealed := s23.UEContextModificationFailureIEValue{}
				*s23.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeUEContextModificationFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationFailureIEValue {
				sealed := s23.UEContextModificationFailureIEValue{}
				*s23.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgeUEContextModificationFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationFailureIEValue {
				sealed := s23.UEContextModificationFailureIEValue{}
				*s23.BridgeUEContextModificationFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeUEContextModificationFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationIndicationIEValue", func(t *testing.T) {
		selectedAssert((*s21.UEContextModificationIndicationIEValue)(nil))
		selectedAssert(&s21.UEContextModificationIndicationIEValue{})
		opaque := func() s21.UEContextModificationIndicationIEValue {
			sealed := s21.UEContextModificationIndicationIEValue{}
			*s21.BridgeUEContextModificationIndicationIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeUEContextModificationIndicationIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.UEContextModificationIndicationIEValue {
				sealed := s21.UEContextModificationIndicationIEValue{}
				*s21.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s21.BridgeUEContextModificationIndicationIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UEContextModificationIndicationIEValue {
				sealed := s21.UEContextModificationIndicationIEValue{}
				*s21.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s21.BridgeUEContextModificationIndicationIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UEContextModificationIndicationIEValue {
				sealed := s21.UEContextModificationIndicationIEValue{}
				*s21.BridgeUEContextModificationIndicationIEValueFieldId(&sealed) = s00.ProtocolIEID(226)
				*s21.BridgeUEContextModificationIndicationIEValueFieldRowCSGMembershipInfo(&sealed) = new(s14.CSGMembershipInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationRequestIEValue", func(t *testing.T) {
		selectedAssert((*s46.UEContextModificationRequestIEValue)(nil))
		selectedAssert(&s46.UEContextModificationRequestIEValue{})
		opaque := func() s46.UEContextModificationRequestIEValue {
			sealed := s46.UEContextModificationRequestIEValue{}
			*s46.BridgeUEContextModificationRequestIEValueFieldIsOpaque(&sealed) = true
			*s46.BridgeUEContextModificationRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(73)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(&sealed) = new(s00.SecurityKey)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(106)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(&sealed) = new(s00.SubscriberProfileIDforRFP)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = new(s35.UEAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(108)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(&sealed) = new(s00.CSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(&sealed) = new(s37.UESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(&sealed) = new(s00.CSGMembershipStatus)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(159)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(&sealed) = new(s18.LAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(187)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(&sealed) = new(s00.AdditionalCSFallbackIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(&sealed) = new(s20.ProSeAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = new(s00.SRVCCOperationPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(243)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(&sealed) = new(s00.SRVCCOperationNotPossible)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = new(s46.V2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = new(s37.UESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = new(s19.NRUESecurityCapabilities)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = new(s00.AerialUEsubscriptionInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = new(s00.AdditionalRRMPriorityIndex)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(&sealed) = new(s00.IABAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = new(s19.NRV2XServicesAuthorized)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = new(s19.NRUESidelinkAggregateMaximumBitrate)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(&sealed) = new(s24.PC5QoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s46.UEContextModificationRequestIEValue {
				sealed := s46.UEContextModificationRequestIEValue{}
				*s46.BridgeUEContextModificationRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s46.BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(&sealed) = new(s00.TimeRefDistribution)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextModificationResponseIEValue", func(t *testing.T) {
		selectedAssert((*s23.UEContextModificationResponseIEValue)(nil))
		selectedAssert(&s23.UEContextModificationResponseIEValue{})
		opaque := func() s23.UEContextModificationResponseIEValue {
			sealed := s23.UEContextModificationResponseIEValue{}
			*s23.BridgeUEContextModificationResponseIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeUEContextModificationResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.UEContextModificationResponseIEValue {
				sealed := s23.UEContextModificationResponseIEValue{}
				*s23.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeUEContextModificationResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationResponseIEValue {
				sealed := s23.UEContextModificationResponseIEValue{}
				*s23.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeUEContextModificationResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextModificationResponseIEValue {
				sealed := s23.UEContextModificationResponseIEValue{}
				*s23.BridgeUEContextModificationResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeUEContextModificationResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseCommandIEValue", func(t *testing.T) {
		selectedAssert((*s37.UEContextReleaseCommandIEValue)(nil))
		selectedAssert(&s37.UEContextReleaseCommandIEValue{})
		opaque := func() s37.UEContextReleaseCommandIEValue {
			sealed := s37.UEContextReleaseCommandIEValue{}
			*s37.BridgeUEContextReleaseCommandIEValueFieldIsOpaque(&sealed) = true
			*s37.BridgeUEContextReleaseCommandIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s37.UEContextReleaseCommandIEValue {
				sealed := s37.UEContextReleaseCommandIEValue{}
				*s37.BridgeUEContextReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(99)
				*s37.BridgeUEContextReleaseCommandIEValueFieldRowUES1APIDs(&sealed) = new(s37.UES1APIDs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s37.UEContextReleaseCommandIEValue {
				sealed := s37.UEContextReleaseCommandIEValue{}
				*s37.BridgeUEContextReleaseCommandIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s37.BridgeUEContextReleaseCommandIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseCompleteIEValue", func(t *testing.T) {
		selectedAssert((*s45.UEContextReleaseCompleteIEValue)(nil))
		selectedAssert(&s45.UEContextReleaseCompleteIEValue{})
		opaque := func() s45.UEContextReleaseCompleteIEValue {
			sealed := s45.UEContextReleaseCompleteIEValue{}
			*s45.BridgeUEContextReleaseCompleteIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeUEContextReleaseCompleteIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = new(s33.InformationOnRecommendedCellsAndENBsForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = new(s17.CellIdentifierAndCELevelForCECapableUEs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextReleaseCompleteIEValue {
				sealed := s45.UEContextReleaseCompleteIEValue{}
				*s45.BridgeUEContextReleaseCompleteIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s45.BridgeUEContextReleaseCompleteIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextReleaseRequestIEValue", func(t *testing.T) {
		selectedAssert((*s43.UEContextReleaseRequestIEValue)(nil))
		selectedAssert(&s43.UEContextReleaseRequestIEValue{})
		opaque := func() s43.UEContextReleaseRequestIEValue {
			sealed := s43.UEContextReleaseRequestIEValue{}
			*s43.BridgeUEContextReleaseRequestIEValueFieldIsOpaque(&sealed) = true
			*s43.BridgeUEContextReleaseRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s43.UEContextReleaseRequestIEValue {
				sealed := s43.UEContextReleaseRequestIEValue{}
				*s43.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s43.BridgeUEContextReleaseRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.UEContextReleaseRequestIEValue {
				sealed := s43.UEContextReleaseRequestIEValue{}
				*s43.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s43.BridgeUEContextReleaseRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.UEContextReleaseRequestIEValue {
				sealed := s43.UEContextReleaseRequestIEValue{}
				*s43.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s43.BridgeUEContextReleaseRequestIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.UEContextReleaseRequestIEValue {
				sealed := s43.UEContextReleaseRequestIEValue{}
				*s43.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(164)
				*s43.BridgeUEContextReleaseRequestIEValueFieldRowGWContextReleaseIndication(&sealed) = new(s00.GWContextReleaseIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s43.UEContextReleaseRequestIEValue {
				sealed := s43.UEContextReleaseRequestIEValue{}
				*s43.BridgeUEContextReleaseRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s43.BridgeUEContextReleaseRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeFailureIEValue", func(t *testing.T) {
		selectedAssert((*s23.UEContextResumeFailureIEValue)(nil))
		selectedAssert(&s23.UEContextResumeFailureIEValue{})
		opaque := func() s23.UEContextResumeFailureIEValue {
			sealed := s23.UEContextResumeFailureIEValue{}
			*s23.BridgeUEContextResumeFailureIEValueFieldIsOpaque(&sealed) = true
			*s23.BridgeUEContextResumeFailureIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s23.UEContextResumeFailureIEValue {
				sealed := s23.UEContextResumeFailureIEValue{}
				*s23.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s23.BridgeUEContextResumeFailureIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextResumeFailureIEValue {
				sealed := s23.UEContextResumeFailureIEValue{}
				*s23.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s23.BridgeUEContextResumeFailureIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextResumeFailureIEValue {
				sealed := s23.UEContextResumeFailureIEValue{}
				*s23.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s23.BridgeUEContextResumeFailureIEValueFieldRowCause(&sealed) = new(s14.Cause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s23.UEContextResumeFailureIEValue {
				sealed := s23.UEContextResumeFailureIEValue{}
				*s23.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s23.BridgeUEContextResumeFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeRequestIEValue", func(t *testing.T) {
		selectedAssert((*s38.UEContextResumeRequestIEValue)(nil))
		selectedAssert(&s38.UEContextResumeRequestIEValue{})
		opaque := func() s38.UEContextResumeRequestIEValue {
			sealed := s38.UEContextResumeRequestIEValue{}
			*s38.BridgeUEContextResumeRequestIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeUEContextResumeRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.UEContextResumeRequestIEValue {
				sealed := s38.UEContextResumeRequestIEValue{}
				*s38.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s38.BridgeUEContextResumeRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeRequestIEValue {
				sealed := s38.UEContextResumeRequestIEValue{}
				*s38.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s38.BridgeUEContextResumeRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeRequestIEValue {
				sealed := s38.UEContextResumeRequestIEValue{}
				*s38.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(235)
				*s38.BridgeUEContextResumeRequestIEValueFieldRowERABFailedToResumeListResumeReq(&sealed) = new(s16.ERABFailedToResumeListResumeReq)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeRequestIEValue {
				sealed := s38.UEContextResumeRequestIEValue{}
				*s38.BridgeUEContextResumeRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(245)
				*s38.BridgeUEContextResumeRequestIEValueFieldRowRRCResumeCause(&sealed) = new(s00.RRCEstablishmentCause)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextResumeResponseIEValue", func(t *testing.T) {
		selectedAssert((*s38.UEContextResumeResponseIEValue)(nil))
		selectedAssert(&s38.UEContextResumeResponseIEValue{})
		opaque := func() s38.UEContextResumeResponseIEValue {
			sealed := s38.UEContextResumeResponseIEValue{}
			*s38.BridgeUEContextResumeResponseIEValueFieldIsOpaque(&sealed) = true
			*s38.BridgeUEContextResumeResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(237)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowERABFailedToResumeListResumeRes(&sealed) = new(s16.ERABFailedToResumeListResumeRes)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowSecurityContext(&sealed) = new(s28.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.UEContextResumeResponseIEValue {
				sealed := s38.UEContextResumeResponseIEValue{}
				*s38.BridgeUEContextResumeResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s38.BridgeUEContextResumeResponseIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextSuspendRequestIEValue", func(t *testing.T) {
		selectedAssert((*s45.UEContextSuspendRequestIEValue)(nil))
		selectedAssert(&s45.UEContextSuspendRequestIEValue{})
		opaque := func() s45.UEContextSuspendRequestIEValue {
			sealed := s45.UEContextSuspendRequestIEValue{}
			*s45.BridgeUEContextSuspendRequestIEValueFieldIsOpaque(&sealed) = true
			*s45.BridgeUEContextSuspendRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(213)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowInformationOnRecommendedCellsAndENBsForPaging(&sealed) = new(s33.InformationOnRecommendedCellsAndENBsForPaging)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(212)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowCellIdentifierAndCELevelForCECapableUEs(&sealed) = new(s17.CellIdentifierAndCELevelForCECapableUEs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(264)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowSecondaryRATDataUsageReportList(&sealed) = new(s28.SecondaryRATDataUsageReportList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(189)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowUserLocationInformation(&sealed) = new(s44.UserLocationInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s45.UEContextSuspendRequestIEValue {
				sealed := s45.UEContextSuspendRequestIEValue{}
				*s45.BridgeUEContextSuspendRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(297)
				*s45.BridgeUEContextSuspendRequestIEValueFieldRowTimeSinceSecondaryNodeRelease(&sealed) = new(s00.TimeSinceSecondaryNodeRelease)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEContextSuspendResponseIEValue", func(t *testing.T) {
		selectedAssert((*s28.UEContextSuspendResponseIEValue)(nil))
		selectedAssert(&s28.UEContextSuspendResponseIEValue{})
		opaque := func() s28.UEContextSuspendResponseIEValue {
			sealed := s28.UEContextSuspendResponseIEValue{}
			*s28.BridgeUEContextSuspendResponseIEValueFieldIsOpaque(&sealed) = true
			*s28.BridgeUEContextSuspendResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s28.UEContextSuspendResponseIEValue {
				sealed := s28.UEContextSuspendResponseIEValue{}
				*s28.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s28.BridgeUEContextSuspendResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UEContextSuspendResponseIEValue {
				sealed := s28.UEContextSuspendResponseIEValue{}
				*s28.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s28.BridgeUEContextSuspendResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UEContextSuspendResponseIEValue {
				sealed := s28.UEContextSuspendResponseIEValue{}
				*s28.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s28.BridgeUEContextSuspendResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s28.UEContextSuspendResponseIEValue {
				sealed := s28.UEContextSuspendResponseIEValue{}
				*s28.BridgeUEContextSuspendResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s28.BridgeUEContextSuspendResponseIEValueFieldRowSecurityContext(&sealed) = new(s28.SecurityContext)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UEInformationTransferIEValue", func(t *testing.T) {
		selectedAssert((*s31.UEInformationTransferIEValue)(nil))
		selectedAssert(&s31.UEInformationTransferIEValue{})
		opaque := func() s31.UEInformationTransferIEValue {
			sealed := s31.UEInformationTransferIEValue{}
			*s31.BridgeUEInformationTransferIEValueFieldIsOpaque(&sealed) = true
			*s31.BridgeUEInformationTransferIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s31.BridgeUEInformationTransferIEValueFieldRowSTMSI(&sealed) = new(s28.STMSI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(252)
				*s31.BridgeUEInformationTransferIEValueFieldRowUELevelQoSParameters(&sealed) = new(s18.ERABLevelQoSParameters)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s31.BridgeUEInformationTransferIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s31.BridgeUEInformationTransferIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = new(s30.SubscriptionBasedUEDifferentiationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s31.BridgeUEInformationTransferIEValueFieldRowPendingDataIndication(&sealed) = new(s00.PendingDataIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s31.UEInformationTransferIEValue {
				sealed := s31.UEInformationTransferIEValue{}
				*s31.BridgeUEInformationTransferIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s31.BridgeUEInformationTransferIEValueFieldRowMaskedIMEISV(&sealed) = new(s00.MaskedIMEISV)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityIDMappingRequestIEValue", func(t *testing.T) {
		selectedAssert((*s07.UERadioCapabilityIDMappingRequestIEValue)(nil))
		selectedAssert(&s07.UERadioCapabilityIDMappingRequestIEValue{})
		opaque := func() s07.UERadioCapabilityIDMappingRequestIEValue {
			sealed := s07.UERadioCapabilityIDMappingRequestIEValue{}
			*s07.BridgeUERadioCapabilityIDMappingRequestIEValueFieldIsOpaque(&sealed) = true
			*s07.BridgeUERadioCapabilityIDMappingRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s07.UERadioCapabilityIDMappingRequestIEValue {
				sealed := s07.UERadioCapabilityIDMappingRequestIEValue{}
				*s07.BridgeUERadioCapabilityIDMappingRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s07.BridgeUERadioCapabilityIDMappingRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityIDMappingResponseIEValue", func(t *testing.T) {
		selectedAssert((*s24.UERadioCapabilityIDMappingResponseIEValue)(nil))
		selectedAssert(&s24.UERadioCapabilityIDMappingResponseIEValue{})
		opaque := func() s24.UERadioCapabilityIDMappingResponseIEValue {
			sealed := s24.UERadioCapabilityIDMappingResponseIEValue{}
			*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s24.UERadioCapabilityIDMappingResponseIEValue{}
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s24.UERadioCapabilityIDMappingResponseIEValue{}
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UERadioCapabilityIDMappingResponseIEValue {
				sealed := s24.UERadioCapabilityIDMappingResponseIEValue{}
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s24.BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityMatchRequestIEValue", func(t *testing.T) {
		selectedAssert((*s12.UERadioCapabilityMatchRequestIEValue)(nil))
		selectedAssert(&s12.UERadioCapabilityMatchRequestIEValue{})
		opaque := func() s12.UERadioCapabilityMatchRequestIEValue {
			sealed := s12.UERadioCapabilityMatchRequestIEValue{}
			*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldIsOpaque(&sealed) = true
			*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s12.UERadioCapabilityMatchRequestIEValue {
				sealed := s12.UERadioCapabilityMatchRequestIEValue{}
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UERadioCapabilityMatchRequestIEValue {
				sealed := s12.UERadioCapabilityMatchRequestIEValue{}
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UERadioCapabilityMatchRequestIEValue {
				sealed := s12.UERadioCapabilityMatchRequestIEValue{}
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(74)
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldRowUERadioCapability(&sealed) = new(s00.UERadioCapability)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UERadioCapabilityMatchRequestIEValue {
				sealed := s12.UERadioCapabilityMatchRequestIEValue{}
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s12.BridgeUERadioCapabilityMatchRequestIEValueFieldRowUERadioCapabilityID(&sealed) = new(s00.UERadioCapabilityID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UERadioCapabilityMatchResponseIEValue", func(t *testing.T) {
		selectedAssert((*s24.UERadioCapabilityMatchResponseIEValue)(nil))
		selectedAssert(&s24.UERadioCapabilityMatchResponseIEValue{})
		opaque := func() s24.UERadioCapabilityMatchResponseIEValue {
			sealed := s24.UERadioCapabilityMatchResponseIEValue{}
			*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldIsOpaque(&sealed) = true
			*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s24.UERadioCapabilityMatchResponseIEValue {
				sealed := s24.UERadioCapabilityMatchResponseIEValue{}
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UERadioCapabilityMatchResponseIEValue {
				sealed := s24.UERadioCapabilityMatchResponseIEValue{}
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UERadioCapabilityMatchResponseIEValue {
				sealed := s24.UERadioCapabilityMatchResponseIEValue{}
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(169)
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldRowVoiceSupportMatchIndicator(&sealed) = new(s00.VoiceSupportMatchIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s24.UERadioCapabilityMatchResponseIEValue {
				sealed := s24.UERadioCapabilityMatchResponseIEValue{}
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s24.BridgeUERadioCapabilityMatchResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UES1APIDPairExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.UES1APIDPairExtIEsValue)(nil))
		selectedAssert(&s06.UES1APIDPairExtIEsValue{})
		opaque := func() s06.UES1APIDPairExtIEsValue {
			sealed := s06.UES1APIDPairExtIEsValue{}
			*s06.BridgeUES1APIDPairExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeUES1APIDPairExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UESecurityCapabilitiesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.UESecurityCapabilitiesExtIEsValue)(nil))
		selectedAssert(&s06.UESecurityCapabilitiesExtIEsValue{})
		opaque := func() s06.UESecurityCapabilitiesExtIEsValue {
			sealed := s06.UESecurityCapabilitiesExtIEsValue{}
			*s06.BridgeUESecurityCapabilitiesExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeUESecurityCapabilitiesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UESidelinkAggregateMaximumBitratesExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.UESidelinkAggregateMaximumBitratesExtIEsValue)(nil))
		selectedAssert(&s06.UESidelinkAggregateMaximumBitratesExtIEsValue{})
		opaque := func() s06.UESidelinkAggregateMaximumBitratesExtIEsValue {
			sealed := s06.UESidelinkAggregateMaximumBitratesExtIEsValue{}
			*s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("ULCPSecurityInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.ULCPSecurityInformationExtIEsValue)(nil))
		selectedAssert(&s06.ULCPSecurityInformationExtIEsValue{})
		opaque := func() s06.ULCPSecurityInformationExtIEsValue {
			sealed := s06.ULCPSecurityInformationExtIEsValue{}
			*s06.BridgeULCPSecurityInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeULCPSecurityInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("UnsuccessfulValue", func(t *testing.T) {
		selectedAssert((*s36.UnsuccessfulValue)(nil))
		selectedAssert(&s36.UnsuccessfulValue{})
		opaque := func() s36.UnsuccessfulValue {
			sealed := s36.UnsuccessfulValue{}
			*s36.BridgeUnsuccessfulValueFieldIsOpaque(&sealed) = true
			*s36.BridgeUnsuccessfulValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s36.BridgeUnsuccessfulValueFieldBodyHandoverPreparationFailure(&sealed) = new(s25.HandoverPreparationFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(1)
				*s36.BridgeUnsuccessfulValueFieldBodyHandoverFailure(&sealed) = new(s25.HandoverFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s36.BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(&sealed) = new(s26.PathSwitchRequestFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s36.BridgeUnsuccessfulValueFieldBodyInitialContextSetupFailure(&sealed) = new(s25.InitialContextSetupFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(17)
				*s36.BridgeUnsuccessfulValueFieldBodyS1SetupFailure(&sealed) = new(s26.S1SetupFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(21)
				*s36.BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(&sealed) = new(s36.UEContextModificationFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(29)
				*s36.BridgeUnsuccessfulValueFieldBodyENBConfigurationUpdateFailure(&sealed) = new(s24.ENBConfigurationUpdateFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(30)
				*s36.BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(&sealed) = new(s25.MMEConfigurationUpdateFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(56)
				*s36.BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(&sealed) = new(s36.UEContextResumeFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s36.UnsuccessfulValue {
				sealed := s36.UnsuccessfulValue{}
				*s36.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(67)
				*s36.BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(&sealed) = new(s26.S1RemovalFailure)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkNASTransportIEValue", func(t *testing.T) {
		selectedAssert((*s32.UplinkNASTransportIEValue)(nil))
		selectedAssert(&s32.UplinkNASTransportIEValue{})
		opaque := func() s32.UplinkNASTransportIEValue {
			sealed := s32.UplinkNASTransportIEValue{}
			*s32.BridgeUplinkNASTransportIEValueFieldIsOpaque(&sealed) = true
			*s32.BridgeUplinkNASTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s32.BridgeUplinkNASTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s32.BridgeUplinkNASTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s32.BridgeUplinkNASTransportIEValueFieldRowNASPDU(&sealed) = new(s00.NASPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s32.BridgeUplinkNASTransportIEValueFieldRowEUTRANCGI(&sealed) = new(s17.EUTRANCGI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s32.BridgeUplinkNASTransportIEValueFieldRowTAI(&sealed) = new(s31.TAI)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
				*s32.BridgeUplinkNASTransportIEValueFieldRowGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
				*s32.BridgeUplinkNASTransportIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = new(s00.TransportLayerAddress)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s32.BridgeUplinkNASTransportIEValueFieldRowLHNID(&sealed) = new(s00.LHNID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s32.BridgeUplinkNASTransportIEValueFieldRowPSCellInformation(&sealed) = new(s20.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.UplinkNASTransportIEValue {
				sealed := s32.UplinkNASTransportIEValue{}
				*s32.BridgeUplinkNASTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s32.BridgeUplinkNASTransportIEValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkNonUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s12.UplinkNonUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s12.UplinkNonUEAssociatedLPPaTransportIEValue{})
		opaque := func() s12.UplinkNonUEAssociatedLPPaTransportIEValue {
			sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValue{}
			*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s12.UplinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UplinkNonUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkS1cdma2000tunnellingIEValue", func(t *testing.T) {
		selectedAssert((*s21.UplinkS1cdma2000tunnellingIEValue)(nil))
		selectedAssert(&s21.UplinkS1cdma2000tunnellingIEValue{})
		opaque := func() s21.UplinkS1cdma2000tunnellingIEValue {
			sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
			*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldIsOpaque(&sealed) = true
			*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = new(s00.Cdma2000RATType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(72)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(&sealed) = new(s00.Cdma2000SectorID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(84)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(&sealed) = new(s00.Cdma2000HORequiredIndication)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(102)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(&sealed) = new(s14.Cdma2000OneXSRVCCInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(97)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(&sealed) = new(s00.Cdma2000OneXRAND)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = new(s00.Cdma2000PDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UplinkS1cdma2000tunnellingIEValue {
				sealed := s21.UplinkS1cdma2000tunnellingIEValue{}
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(140)
				*s21.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(&sealed) = new(s00.EUTRANRoundTripDelayEstimationInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UplinkUEAssociatedLPPaTransportIEValue", func(t *testing.T) {
		selectedAssert((*s12.UplinkUEAssociatedLPPaTransportIEValue)(nil))
		selectedAssert(&s12.UplinkUEAssociatedLPPaTransportIEValue{})
		opaque := func() s12.UplinkUEAssociatedLPPaTransportIEValue {
			sealed := s12.UplinkUEAssociatedLPPaTransportIEValue{}
			*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldIsOpaque(&sealed) = true
			*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s12.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowMMEUES1APID(&sealed) = new(s00.MMEUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowENBUES1APID(&sealed) = new(s00.ENBUES1APID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(148)
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowRoutingID(&sealed) = new(s00.RoutingID)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s12.UplinkUEAssociatedLPPaTransportIEValue {
				sealed := s12.UplinkUEAssociatedLPPaTransportIEValue{}
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldId(&sealed) = s00.ProtocolIEID(147)
				*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueFieldRowLPPaPDU(&sealed) = new(s00.LPPaPDU)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("UserLocationInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s21.UserLocationInformationExtIEsValue)(nil))
		selectedAssert(&s21.UserLocationInformationExtIEsValue{})
		opaque := func() s21.UserLocationInformationExtIEsValue {
			sealed := s21.UserLocationInformationExtIEsValue{}
			*s21.BridgeUserLocationInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s21.BridgeUserLocationInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s21.UserLocationInformationExtIEsValue {
				sealed := s21.UserLocationInformationExtIEsValue{}
				*s21.BridgeUserLocationInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(288)
				*s21.BridgeUserLocationInformationExtIEsValueFieldRowPSCellInformation(&sealed) = new(s20.PSCellInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s21.UserLocationInformationExtIEsValue {
				sealed := s21.UserLocationInformationExtIEsValue{}
				*s21.BridgeUserLocationInformationExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s21.BridgeUserLocationInformationExtIEsValueFieldRowLTENTNTAIInformation(&sealed) = new(s18.LTENTNTAIInformation)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("V2XServicesAuthorizedExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.V2XServicesAuthorizedExtIEsValue)(nil))
		selectedAssert(&s06.V2XServicesAuthorizedExtIEsValue{})
		opaque := func() s06.V2XServicesAuthorizedExtIEsValue {
			sealed := s06.V2XServicesAuthorizedExtIEsValue{}
			*s06.BridgeV2XServicesAuthorizedExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeV2XServicesAuthorizedExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WLANMeasurementConfigurationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.WLANMeasurementConfigurationExtIEsValue)(nil))
		selectedAssert(&s06.WLANMeasurementConfigurationExtIEsValue{})
		opaque := func() s06.WLANMeasurementConfigurationExtIEsValue {
			sealed := s06.WLANMeasurementConfigurationExtIEsValue{}
			*s06.BridgeWLANMeasurementConfigurationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeWLANMeasurementConfigurationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WUSAssistanceInformationExtIEsValue", func(t *testing.T) {
		selectedAssert((*s06.WUSAssistanceInformationExtIEsValue)(nil))
		selectedAssert(&s06.WUSAssistanceInformationExtIEsValue{})
		opaque := func() s06.WUSAssistanceInformationExtIEsValue {
			sealed := s06.WUSAssistanceInformationExtIEsValue{}
			*s06.BridgeWUSAssistanceInformationExtIEsValueFieldIsOpaque(&sealed) = true
			*s06.BridgeWUSAssistanceInformationExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
	})
	t.Run("WriteReplaceWarningRequestIEValue", func(t *testing.T) {
		selectedAssert((*s33.WriteReplaceWarningRequestIEValue)(nil))
		selectedAssert(&s33.WriteReplaceWarningRequestIEValue{})
		opaque := func() s33.WriteReplaceWarningRequestIEValue {
			sealed := s33.WriteReplaceWarningRequestIEValue{}
			*s33.BridgeWriteReplaceWarningRequestIEValueFieldIsOpaque(&sealed) = true
			*s33.BridgeWriteReplaceWarningRequestIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(113)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaList(&sealed) = new(s32.WarningAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(114)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowRepetitionPeriod(&sealed) = new(s00.RepetitionPeriod)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(144)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowExtendedRepetitionPeriod(&sealed) = new(s00.ExtendedRepetitionPeriod)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(115)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowNumberofBroadcastRequest(&sealed) = new(s00.NumberofBroadcastRequest)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(116)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningType(&sealed) = new(s00.WarningType)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(117)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningSecurityInfo(&sealed) = new(s00.WarningSecurityInfo)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(118)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowDataCodingScheme(&sealed) = new(s00.DataCodingScheme)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(119)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningMessageContents(&sealed) = new(s00.WarningMessageContents)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(142)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowConcurrentWarningMessageIndicator(&sealed) = new(s00.ConcurrentWarningMessageIndicator)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s33.WriteReplaceWarningRequestIEValue {
				sealed := s33.WriteReplaceWarningRequestIEValue{}
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(286)
				*s33.BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaCoordinates(&sealed) = new(s00.WarningAreaCoordinates)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("WriteReplaceWarningResponseIEValue", func(t *testing.T) {
		selectedAssert((*s32.WriteReplaceWarningResponseIEValue)(nil))
		selectedAssert(&s32.WriteReplaceWarningResponseIEValue{})
		opaque := func() s32.WriteReplaceWarningResponseIEValue {
			sealed := s32.WriteReplaceWarningResponseIEValue{}
			*s32.BridgeWriteReplaceWarningResponseIEValueFieldIsOpaque(&sealed) = true
			*s32.BridgeWriteReplaceWarningResponseIEValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s32.WriteReplaceWarningResponseIEValue {
				sealed := s32.WriteReplaceWarningResponseIEValue{}
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(111)
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldRowMessageIdentifier(&sealed) = new(s00.MessageIdentifier)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.WriteReplaceWarningResponseIEValue {
				sealed := s32.WriteReplaceWarningResponseIEValue{}
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(112)
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldRowSerialNumber(&sealed) = new(s00.SerialNumber)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.WriteReplaceWarningResponseIEValue {
				sealed := s32.WriteReplaceWarningResponseIEValue{}
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(120)
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldRowBroadcastCompletedAreaList(&sealed) = new(s32.BroadcastCompletedAreaList)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s32.WriteReplaceWarningResponseIEValue {
				sealed := s32.WriteReplaceWarningResponseIEValue{}
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s32.BridgeWriteReplaceWarningResponseIEValueFieldRowCriticalityDiagnostics(&sealed) = new(s22.CriticalityDiagnostics)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
	})
	t.Run("X2TNLConfigurationInfoExtIEsValue", func(t *testing.T) {
		selectedAssert((*s38.X2TNLConfigurationInfoExtIEsValue)(nil))
		selectedAssert(&s38.X2TNLConfigurationInfoExtIEsValue{})
		opaque := func() s38.X2TNLConfigurationInfoExtIEsValue {
			sealed := s38.X2TNLConfigurationInfoExtIEsValue{}
			*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldIsOpaque(&sealed) = true
			*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldOpaque(&sealed) = opaqueValue
			return sealed
		}()
		selectedAssertOpaque(&opaque)
		unions++
		{
			value := func() s38.X2TNLConfigurationInfoExtIEsValue {
				sealed := s38.X2TNLConfigurationInfoExtIEsValue{}
				*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(153)
				*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBX2ExtendedTransportLayerAddresses(&sealed) = new(s15.ENBX2ExtTLAs)
				return sealed
			}()
			selectedAssert(&value)
			rows++
		}
		{
			value := func() s38.X2TNLConfigurationInfoExtIEsValue {
				sealed := s38.X2TNLConfigurationInfoExtIEsValue{}
				*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(193)
				*s38.BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBIndirectX2TransportLayerAddresses(&sealed) = new(s00.ENBIndirectX2TransportLayerAddresses)
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
