// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s04

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

type selectedUnion interface{ Selected() (any, bool) }

var selectedSink any

func selectedAssert(t *testing.T, v selectedUnion) {
	t.Helper()
	var want any
	found := false
	value := reflect.ValueOf(v)
	if !value.IsNil() {
		if opaque := value.MethodByName("Opaque").Call(nil); !opaque[1].Bool() {
			for i := 0; i < value.NumMethod(); i++ {
				m := value.Type().Method(i)
				if !strings.HasPrefix(m.Name, "As") {
					continue
				}
				r := value.Method(i).Call(nil)
				if r[1].Bool() {
					want = r[0].Interface()
					found = true
					break
				}
			}
		}
	}
	got, ok := v.Selected()
	if got != want || ok != found {
		t.Fatalf("%T Selected=(%v,%v), As oracle=(%v,%v)", v, got, ok, want, found)
	}
	if n := testing.AllocsPerRun(10, func() { selectedSink, _ = v.Selected() }); n != 0 {
		t.Fatalf("%T Selected allocations=%v", v, n)
	}
}
func TestSelectedSecurityIndicationExtIEsValue(t *testing.T) {
	var absent *SecurityIndicationExtIEsValue
	selectedAssert(t, absent)
	v := SecurityIndicationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SecurityIndicationExtIEsValue: 0 synthetic rows")
}
func TestSelectedSecurityResultExtIEsValue(t *testing.T) {
	var absent *SecurityResultExtIEsValue
	selectedAssert(t, absent)
	v := SecurityResultExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SecurityResultExtIEsValue: 0 synthetic rows")
}
func TestSelectedSensorMeasConfigNameItemExtIEsValue(t *testing.T) {
	var absent *SensorMeasConfigNameItemExtIEsValue
	selectedAssert(t, absent)
	v := SensorMeasConfigNameItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SensorMeasConfigNameItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedSensorMeasurementConfigurationExtIEsValue(t *testing.T) {
	var absent *SensorMeasurementConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := SensorMeasurementConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SensorMeasurementConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedSensorNameConfigExtIEValue(t *testing.T) {
	var absent *SensorNameConfigExtIEValue
	selectedAssert(t, absent)
	v := SensorNameConfigExtIEValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SensorNameConfigExtIEValue: 0 synthetic rows")
}
func TestSelectedServedCellSpecificInfoReqNRItemExtIEsValue(t *testing.T) {
	var absent *ServedCellSpecificInfoReqNRItemExtIEsValue
	selectedAssert(t, absent)
	v := ServedCellSpecificInfoReqNRItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedCellSpecificInfoReqNRItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedServedCellsToActivateItemExtIEsValue(t *testing.T) {
	var absent *ServedCellsToActivateItemExtIEsValue
	selectedAssert(t, absent)
	v := ServedCellsToActivateItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedCellsToActivateItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedServedEUTRAcellsENDCX2ManagementExtIEsValue(t *testing.T) {
	var absent *ServedEUTRAcellsENDCX2ManagementExtIEsValue
	selectedAssert(t, absent)
	v := ServedEUTRAcellsENDCX2ManagementExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedEUTRAcellsENDCX2ManagementExtIEsValue: 0 synthetic rows")
}
func TestSelectedServedEUTRAcellsToModifyListENDCConfUpdExtIEsValue(t *testing.T) {
	var absent *ServedEUTRAcellsToModifyListENDCConfUpdExtIEsValue
	selectedAssert(t, absent)
	v := ServedEUTRAcellsToModifyListENDCConfUpdExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedEUTRAcellsToModifyListENDCConfUpdExtIEsValue: 0 synthetic rows")
}
func TestSelectedServedNRCellsToActivateItemExtIEsValue(t *testing.T) {
	var absent *ServedNRCellsToActivateItemExtIEsValue
	selectedAssert(t, absent)
	v := ServedNRCellsToActivateItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedNRCellsToActivateItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedServedNRCellsToModifyItemExtIEsValue(t *testing.T) {
	var absent *ServedNRCellsToModifyItemExtIEsValue
	selectedAssert(t, absent)
	v := ServedNRCellsToModifyItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ServedNRCellsToModifyItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedSpecialSubframeInfoExtIEsValue(t *testing.T) {
	var absent *SpecialSubframeInfoExtIEsValue
	selectedAssert(t, absent)
	v := SpecialSubframeInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SpecialSubframeInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedSplitSRBExtIEsValue(t *testing.T) {
	var absent *SplitSRBExtIEsValue
	selectedAssert(t, absent)
	v := SplitSRBExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SplitSRBExtIEsValue: 0 synthetic rows")
}
func TestSelectedSubbandCQIExtIEsValue(t *testing.T) {
	var absent *SubbandCQIExtIEsValue
	selectedAssert(t, absent)
	v := SubbandCQIExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SubbandCQIExtIEsValue: 0 synthetic rows")
}
func TestSelectedSubbandCQIItemExtIEsValue(t *testing.T) {
	var absent *SubbandCQIItemExtIEsValue
	selectedAssert(t, absent)
	v := SubbandCQIItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SubbandCQIItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedSubscriptionBasedUEDifferentiationInfoExtIEsValue(t *testing.T) {
	var absent *SubscriptionBasedUEDifferentiationInfoExtIEsValue
	selectedAssert(t, absent)
	v := SubscriptionBasedUEDifferentiationInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SubscriptionBasedUEDifferentiationInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedSupportedSULFreqBandItemExtIEsValue(t *testing.T) {
	var absent *SupportedSULFreqBandItemExtIEsValue
	selectedAssert(t, absent)
	v := SupportedSULFreqBandItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union SupportedSULFreqBandItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTABasedMDTExtIEsValue(t *testing.T) {
	var absent *TABasedMDTExtIEsValue
	selectedAssert(t, absent)
	v := TABasedMDTExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TABasedMDTExtIEsValue: 0 synthetic rows")
}
func TestSelectedTABasedQMCExtIEsValue(t *testing.T) {
	var absent *TABasedQMCExtIEsValue
	selectedAssert(t, absent)
	v := TABasedQMCExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TABasedQMCExtIEsValue: 0 synthetic rows")
}
func TestSelectedTAIBasedMDTExtIEsValue(t *testing.T) {
	var absent *TAIBasedMDTExtIEsValue
	selectedAssert(t, absent)
	v := TAIBasedMDTExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TAIBasedMDTExtIEsValue: 0 synthetic rows")
}
func TestSelectedTAIBasedQMCExtIEsValue(t *testing.T) {
	var absent *TAIBasedQMCExtIEsValue
	selectedAssert(t, absent)
	v := TAIBasedQMCExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TAIBasedQMCExtIEsValue: 0 synthetic rows")
}
func TestSelectedTAIItemExtIEsValue(t *testing.T) {
	var absent *TAIItemExtIEsValue
	selectedAssert(t, absent)
	v := TAIItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TAIItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLAFailedToSetupItemExtIEsValue(t *testing.T) {
	var absent *TNLAFailedToSetupItemExtIEsValue
	selectedAssert(t, absent)
	v := TNLAFailedToSetupItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLAFailedToSetupItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLASetupItemExtIEsValue(t *testing.T) {
	var absent *TNLASetupItemExtIEsValue
	selectedAssert(t, absent)
	v := TNLASetupItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLASetupItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLAToAddItemExtIEsValue(t *testing.T) {
	var absent *TNLAToAddItemExtIEsValue
	selectedAssert(t, absent)
	v := TNLAToAddItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLAToAddItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLAToRemoveItemExtIEsValue(t *testing.T) {
	var absent *TNLAToRemoveItemExtIEsValue
	selectedAssert(t, absent)
	v := TNLAToRemoveItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLAToRemoveItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLAToUpdateItemExtIEsValue(t *testing.T) {
	var absent *TNLAToUpdateItemExtIEsValue
	selectedAssert(t, absent)
	v := TNLAToUpdateItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLAToUpdateItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLCapacityIndicatorExtIEsValue(t *testing.T) {
	var absent *TNLCapacityIndicatorExtIEsValue
	selectedAssert(t, absent)
	v := TNLCapacityIndicatorExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLCapacityIndicatorExtIEsValue: 0 synthetic rows")
}
func TestSelectedTNLConfigurationInfoExtIEsValue(t *testing.T) {
	var absent *TNLConfigurationInfoExtIEsValue
	selectedAssert(t, absent)
	v := TNLConfigurationInfoExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TNLConfigurationInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedTransportUPLayerAddressesInfoToAddItemExtIEsValue(t *testing.T) {
	var absent *TransportUPLayerAddressesInfoToAddItemExtIEsValue
	selectedAssert(t, absent)
	v := TransportUPLayerAddressesInfoToAddItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TransportUPLayerAddressesInfoToAddItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTransportUPLayerAddressesInfoToRemoveItemExtIEsValue(t *testing.T) {
	var absent *TransportUPLayerAddressesInfoToRemoveItemExtIEsValue
	selectedAssert(t, absent)
	v := TransportUPLayerAddressesInfoToRemoveItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TransportUPLayerAddressesInfoToRemoveItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedTunnelInformationExtIEsValue(t *testing.T) {
	var absent *TunnelInformationExtIEsValue
	selectedAssert(t, absent)
	v := TunnelInformationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union TunnelInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedUEContextInformationSeNBModReqExtIEsValue(t *testing.T) {
	var absent *UEContextInformationSeNBModReqExtIEsValue
	selectedAssert(t, absent)
	v := UEContextInformationSeNBModReqExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UEContextInformationSeNBModReqExtIEsValue: 0 synthetic rows")
}
func TestSelectedUEContextReferenceAtSeNBItemExtIEsValue(t *testing.T) {
	var absent *UEContextReferenceAtSeNBItemExtIEsValue
	selectedAssert(t, absent)
	v := UEContextReferenceAtSeNBItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UEContextReferenceAtSeNBItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedUEContextReferenceAtSgNBItemExtIEsValue(t *testing.T) {
	var absent *UEContextReferenceAtSgNBItemExtIEsValue
	selectedAssert(t, absent)
	v := UEContextReferenceAtSgNBItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UEContextReferenceAtSgNBItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedUEContextReferenceAtWTItemExtIEsValue(t *testing.T) {
	var absent *UEContextReferenceAtWTItemExtIEsValue
	selectedAssert(t, absent)
	v := UEContextReferenceAtWTItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UEContextReferenceAtWTItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedUESecurityCapabilitiesExtIEsValue(t *testing.T) {
	var absent *UESecurityCapabilitiesExtIEsValue
	selectedAssert(t, absent)
	v := UESecurityCapabilitiesExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UESecurityCapabilitiesExtIEsValue: 0 synthetic rows")
}
func TestSelectedUESidelinkAggregateMaximumBitRateExtIEsValue(t *testing.T) {
	var absent *UESidelinkAggregateMaximumBitRateExtIEsValue
	selectedAssert(t, absent)
	v := UESidelinkAggregateMaximumBitRateExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UESidelinkAggregateMaximumBitRateExtIEsValue: 0 synthetic rows")
}
func TestSelectedUEsToBeResetListItemExtIEsValue(t *testing.T) {
	var absent *UEsToBeResetListItemExtIEsValue
	selectedAssert(t, absent)
	v := UEsToBeResetListItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UEsToBeResetListItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedULConfigurationExtIEsValue(t *testing.T) {
	var absent *ULConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := ULConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ULConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedULHighInterferenceIndicationInfoItemExtIEsValue(t *testing.T) {
	var absent *ULHighInterferenceIndicationInfoItemExtIEsValue
	selectedAssert(t, absent)
	v := ULHighInterferenceIndicationInfoItemExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ULHighInterferenceIndicationInfoItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedULOnlySharingExtIEsValue(t *testing.T) {
	var absent *ULOnlySharingExtIEsValue
	selectedAssert(t, absent)
	v := ULOnlySharingExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ULOnlySharingExtIEsValue: 0 synthetic rows")
}
func TestSelectedULandDLSharingExtIEsValue(t *testing.T) {
	var absent *ULandDLSharingExtIEsValue
	selectedAssert(t, absent)
	v := ULandDLSharingExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union ULandDLSharingExtIEsValue: 0 synthetic rows")
}
func TestSelectedUsableABSInformationFDDExtIEsValue(t *testing.T) {
	var absent *UsableABSInformationFDDExtIEsValue
	selectedAssert(t, absent)
	v := UsableABSInformationFDDExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UsableABSInformationFDDExtIEsValue: 0 synthetic rows")
}
func TestSelectedUsableABSInformationTDDExtIEsValue(t *testing.T) {
	var absent *UsableABSInformationTDDExtIEsValue
	selectedAssert(t, absent)
	v := UsableABSInformationTDDExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union UsableABSInformationTDDExtIEsValue: 0 synthetic rows")
}
func TestSelectedV2XServicesAuthorizedExtIEsValue(t *testing.T) {
	var absent *V2XServicesAuthorizedExtIEsValue
	selectedAssert(t, absent)
	v := V2XServicesAuthorizedExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union V2XServicesAuthorizedExtIEsValue: 0 synthetic rows")
}
func TestSelectedWLANMeasurementConfigurationExtIEsValue(t *testing.T) {
	var absent *WLANMeasurementConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := WLANMeasurementConfigurationExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union WLANMeasurementConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedWidebandCQIExtIEsValue(t *testing.T) {
	var absent *WidebandCQIExtIEsValue
	selectedAssert(t, absent)
	v := WidebandCQIExtIEsValue{}
	selectedAssert(t, &v)
	opaqueBudget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := aper.BuildOpaqueOpenType([]byte{0xaa}, opaqueBudget)
	if err != nil {
		t.Fatal(err)
	}
	v.isOpaque = true
	v.opaque = opaque
	if _, ok := v.Opaque(); !ok {
		t.Fatal("opaque arm not selected")
	}
	selectedAssert(t, &v)
	t.Logf("union WidebandCQIExtIEsValue: 0 synthetic rows")
}
