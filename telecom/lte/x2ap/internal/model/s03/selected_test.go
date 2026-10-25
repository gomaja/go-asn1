// Code generated from the locked X2AP source closure. DO NOT EDIT.

package s03

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
func TestSelectedExtendedULInterferenceOverloadInfoExtIEsValue(t *testing.T) {
	var absent *ExtendedULInterferenceOverloadInfoExtIEsValue
	selectedAssert(t, absent)
	v := ExtendedULInterferenceOverloadInfoExtIEsValue{}
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
	t.Logf("union ExtendedULInterferenceOverloadInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedFastMCGRecoveryExtIEsValue(t *testing.T) {
	var absent *FastMCGRecoveryExtIEsValue
	selectedAssert(t, absent)
	v := FastMCGRecoveryExtIEsValue{}
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
	t.Logf("union FastMCGRecoveryExtIEsValue: 0 synthetic rows")
}
func TestSelectedFirstDLCountExtIEsValue(t *testing.T) {
	var absent *FirstDLCountExtIEsValue
	selectedAssert(t, absent)
	v := FirstDLCountExtIEsValue{}
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
	t.Logf("union FirstDLCountExtIEsValue: 0 synthetic rows")
}
func TestSelectedForbiddenLAsItemExtIEsValue(t *testing.T) {
	var absent *ForbiddenLAsItemExtIEsValue
	selectedAssert(t, absent)
	v := ForbiddenLAsItemExtIEsValue{}
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
	t.Logf("union ForbiddenLAsItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedForbiddenTAsItemExtIEsValue(t *testing.T) {
	var absent *ForbiddenTAsItemExtIEsValue
	selectedAssert(t, absent)
	v := ForbiddenTAsItemExtIEsValue{}
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
	t.Logf("union ForbiddenTAsItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedFreqBandNrItemExtIEsValue(t *testing.T) {
	var absent *FreqBandNrItemExtIEsValue
	selectedAssert(t, absent)
	v := FreqBandNrItemExtIEsValue{}
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
	t.Logf("union FreqBandNrItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedGTPTLAItemExtIEsValue(t *testing.T) {
	var absent *GTPTLAItemExtIEsValue
	selectedAssert(t, absent)
	v := GTPTLAItemExtIEsValue{}
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
	t.Logf("union GTPTLAItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedGUGroupIDExtIEsValue(t *testing.T) {
	var absent *GUGroupIDExtIEsValue
	selectedAssert(t, absent)
	v := GUGroupIDExtIEsValue{}
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
	t.Logf("union GUGroupIDExtIEsValue: 0 synthetic rows")
}
func TestSelectedGUMMEIExtIEsValue(t *testing.T) {
	var absent *GUMMEIExtIEsValue
	selectedAssert(t, absent)
	v := GUMMEIExtIEsValue{}
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
	t.Logf("union GUMMEIExtIEsValue: 0 synthetic rows")
}
func TestSelectedGlobalENBIDExtIEsValue(t *testing.T) {
	var absent *GlobalENBIDExtIEsValue
	selectedAssert(t, absent)
	v := GlobalENBIDExtIEsValue{}
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
	t.Logf("union GlobalENBIDExtIEsValue: 0 synthetic rows")
}
func TestSelectedGlobalGNBIDExtIEsValue(t *testing.T) {
	var absent *GlobalGNBIDExtIEsValue
	selectedAssert(t, absent)
	v := GlobalGNBIDExtIEsValue{}
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
	t.Logf("union GlobalGNBIDExtIEsValue: 0 synthetic rows")
}
func TestSelectedGlobalRANNODEIDExtIEValue(t *testing.T) {
	var absent *GlobalRANNODEIDExtIEValue
	selectedAssert(t, absent)
	v := GlobalRANNODEIDExtIEValue{}
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
	t.Logf("union GlobalRANNODEIDExtIEValue: 0 synthetic rows")
}
func TestSelectedHWLoadIndicatorExtIEsValue(t *testing.T) {
	var absent *HWLoadIndicatorExtIEsValue
	selectedAssert(t, absent)
	v := HWLoadIndicatorExtIEsValue{}
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
	t.Logf("union HWLoadIndicatorExtIEsValue: 0 synthetic rows")
}
func TestSelectedLimitedListExtIEsValue(t *testing.T) {
	var absent *LimitedListExtIEsValue
	selectedAssert(t, absent)
	v := LimitedListExtIEsValue{}
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
	t.Logf("union LimitedListExtIEsValue: 0 synthetic rows")
}
func TestSelectedLocationInformationSgNBExtIEsValue(t *testing.T) {
	var absent *LocationInformationSgNBExtIEsValue
	selectedAssert(t, absent)
	v := LocationInformationSgNBExtIEsValue{}
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
	t.Logf("union LocationInformationSgNBExtIEsValue: 0 synthetic rows")
}
func TestSelectedM1PeriodicReportingExtIEsValue(t *testing.T) {
	var absent *M1PeriodicReportingExtIEsValue
	selectedAssert(t, absent)
	v := M1PeriodicReportingExtIEsValue{}
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
	t.Logf("union M1PeriodicReportingExtIEsValue: 0 synthetic rows")
}
func TestSelectedM1ThresholdEventA2ExtIEsValue(t *testing.T) {
	var absent *M1ThresholdEventA2ExtIEsValue
	selectedAssert(t, absent)
	v := M1ThresholdEventA2ExtIEsValue{}
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
	t.Logf("union M1ThresholdEventA2ExtIEsValue: 0 synthetic rows")
}
func TestSelectedM3ConfigurationExtIEsValue(t *testing.T) {
	var absent *M3ConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := M3ConfigurationExtIEsValue{}
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
	t.Logf("union M3ConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedMBSFNSubframeInfoExtIEsValue(t *testing.T) {
	var absent *MBSFNSubframeInfoExtIEsValue
	selectedAssert(t, absent)
	v := MBSFNSubframeInfoExtIEsValue{}
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
	t.Logf("union MBSFNSubframeInfoExtIEsValue: 0 synthetic rows")
}
func TestSelectedMIMOPRBusageInformationExtIEsValue(t *testing.T) {
	var absent *MIMOPRBusageInformationExtIEsValue
	selectedAssert(t, absent)
	v := MIMOPRBusageInformationExtIEsValue{}
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
	t.Logf("union MIMOPRBusageInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedMeasurementFailureCauseItemExtIEsValue(t *testing.T) {
	var absent *MeasurementFailureCauseItemExtIEsValue
	selectedAssert(t, absent)
	v := MeasurementFailureCauseItemExtIEsValue{}
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
	t.Logf("union MeasurementFailureCauseItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedMeasurementInitiationResultItemExtIEsValue(t *testing.T) {
	var absent *MeasurementInitiationResultItemExtIEsValue
	selectedAssert(t, absent)
	v := MeasurementInitiationResultItemExtIEsValue{}
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
	t.Logf("union MeasurementInitiationResultItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedMeasurementResultforNRCellsPossiblyAggregatedItemExtIEsValue(t *testing.T) {
	var absent *MeasurementResultforNRCellsPossiblyAggregatedItemExtIEsValue
	selectedAssert(t, absent)
	v := MeasurementResultforNRCellsPossiblyAggregatedItemExtIEsValue{}
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
	t.Logf("union MeasurementResultforNRCellsPossiblyAggregatedItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedMessageOversizeNotificationExtIEsValue(t *testing.T) {
	var absent *MessageOversizeNotificationExtIEsValue
	selectedAssert(t, absent)
	v := MessageOversizeNotificationExtIEsValue{}
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
	t.Logf("union MessageOversizeNotificationExtIEsValue: 0 synthetic rows")
}
func TestSelectedNPRACHConfigurationExtIEsValue(t *testing.T) {
	var absent *NPRACHConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := NPRACHConfigurationExtIEsValue{}
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
	t.Logf("union NPRACHConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedNPRACHConfigurationFDDExtIEsValue(t *testing.T) {
	var absent *NPRACHConfigurationFDDExtIEsValue
	selectedAssert(t, absent)
	v := NPRACHConfigurationFDDExtIEsValue{}
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
	t.Logf("union NPRACHConfigurationFDDExtIEsValue: 0 synthetic rows")
}
func TestSelectedNPRACHConfigurationTDDExtIEsValue(t *testing.T) {
	var absent *NPRACHConfigurationTDDExtIEsValue
	selectedAssert(t, absent)
	v := NPRACHConfigurationTDDExtIEsValue{}
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
	t.Logf("union NPRACHConfigurationTDDExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRCGIExtIEsValue(t *testing.T) {
	var absent *NRCGIExtIEsValue
	selectedAssert(t, absent)
	v := NRCGIExtIEsValue{}
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
	t.Logf("union NRCGIExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRCapacityValueExtIEsValue(t *testing.T) {
	var absent *NRCapacityValueExtIEsValue
	selectedAssert(t, absent)
	v := NRCapacityValueExtIEsValue{}
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
	t.Logf("union NRCapacityValueExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRCarrierItemExtIEsValue(t *testing.T) {
	var absent *NRCarrierItemExtIEsValue
	selectedAssert(t, absent)
	v := NRCarrierItemExtIEsValue{}
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
	t.Logf("union NRCarrierItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRCompositeAvailableCapacityExtIEsValue(t *testing.T) {
	var absent *NRCompositeAvailableCapacityExtIEsValue
	selectedAssert(t, absent)
	v := NRCompositeAvailableCapacityExtIEsValue{}
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
	t.Logf("union NRCompositeAvailableCapacityExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRCompositeAvailableCapacityGroupExtIEsValue(t *testing.T) {
	var absent *NRCompositeAvailableCapacityGroupExtIEsValue
	selectedAssert(t, absent)
	v := NRCompositeAvailableCapacityGroupExtIEsValue{}
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
	t.Logf("union NRCompositeAvailableCapacityGroupExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRTxBWExtIEsValue(t *testing.T) {
	var absent *NRTxBWExtIEsValue
	selectedAssert(t, absent)
	v := NRTxBWExtIEsValue{}
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
	t.Logf("union NRTxBWExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRUESecurityCapabilitiesExtIEsValue(t *testing.T) {
	var absent *NRUESecurityCapabilitiesExtIEsValue
	selectedAssert(t, absent)
	v := NRUESecurityCapabilitiesExtIEsValue{}
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
	t.Logf("union NRUESecurityCapabilitiesExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRUESidelinkAggregateMaximumBitRateExtIEsValue(t *testing.T) {
	var absent *NRUESidelinkAggregateMaximumBitRateExtIEsValue
	selectedAssert(t, absent)
	v := NRUESidelinkAggregateMaximumBitRateExtIEsValue{}
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
	t.Logf("union NRUESidelinkAggregateMaximumBitRateExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRUeReportExtIEsValue(t *testing.T) {
	var absent *NRUeReportExtIEsValue
	selectedAssert(t, absent)
	v := NRUeReportExtIEsValue{}
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
	t.Logf("union NRUeReportExtIEsValue: 0 synthetic rows")
}
func TestSelectedNRV2XServicesAuthorizedExtIEsValue(t *testing.T) {
	var absent *NRV2XServicesAuthorizedExtIEsValue
	selectedAssert(t, absent)
	v := NRV2XServicesAuthorizedExtIEsValue{}
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
	t.Logf("union NRV2XServicesAuthorizedExtIEsValue: 0 synthetic rows")
}
func TestSelectedNonAnchorCarrierFrequencylistExtIEsValue(t *testing.T) {
	var absent *NonAnchorCarrierFrequencylistExtIEsValue
	selectedAssert(t, absent)
	v := NonAnchorCarrierFrequencylistExtIEsValue{}
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
	t.Logf("union NonAnchorCarrierFrequencylistExtIEsValue: 0 synthetic rows")
}
func TestSelectedPC5FlowBitRatesExtIEsValue(t *testing.T) {
	var absent *PC5FlowBitRatesExtIEsValue
	selectedAssert(t, absent)
	v := PC5FlowBitRatesExtIEsValue{}
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
	t.Logf("union PC5FlowBitRatesExtIEsValue: 0 synthetic rows")
}
func TestSelectedPC5QoSFlowItemExtIEsValue(t *testing.T) {
	var absent *PC5QoSFlowItemExtIEsValue
	selectedAssert(t, absent)
	v := PC5QoSFlowItemExtIEsValue{}
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
	t.Logf("union PC5QoSFlowItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedPC5QoSParametersExtIEsValue(t *testing.T) {
	var absent *PC5QoSParametersExtIEsValue
	selectedAssert(t, absent)
	v := PC5QoSParametersExtIEsValue{}
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
	t.Logf("union PC5QoSParametersExtIEsValue: 0 synthetic rows")
}
func TestSelectedPLMNAreaBasedQMCExtIEsValue(t *testing.T) {
	var absent *PLMNAreaBasedQMCExtIEsValue
	selectedAssert(t, absent)
	v := PLMNAreaBasedQMCExtIEsValue{}
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
	t.Logf("union PLMNAreaBasedQMCExtIEsValue: 0 synthetic rows")
}
func TestSelectedPRACHConfigurationExtIEsValue(t *testing.T) {
	var absent *PRACHConfigurationExtIEsValue
	selectedAssert(t, absent)
	v := PRACHConfigurationExtIEsValue{}
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
	t.Logf("union PRACHConfigurationExtIEsValue: 0 synthetic rows")
}
func TestSelectedProcedureStageChoiceExtIEValue(t *testing.T) {
	var absent *ProcedureStageChoiceExtIEValue
	selectedAssert(t, absent)
	v := ProcedureStageChoiceExtIEValue{}
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
	t.Logf("union ProcedureStageChoiceExtIEValue: 0 synthetic rows")
}
func TestSelectedProtectedEUTRAResourceIndicationExtIEsValue(t *testing.T) {
	var absent *ProtectedEUTRAResourceIndicationExtIEsValue
	selectedAssert(t, absent)
	v := ProtectedEUTRAResourceIndicationExtIEsValue{}
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
	t.Logf("union ProtectedEUTRAResourceIndicationExtIEsValue: 0 synthetic rows")
}
func TestSelectedProtectedFootprintTimePatternExtIEsValue(t *testing.T) {
	var absent *ProtectedFootprintTimePatternExtIEsValue
	selectedAssert(t, absent)
	v := ProtectedFootprintTimePatternExtIEsValue{}
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
	t.Logf("union ProtectedFootprintTimePatternExtIEsValue: 0 synthetic rows")
}
func TestSelectedProtectedResourceListItemExtIEsValue(t *testing.T) {
	var absent *ProtectedResourceListItemExtIEsValue
	selectedAssert(t, absent)
	v := ProtectedResourceListItemExtIEsValue{}
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
	t.Logf("union ProtectedResourceListItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedQoSMappingInformationExtIEsValue(t *testing.T) {
	var absent *QoSMappingInformationExtIEsValue
	selectedAssert(t, absent)
	v := QoSMappingInformationExtIEsValue{}
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
	t.Logf("union QoSMappingInformationExtIEsValue: 0 synthetic rows")
}
func TestSelectedRATRestrictionsItemExtIEsValue(t *testing.T) {
	var absent *RATRestrictionsItemExtIEsValue
	selectedAssert(t, absent)
	v := RATRestrictionsItemExtIEsValue{}
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
	t.Logf("union RATRestrictionsItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedRLCStatusExtIEsValue(t *testing.T) {
	var absent *RLCStatusExtIEsValue
	selectedAssert(t, absent)
	v := RLCStatusExtIEsValue{}
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
	t.Logf("union RLCStatusExtIEsValue: 0 synthetic rows")
}
func TestSelectedRNLHeaderItemExtIEsValue(t *testing.T) {
	var absent *RNLHeaderItemExtIEsValue
	selectedAssert(t, absent)
	v := RNLHeaderItemExtIEsValue{}
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
	t.Logf("union RNLHeaderItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedRSRPMeasurementResultExtIEsValue(t *testing.T) {
	var absent *RSRPMeasurementResultExtIEsValue
	selectedAssert(t, absent)
	v := RSRPMeasurementResultExtIEsValue{}
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
	t.Logf("union RSRPMeasurementResultExtIEsValue: 0 synthetic rows")
}
func TestSelectedRaReportIndicationListItemExtIEsValue(t *testing.T) {
	var absent *RaReportIndicationListItemExtIEsValue
	selectedAssert(t, absent)
	v := RaReportIndicationListItemExtIEsValue{}
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
	t.Logf("union RaReportIndicationListItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedReservedSubframePatternExtIEsValue(t *testing.T) {
	var absent *ReservedSubframePatternExtIEsValue
	selectedAssert(t, absent)
	v := ReservedSubframePatternExtIEsValue{}
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
	t.Logf("union ReservedSubframePatternExtIEsValue: 0 synthetic rows")
}
func TestSelectedResponseInformationSeNBReconfCompRejectByMeNBItemExtIEsValue(t *testing.T) {
	var absent *ResponseInformationSeNBReconfCompRejectByMeNBItemExtIEsValue
	selectedAssert(t, absent)
	v := ResponseInformationSeNBReconfCompRejectByMeNBItemExtIEsValue{}
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
	t.Logf("union ResponseInformationSeNBReconfCompRejectByMeNBItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedResponseInformationSeNBReconfCompSuccessItemExtIEsValue(t *testing.T) {
	var absent *ResponseInformationSeNBReconfCompSuccessItemExtIEsValue
	selectedAssert(t, absent)
	v := ResponseInformationSeNBReconfCompSuccessItemExtIEsValue{}
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
	t.Logf("union ResponseInformationSeNBReconfCompSuccessItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedResponseInformationSgNBReconfCompRejectByMeNBItemExtIEsValue(t *testing.T) {
	var absent *ResponseInformationSgNBReconfCompRejectByMeNBItemExtIEsValue
	selectedAssert(t, absent)
	v := ResponseInformationSgNBReconfCompRejectByMeNBItemExtIEsValue{}
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
	t.Logf("union ResponseInformationSgNBReconfCompRejectByMeNBItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedResponseInformationSgNBReconfCompSuccessItemExtIEsValue(t *testing.T) {
	var absent *ResponseInformationSgNBReconfCompSuccessItemExtIEsValue
	selectedAssert(t, absent)
	v := ResponseInformationSgNBReconfCompSuccessItemExtIEsValue{}
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
	t.Logf("union ResponseInformationSgNBReconfCompSuccessItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedS1TNLLoadIndicatorExtIEsValue(t *testing.T) {
	var absent *S1TNLLoadIndicatorExtIEsValue
	selectedAssert(t, absent)
	v := S1TNLLoadIndicatorExtIEsValue{}
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
	t.Logf("union S1TNLLoadIndicatorExtIEsValue: 0 synthetic rows")
}
func TestSelectedSFNOffsetExtIEsValue(t *testing.T) {
	var absent *SFNOffsetExtIEsValue
	selectedAssert(t, absent)
	v := SFNOffsetExtIEsValue{}
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
	t.Logf("union SFNOffsetExtIEsValue: 0 synthetic rows")
}
func TestSelectedSSBAreaCapacityValueExtIEsValue(t *testing.T) {
	var absent *SSBAreaCapacityValueExtIEsValue
	selectedAssert(t, absent)
	v := SSBAreaCapacityValueExtIEsValue{}
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
	t.Logf("union SSBAreaCapacityValueExtIEsValue: 0 synthetic rows")
}
func TestSelectedSSBAreaRadioResourceStatusExtIEsValue(t *testing.T) {
	var absent *SSBAreaRadioResourceStatusExtIEsValue
	selectedAssert(t, absent)
	v := SSBAreaRadioResourceStatusExtIEsValue{}
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
	t.Logf("union SSBAreaRadioResourceStatusExtIEsValue: 0 synthetic rows")
}
func TestSelectedSSBPositionsInBurstExtIEValue(t *testing.T) {
	var absent *SSBPositionsInBurstExtIEValue
	selectedAssert(t, absent)
	v := SSBPositionsInBurstExtIEValue{}
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
	t.Logf("union SSBPositionsInBurstExtIEValue: 0 synthetic rows")
}
func TestSelectedSSBToReportItemExtIEsValue(t *testing.T) {
	var absent *SSBToReportItemExtIEsValue
	selectedAssert(t, absent)
	v := SSBToReportItemExtIEsValue{}
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
	t.Logf("union SSBToReportItemExtIEsValue: 0 synthetic rows")
}
func TestSelectedScheduledCommunicationTimeExtIEsValue(t *testing.T) {
	var absent *ScheduledCommunicationTimeExtIEsValue
	selectedAssert(t, absent)
	v := ScheduledCommunicationTimeExtIEsValue{}
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
	t.Logf("union ScheduledCommunicationTimeExtIEsValue: 0 synthetic rows")
}
func TestSelectedSecondaryRATUsageReportItemExtIEsValue(t *testing.T) {
	var absent *SecondaryRATUsageReportItemExtIEsValue
	selectedAssert(t, absent)
	v := SecondaryRATUsageReportItemExtIEsValue{}
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
	t.Logf("union SecondaryRATUsageReportItemExtIEsValue: 0 synthetic rows")
}
